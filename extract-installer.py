#!/usr/bin/env python3

import argparse
import io
import os
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import zipfile
from pathlib import Path
from typing import Callable

OutputCallback = Callable[[str], None]
ProgressCallback = Callable[[int, int], None]

FORMATS = ("appimage", "flatpak", "inno", "mojo", "pkg")

FORMAT_DISPLAY = {
    "appimage": "AppImage",
    "flatpak": "Flatpak",
    "inno": "Inno Setup (Windows installer)",
    "mojo": "GOG MojoSetup (.sh)",
    "pkg": "macOS Installer (.pkg / XAR)",
}

MOJO_OFFSET_RE = re.compile(r'offset=`head -n (\d+?) "\$0"')
MOJO_FILESIZE_RE = re.compile(r'filesizes="(\d+?)"')


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def run_command(
    cmd_list: list[str],
    description: str = "command",
    output: OutputCallback = print,
    cwd: Path | None = None,
) -> bool:
    """Runs a command, streaming stdout/stderr line-by-line to `output`."""
    output(f"⏳ {' '.join(cmd_list)}")
    try:
        proc = subprocess.Popen(
            cmd_list,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            cwd=cwd,
        )
    except FileNotFoundError:
        output(f"Error: Command '{cmd_list[0]}' not found.")
        raise

    assert proc.stdout is not None
    for line in proc.stdout:
        output(line.rstrip("\n"))
    returncode = proc.wait()

    if returncode != 0:
        output(f"Error: {description} failed with exit code {returncode}")
        return False
    return True


def list_files(startpath: Path, output: OutputCallback = print, max_entries: int | None = 200) -> None:
    """
    Reports files and directories under startpath via `output`.

    Paths are reported relative to the CWD (prefixed with './') if startpath
    is a direct child of the CWD, otherwise as absolute paths. Symlinks are
    shown as 'name -> target'.

    If max_entries is given, at most that many entries are listed (beyond
    startpath itself) and the remainder is summarized as a count, rather
    than printing every entry. Large extracted trees (easily tens of
    thousands of files for some installers) are otherwise slow to walk and,
    in the GUI, slow to render line-by-line into the log widget. Pass None
    to list everything.
    """
    try:
        startpath = startpath.resolve(strict=True)
    except FileNotFoundError:
        output(f"Error: Start path '{startpath}' not found.")
        return
    except PermissionError:
        output(f"Error: Permission denied for start path '{startpath}'.")
        return

    cwd = Path.cwd()
    use_relative = startpath.parent == cwd

    def display(p: Path) -> str:
        if use_relative and p.is_relative_to(cwd):
            rel = p.relative_to(cwd)
            base = "." if str(rel) == "." else f"./{rel}"
        else:
            base = str(p)
        if p.is_symlink():
            try:
                target = os.readlink(p)
            except OSError:
                target = "?"
            base += f" -> {target}"
        return base

    output(display(startpath))

    if not startpath.is_dir():
        return

    try:
        entries = sorted(startpath.rglob("*"))
    except PermissionError:
        output(f"Error: Permission denied while listing '{startpath}'.")
        return

    if max_entries is not None and len(entries) > max_entries:
        for entry in entries[:max_entries]:
            output(display(entry))
        output(f"… and {len(entries) - max_entries} more (of {len(entries)} total)")
    else:
        for entry in entries:
            output(display(entry))


# ---------------------------------------------------------------------------
# Format detection
# ---------------------------------------------------------------------------
#
# Detection is a mix of magic-byte sniffing (reliable, used where a real
# signature exists) and extension (used as a fallback where it doesn't).
# AppImage, Inno/MojoSetup, and XAR/.pkg all embed identifiable markers near
# the start of the file, so those are sniffed directly. Flatpak single-file
# bundles don't have a simple, well-documented magic sequence worth
# hand-rolling, so that one is extension-only — if that's ever not good
# enough, pass --format flatpak explicitly.

def _looks_like_appimage(header: bytes) -> bool:
    # ELF magic, followed by the "AI" + type-byte AppImage marker at offset 8.
    return (
        len(header) >= 11
        and header[:4] == b"\x7fELF"
        and header[8:10] == b"AI"
        and header[10] in (0x01, 0x02)
    )


def _looks_like_mojo(prefix: bytes) -> bool:
    text = prefix.decode("utf-8", errors="ignore")
    return "MojoSetup" in text or MOJO_OFFSET_RE.search(text) is not None


def _looks_like_inno(prefix: bytes) -> bool:
    return b"Inno Setup" in prefix


def _looks_like_xar(header: bytes) -> bool:
    # XAR container magic — macOS .pkg installers are XAR archives.
    return header[:4] == b"xar!"


def detect_format(path: Path) -> str | None:
    """Best-effort detection of which extractor a file needs. Returns one
    of FORMATS, or None if nothing matched confidently."""
    try:
        with open(path, "rb") as f:
            header = f.read(16)
            f.seek(0)
            prefix = f.read(4 * 1024 * 1024)  # plenty for the mojo/inno markers
    except OSError:
        return None

    if _looks_like_appimage(header):
        return "appimage"

    if _looks_like_xar(header):
        return "pkg"

    if path.suffix.lower() == ".flatpak":
        return "flatpak"

    if (path.suffix.lower() == ".sh" or prefix.startswith(b"#!")) and _looks_like_mojo(prefix):
        return "mojo"

    if (path.suffix.lower() == ".exe" or header[:2] == b"MZ") and _looks_like_inno(prefix):
        return "inno"

    return None


def default_outdir(input_file: Path, fmt: str) -> Path:
    suffix = {"appimage": "-appimage", "flatpak": "-flatpak", "pkg": "-pkg"}.get(fmt, "")
    return Path(f"{input_file.stem}{suffix}").resolve()


# ---------------------------------------------------------------------------
# AppImage
# ---------------------------------------------------------------------------

def ensure_executable(path: Path, output: OutputCallback = print) -> None:
    """Ensures the AppImage has its executable bit set (required for extraction)."""
    st = path.stat()
    if not (st.st_mode & stat.S_IXUSR):
        output(f"Marking {path} as executable")
        os.chmod(path, st.st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)


def extract_appimage(input_file: Path, outdir: Path, tmpdir: Path, output: OutputCallback = print) -> bool:
    ensure_executable(input_file, output)

    if not run_command(
        [str(input_file), "--appimage-extract"], "appimage-extract", output, cwd=tmpdir
    ):
        return False

    squashfs_root = tmpdir / "squashfs-root"
    if not squashfs_root.is_dir() or squashfs_root.is_symlink():
        # Some runtimes name the extracted dir something else, or leave
        # 'squashfs-root' as a symlink (e.g. -> ./AppDir) instead of the
        # real directory. Fall back to whatever single real directory (not
        # a symlink) ended up in tmpdir.
        candidates = [p for p in tmpdir.iterdir() if p.is_dir() and not p.is_symlink()]
        if len(candidates) == 1:
            output(
                f"Note: extracted directory was '{candidates[0].name}', "
                "not 'squashfs-root' — using it."
            )
            squashfs_root = candidates[0]
        else:
            output(
                "Error: Extraction reported success but no usable extracted "
                "directory was found. Contents of the temp dir:"
            )
            list_files(tmpdir, output)
            return False

    shutil.move(str(squashfs_root), str(outdir))

    output("DONE.")
    return True


# ---------------------------------------------------------------------------
# Flatpak
# ---------------------------------------------------------------------------

def find_commit_hash(repo_dir: Path, output: OutputCallback = print) -> str | None:
    """
    Finds the commit hash by locating the .commit file in the repo's objects.
    The hash is derived from the parent directory name and the filename (without extension).
    Example: objects/ab/cdef123...commit -> abcdef123...
    """
    objects_dir = repo_dir / "objects"
    if not objects_dir.is_dir():
        output(f"Error: Objects directory not found: {objects_dir}")
        return None

    commit_files = list(objects_dir.rglob("*.commit"))

    if not commit_files:
        output(f"Error: No .commit file found under {objects_dir}")
        return None

    if len(commit_files) > 1:
        commit_files.sort(key=lambda p: p.stat().st_mtime, reverse=True)
        output(
            f"Warning: Found {len(commit_files)} .commit files, "
            f"using the most recently modified: {commit_files[0]}"
        )

    commit_file_path = commit_files[0]
    return commit_file_path.parent.name + commit_file_path.stem


def extract_flatpak(input_file: Path, outdir: Path, tmpdir: Path, output: OutputCallback = print) -> bool:
    if not run_command(
        ["ostree", "init", f"--repo={tmpdir}", "--mode=bare-user"], "ostree init", output
    ):
        return False

    if not run_command(
        ["ostree", "static-delta", "apply-offline", f"--repo={tmpdir}", str(input_file)],
        "ostree apply-offline",
        output,
    ):
        return False

    commit_hash = find_commit_hash(tmpdir, output)
    if commit_hash is None:
        output("Error: Could not determine commit hash.")
        return False

    if not run_command(
        ["ostree", "checkout", f"--repo={tmpdir}", "-U", commit_hash, str(outdir)],
        "ostree checkout",
        output,
    ):
        return False

    output("DONE.")
    return True


# ---------------------------------------------------------------------------
# Inno Setup
# ---------------------------------------------------------------------------

def extract_inno(
    input_file: Path,
    outdir: Path,
    tmpdir: Path,
    output: OutputCallback = print,
    include_gog: bool = False,
) -> bool:
    staging = tmpdir / "extracted"

    cmd = ["innoextract", "--output-dir", str(staging), "--extract"]
    if include_gog:
        cmd.append("--gog")
    cmd.append(str(input_file))

    if not run_command(cmd, "innoextract", output):
        return False

    if not staging.is_dir():
        output(
            "Error: innoextract reported success but no output directory "
            "was produced. Contents of the temp dir:"
        )
        list_files(tmpdir, output)
        return False

    shutil.move(str(staging), str(outdir))

    output("DONE.")
    return True


# ---------------------------------------------------------------------------
# macOS Installer (.pkg / XAR)
# ---------------------------------------------------------------------------
#
# A .pkg is a XAR archive. `xar -xf` unpacks the container losslessly, but
# the interesting content — the installed files and any pre/post-install
# scripts — sits inside Payload and Scripts entries, which are themselves
# gzip-compressed cpio archives (one pair per component, so a "product
# archive" .pkg containing several sub-packages has several). Those are
# decompressed and unpacked here too, via `gzip`/`cpio`, so the result reads
# like a normal extracted tree rather than leaving opaque archives behind.
#
# Only gzip-compressed payloads are handled — that covers the common case,
# but some newer installers compress with something else (bzip2, etc), in
# which case the archive is left as-is with a note rather than failing the
# whole extraction.

def _cpio_gz_list(payload_path: Path) -> list[str] | None:
    """Lists entry names in a gzip-compressed cpio archive via `gzip -dc |
    cpio -t`, without extracting anything. Returns None if either tool is
    missing or the listing failed."""
    try:
        with open(payload_path, "rb") as compressed:
            gunzip = subprocess.Popen(["gzip", "-dc"], stdin=compressed, stdout=subprocess.PIPE)
            try:
                result = subprocess.run(
                    ["cpio", "-t"],
                    stdin=gunzip.stdout,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL,
                    text=True,
                )
            finally:
                gunzip.stdout.close()
                gunzip.wait()
    except (FileNotFoundError, OSError):
        return None

    if gunzip.returncode != 0 or result.returncode != 0:
        return None
    return [line for line in result.stdout.splitlines() if line]


def _extract_payload(payload_path: Path, output: OutputCallback = print) -> None:
    """
    Decompresses and unpacks a gzip-compressed cpio Payload/Scripts archive
    (as found inside an expanded .pkg) into a sibling '<name>.extracted'
    directory, then removes the compressed original. Non-fatal on any
    failure — it just leaves the file compressed and notes why.
    """
    try:
        magic = payload_path.open("rb").read(2)
    except OSError as e:
        output(f"Warning: Could not read {payload_path.name}: {e}")
        return

    if magic != b"\x1f\x8b":
        output(f"Note: {payload_path.name} isn't gzip-compressed — leaving it as-is.")
        return

    members = _cpio_gz_list(payload_path)
    if members is None:
        output(
            f"Note: 'gzip'/'cpio' unavailable or failed to read {payload_path.name} "
            "— leaving it as-is."
        )
        return

    extract_dir = payload_path.parent / f"{payload_path.name}.extracted"
    resolved_root = extract_dir.resolve()
    for name in members:
        target = (extract_dir / name).resolve()
        if target != resolved_root and not target.is_relative_to(resolved_root):
            output(
                f"Warning: refusing to unpack {payload_path.name} — unsafe path in "
                f"archive: {name}"
            )
            return

    extract_dir.mkdir(exist_ok=True)
    try:
        with open(payload_path, "rb") as compressed:
            gunzip = subprocess.Popen(["gzip", "-dc"], stdin=compressed, stdout=subprocess.PIPE)
            try:
                cpio_result = subprocess.run(
                    ["cpio", "-idm"],
                    stdin=gunzip.stdout,
                    cwd=extract_dir,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.PIPE,
                    text=True,
                )
            finally:
                gunzip.stdout.close()
                gunzip.wait()
    except OSError as e:
        output(f"Warning: Failed to unpack {payload_path.name}: {e}")
        return

    if gunzip.returncode != 0 or cpio_result.returncode != 0:
        output(f"Warning: Failed to fully unpack {payload_path.name} (gzip/cpio reported an error).")
        if cpio_result.stderr:
            output(cpio_result.stderr.strip())
        return

    try:
        payload_path.unlink()
    except OSError as e:
        output(f"Warning: unpacked {payload_path.name} but failed to remove the original: {e}")

    output(f"Unpacked {payload_path.name} -> {extract_dir.name}/")


def extract_pkg(input_file: Path, outdir: Path, tmpdir: Path, output: OutputCallback = print) -> bool:
    staging = tmpdir / "extracted"
    staging.mkdir(parents=True, exist_ok=True)

    if not run_command(["xar", "-xf", str(input_file), "-C", str(staging)], "xar", output):
        return False

    if not any(staging.iterdir()):
        output(
            "Error: xar reported success but nothing was extracted. Contents "
            "of the temp dir:"
        )
        list_files(tmpdir, output)
        return False

    for name in ("Payload", "Scripts"):
        for payload in staging.rglob(name):
            if payload.is_file():
                _extract_payload(payload, output)

    shutil.move(str(staging), str(outdir))

    output("DONE.")
    return True


# ---------------------------------------------------------------------------
# GOG MojoSetup
# ---------------------------------------------------------------------------

def extract_mojo(
    input_path: Path,
    output_path: Path,
    output: OutputCallback = print,
    progress: ProgressCallback | None = None,
    extract_archives: bool = True,
) -> tuple[bool, str]:
    """
    Splits a GOG MojoSetup installer (.sh) into its three constituent parts:
    the makeself unpacker script, the MojoSetup archive, and the game data
    archive, writing unpacker.sh, mojosetup.tar.gz, and data.zip into
    output_path.

    If extract_archives is True (the default), mojosetup.tar.gz and data.zip
    are then each extracted into output_path/mojosetup and output_path/data
    respectively, and the two archives are deleted once their extraction
    succeeds. If False, the split is all that happens.

    Returns (success, message).
    """
    if not input_path.is_file():
        return False, f"Input file not found: {input_path}"

    try:
        output_path.mkdir(parents=True, exist_ok=True)
    except OSError as e:
        return False, f"Could not create output directory {output_path}: {e}"

    unpacker_path = output_path / "unpacker.sh"
    mojosetup_path = output_path / "mojosetup.tar.gz"
    data_path = output_path / "data.zip"
    mojosetup_extract_dir = output_path / "mojosetup"
    data_extract_dir = output_path / "data"

    existing = [p for p in (unpacker_path, mojosetup_path, data_path) if p.exists()]
    if existing:
        names = ", ".join(p.name for p in existing)
        return False, f"Refusing to overwrite existing file(s) in {output_path}: {names}"
    if extract_archives:
        for extract_dir in (mojosetup_extract_dir, data_extract_dir):
            if extract_dir.exists() and any(extract_dir.iterdir()):
                return False, f"Refusing to extract into non-empty existing directory: {extract_dir}"

    total_size = input_path.stat().st_size

    try:
        with open(input_path, "rb") as game_bin:
            beginning = game_bin.read(10240).decode("utf-8", errors="ignore")
            offset_match = MOJO_OFFSET_RE.search(beginning)
            if offset_match is None:
                return False, "Could not find the makeself offset marker — is this a GOG .sh installer?"
            script_lines = int(offset_match.group(1))

            game_bin.seek(0, io.SEEK_SET)
            for _ in range(script_lines):
                game_bin.readline()
            script_size = game_bin.tell()
            output(f"Makeself script size: {script_size}")

            game_bin.seek(0, io.SEEK_SET)
            script_bin = game_bin.read(script_size)
            unpacker_path.write_bytes(script_bin)
            script = script_bin.decode("utf-8", errors="ignore")

            filesize_match = MOJO_FILESIZE_RE.search(script)
            if filesize_match is None:
                return False, "Could not find the MojoSetup archive filesize in the unpacker script."
            filesize = int(filesize_match.group(1))
            output(f"MojoSetup archive size: {filesize}")

            game_bin.seek(script_size, io.SEEK_SET)
            with open(mojosetup_path, "wb") as setup_f:
                setup_f.write(game_bin.read(filesize))

            dataoffset = script_size + filesize
            remaining_total = max(total_size - dataoffset, 0)
            game_bin.seek(dataoffset, io.SEEK_SET)
            copied = 0
            chunk_size = 1024 * 1024
            with open(data_path, "wb") as datafile:
                while True:
                    chunk = game_bin.read(chunk_size)
                    if not chunk:
                        break
                    datafile.write(chunk)
                    copied += len(chunk)
                    if progress is not None:
                        progress(copied, remaining_total)
    except OSError as e:
        return False, f"An error occurred while reading/writing files: {e}"

    if not extract_archives:
        output("DONE.")
        return True, (
            f"Split into {output_path} "
            f"(mojosetup.tar.gz and data.zip left un-extracted)"
        )

    output(f"Extracting {mojosetup_path.name} …")
    try:
        with tarfile.open(mojosetup_path) as tf:
            members = tf.getmembers()

            resolved_root = mojosetup_extract_dir.resolve()
            for member in members:
                target = (mojosetup_extract_dir / member.name).resolve()
                if target != resolved_root and not target.is_relative_to(resolved_root):
                    return False, f"Refusing to extract unsafe path from mojosetup.tar.gz: {member.name}"

            total_uncompressed = sum(m.size for m in members) or 1
            extracted = 0
            for member in members:
                tf.extract(member, path=mojosetup_extract_dir)
                extracted += member.size
                if progress is not None:
                    progress(extracted, total_uncompressed)
    except tarfile.TarError as e:
        return False, f"mojosetup.tar.gz is not a valid tar archive: {e}"
    except OSError as e:
        return False, f"An error occurred while extracting mojosetup.tar.gz: {e}"

    try:
        mojosetup_path.unlink()
    except OSError as e:
        output(f"Warning: extraction succeeded but failed to remove {mojosetup_path.name}: {e}")

    output(f"Extracting {data_path.name} …")
    try:
        with zipfile.ZipFile(data_path) as zf:
            infos = zf.infolist()

            resolved_root = data_extract_dir.resolve()
            for info in infos:
                target = (data_extract_dir / info.filename).resolve()
                if target != resolved_root and not target.is_relative_to(resolved_root):
                    return False, f"Refusing to extract unsafe path from data.zip: {info.filename}"

            total_uncompressed = sum(i.file_size for i in infos) or 1
            extracted = 0
            for info in infos:
                zf.extract(info, path=data_extract_dir)
                extracted += info.file_size
                if progress is not None:
                    progress(extracted, total_uncompressed)
    except zipfile.BadZipFile as e:
        return False, f"data.zip is not a valid zip archive: {e}"
    except OSError as e:
        return False, f"An error occurred while extracting data.zip: {e}"

    try:
        data_path.unlink()
    except OSError as e:
        output(f"Warning: extraction succeeded but failed to remove {data_path.name}: {e}")

    output("DONE.")
    return True, (
        f"Extracted to {output_path} "
        f"(MojoSetup files in {mojosetup_extract_dir}, game data in {data_extract_dir})"
    )


# ---------------------------------------------------------------------------
# Unified dispatcher (shared by CLI and GUI)
# ---------------------------------------------------------------------------

def run_extraction(
    input_file: Path,
    outdir: Path,
    tmpdir_arg: Path | None,
    output: OutputCallback = print,
    fmt: str | None = None,
    *,
    include_gog: bool = False,
    mojo_extract_archives: bool = True,
    progress: ProgressCallback | None = None,
) -> tuple[bool, str, str]:
    """
    Resolves the installer format (auto-detecting if `fmt` isn't given),
    then validates paths, manages temp-directory lifecycle for the formats
    that need one, and runs the matching extractor.

    Returns (success, message, format_used). format_used is "" if detection
    failed before a format could be determined.
    """
    if not input_file.is_file():
        return False, f"Input file not found: {input_file}", ""

    if fmt is None:
        fmt = detect_format(input_file)
        if fmt is None:
            return (
                False,
                "Could not auto-detect the installer format from its contents or "
                f"extension. Pass --format {{{','.join(FORMATS)}}} to specify it explicitly.",
                "",
            )
        output(f"Detected format: {FORMAT_DISPLAY[fmt]}")

    if fmt not in FORMATS:
        return False, f"Unknown format: {fmt}", fmt

    if fmt == "mojo":
        try:
            success, message = extract_mojo(
                input_file, outdir, output, progress=progress, extract_archives=mojo_extract_archives
            )
        except Exception as e:
            output(f"An unexpected error occurred: {e}")
            success, message = False, f"Extract process failed: {e}"
        return success, message, fmt

    # appimage / flatpak / inno all share the same shape: a scratch tmpdir,
    # and a hard requirement that outdir doesn't already exist.
    if outdir.is_symlink() or outdir.exists():
        return False, f"Output path already exists: {outdir}", fmt

    if tmpdir_arg is not None:
        tmpdir = tmpdir_arg
        if tmpdir.exists():
            return False, f"Temporary directory already exists: {tmpdir}", fmt
        tmpdir.mkdir(parents=True)
    else:
        tmpdir = Path(tempfile.mkdtemp(prefix=f"{fmt}-extract-"))

    try:
        if fmt == "appimage":
            success = extract_appimage(input_file, outdir, tmpdir, output)
        elif fmt == "flatpak":
            success = extract_flatpak(input_file, outdir, tmpdir, output)
        elif fmt == "pkg":
            success = extract_pkg(input_file, outdir, tmpdir, output)
        else:  # inno
            success = extract_inno(input_file, outdir, tmpdir, output, include_gog=include_gog)
    except Exception as e:
        output(f"An unexpected error occurred: {e}")
        success = False
    finally:
        if tmpdir.exists():
            try:
                shutil.rmtree(tmpdir)
            except Exception as e:
                output(f"Warning: Failed to remove temporary directory {tmpdir}: {e}")
                output("You may need to remove it manually.")

    if success:
        return True, f"Extracted to {outdir}", fmt
    return False, "Extract process failed.", fmt


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main_cli(args: argparse.Namespace) -> int:
    input_file = Path(args.filename).resolve()

    fmt = args.format
    if fmt is None:
        fmt = detect_format(input_file)
        if fmt is None:
            print(
                "\nCould not auto-detect the installer format from its contents or "
                f"extension. Re-run with --format {{{','.join(FORMATS)}}} to specify it.",
                file=sys.stderr,
            )
            return 1
        print(f"Detected format: {FORMAT_DISPLAY[fmt]}")

    outdir = Path(args.outdir).resolve() if args.outdir is not None else default_outdir(input_file, fmt)
    tmpdir = Path(args.tmpdir).resolve() if args.tmpdir is not None else None

    success, message, _ = run_extraction(
        input_file,
        outdir,
        tmpdir,
        output=print,
        fmt=fmt,
        include_gog=args.gog,
        mojo_extract_archives=not args.no_extract,
    )
    if not success:
        print(f"\n{message}", file=sys.stderr)
        return 1
    return 0


# ---------------------------------------------------------------------------
# GUI entry point (PySide6, optional)
# ---------------------------------------------------------------------------

def main_gui(initial_filename: str | None) -> int:
    try:
        from PySide6.QtCore import QThread, Signal
        from PySide6.QtWidgets import (
            QApplication,
            QWidget,
            QVBoxLayout,
            QHBoxLayout,
            QLabel,
            QLineEdit,
            QPushButton,
            QTextEdit,
            QFileDialog,
            QProgressBar,
            QMessageBox,
            QCheckBox,
            QComboBox,
        )
    except ImportError:
        print(
            "Error: --gui requires PySide6. Install it with:\n"
            "    pip install PySide6",
            file=sys.stderr,
        )
        return 1

    AUTO_DETECT = "Auto-detect"
    DISPLAY_TO_FORMAT = {v: k for k, v in FORMAT_DISPLAY.items()}
    COMBO_ITEMS = [AUTO_DETECT] + [FORMAT_DISPLAY[f] for f in FORMATS]

    class ExtractWorker(QThread):
        line_output = Signal(str)
        progress_update = Signal(int)  # percent, 0-100
        finished_result = Signal(bool, str, str)

        def __init__(
            self,
            input_file: Path,
            outdir: Path,
            fmt: str | None,
            include_gog: bool,
            mojo_extract_archives: bool,
        ):
            super().__init__()
            self.input_file = input_file
            self.outdir = outdir
            self.fmt = fmt
            self.include_gog = include_gog
            self.mojo_extract_archives = mojo_extract_archives
            self._last_percent = -1

        def _on_progress(self, copied: int, total: int):
            # copied/total can exceed 2^31 for multi-GB archives, which would
            # overflow a Qt signal declared as a plain C int. Reduce to a
            # 0-100 percentage before crossing the signal/slot boundary.
            if total <= 0:
                return
            percent = int(copied * 100 / total)
            if percent != self._last_percent:
                self._last_percent = percent
                self.progress_update.emit(percent)

        def run(self):
            success, message, fmt = run_extraction(
                self.input_file,
                self.outdir,
                None,
                output=self.line_output.emit,
                fmt=self.fmt,
                include_gog=self.include_gog,
                mojo_extract_archives=self.mojo_extract_archives,
                progress=self._on_progress,
            )
            self.finished_result.emit(success, message, fmt)

    class MainWindow(QWidget):
        def __init__(self):
            super().__init__()
            self.setWindowTitle("Installer Extract")
            self.resize(640, 520)
            self.setAcceptDrops(True)
            self.worker: ExtractWorker | None = None
            self._detected_format: str | None = None

            layout = QVBoxLayout(self)

            # Input file row
            input_row = QHBoxLayout()
            self.input_edit = QLineEdit()
            self.input_edit.setPlaceholderText(
                "Path to .AppImage, .flatpak, installer .exe, GOG .sh, or "
                "macOS .pkg file — or drag and drop a file onto this window"
            )
            self.input_edit.textChanged.connect(self.refresh_detection)
            self.input_browse = QPushButton("Browse…")
            self.input_browse.clicked.connect(self.browse_input)
            input_row.addWidget(QLabel("Input:"))
            input_row.addWidget(self.input_edit)
            input_row.addWidget(self.input_browse)
            layout.addLayout(input_row)

            # Format row
            format_row = QHBoxLayout()
            self.format_combo = QComboBox()
            self.format_combo.addItems(COMBO_ITEMS)
            self.format_combo.currentTextChanged.connect(self.update_options_visibility)
            self.detected_label = QLabel("")
            format_row.addWidget(QLabel("Format:"))
            format_row.addWidget(self.format_combo)
            format_row.addWidget(self.detected_label)
            format_row.addStretch()
            layout.addLayout(format_row)

            # Output dir row
            output_row = QHBoxLayout()
            self.output_edit = QLineEdit()
            self.output_edit.setPlaceholderText("Defaults to a folder named after the input file")
            self.output_browse = QPushButton("Browse…")
            self.output_browse.clicked.connect(self.browse_output)
            output_row.addWidget(QLabel("Output:"))
            output_row.addWidget(self.output_edit)
            output_row.addWidget(self.output_browse)
            layout.addLayout(output_row)

            # Format-specific options
            options_row = QHBoxLayout()
            self.gog_checkbox = QCheckBox("Include GOG.com metadata (--gog)")
            self.mojo_extract_checkbox = QCheckBox("Extract mojosetup.tar.gz and data.zip after splitting")
            self.mojo_extract_checkbox.setChecked(True)
            options_row.addWidget(self.gog_checkbox)
            options_row.addWidget(self.mojo_extract_checkbox)
            options_row.addStretch()
            layout.addLayout(options_row)

            # Extract button + progress bar
            action_row = QHBoxLayout()
            self.extract_button = QPushButton("Extract")
            self.extract_button.clicked.connect(self.start_extraction)
            self.progress = QProgressBar()
            self.progress.setRange(0, 0)  # indeterminate until we know otherwise
            self.progress.hide()
            action_row.addWidget(self.extract_button)
            action_row.addWidget(self.progress)
            layout.addLayout(action_row)

            # Log output
            self.log = QTextEdit()
            self.log.setReadOnly(True)
            self.log.setFontFamily("monospace")
            layout.addWidget(self.log)

            self.update_options_visibility()

            if initial_filename:
                self.input_edit.setText(initial_filename)

        def dragEnterEvent(self, event):
            if event.mimeData().hasUrls():
                event.acceptProposedAction()
            else:
                event.ignore()

        def dragMoveEvent(self, event):
            if event.mimeData().hasUrls():
                event.acceptProposedAction()
            else:
                event.ignore()

        def dropEvent(self, event):
            local_files = [
                url.toLocalFile() for url in event.mimeData().urls() if url.isLocalFile()
            ]
            if not local_files:
                event.ignore()
                return
            if len(local_files) > 1:
                QMessageBox.warning(
                    self,
                    "Multiple files dropped",
                    "Drop one installer file at a time — using the first one.",
                )
            self.input_edit.setText(local_files[0])
            event.acceptProposedAction()

        def effective_format(self) -> str | None:
            combo_text = self.format_combo.currentText()
            if combo_text != AUTO_DETECT:
                return DISPLAY_TO_FORMAT[combo_text]
            return self._detected_format

        def refresh_detection(self):
            text = self.input_edit.text().strip()
            path = Path(text) if text else None
            fmt = detect_format(path) if path and path.is_file() else None
            self._detected_format = fmt

            if self.format_combo.currentText() != AUTO_DETECT:
                self.detected_label.setText("")
            elif fmt is None:
                self.detected_label.setText(
                    "(couldn't detect — choose a format manually)" if path else ""
                )
            else:
                self.detected_label.setText(f"(detected: {FORMAT_DISPLAY[fmt]})")

            self.update_options_visibility()

        def update_options_visibility(self):
            fmt = self.effective_format()
            self.gog_checkbox.setVisible(fmt == "inno")
            self.mojo_extract_checkbox.setVisible(fmt == "mojo")
            self.refresh_detection_label_only()

        def refresh_detection_label_only(self):
            # Keeps the "(detected: ...)" label in sync when the user
            # switches the format dropdown without changing the input path.
            if self.format_combo.currentText() != AUTO_DETECT:
                self.detected_label.setText("")
            elif self._detected_format is not None:
                self.detected_label.setText(f"(detected: {FORMAT_DISPLAY[self._detected_format]})")

        def browse_input(self):
            path, _ = QFileDialog.getOpenFileName(
                self,
                "Select installer file",
                "",
                "All supported installers (*.AppImage *.flatpak *.exe *.sh *.pkg *.xar);;"
                "AppImage (*.AppImage);;Flatpak bundle (*.flatpak);;"
                "Windows installer (*.exe);;GOG installer script (*.sh);;"
                "macOS installer (*.pkg *.xar);;All files (*)",
            )
            if path:
                self.input_edit.setText(path)

        def browse_output(self):
            path = QFileDialog.getExistingDirectory(self, "Select output directory")
            if path:
                self.output_edit.setText(path)

        def append_log(self, line: str):
            self.log.append(line)

        def update_progress(self, percent: int):
            if self.progress.maximum() == 0:
                self.progress.setRange(0, 100)
            self.progress.setValue(percent)

        def set_controls_enabled(self, enabled: bool):
            self.extract_button.setEnabled(enabled)
            self.input_browse.setEnabled(enabled)
            self.output_browse.setEnabled(enabled)
            self.input_edit.setEnabled(enabled)
            self.output_edit.setEnabled(enabled)
            self.format_combo.setEnabled(enabled)
            self.gog_checkbox.setEnabled(enabled)
            self.mojo_extract_checkbox.setEnabled(enabled)

        def start_extraction(self):
            input_text = self.input_edit.text().strip()
            if not input_text:
                QMessageBox.warning(self, "Missing input", "Please choose an installer file first.")
                return

            input_file = Path(input_text).resolve()

            fmt = self.effective_format()
            if fmt is None:
                QMessageBox.critical(
                    self,
                    "Unknown format",
                    "Could not auto-detect the installer format. Please pick one "
                    "from the Format dropdown.",
                )
                return

            outdir_text = self.output_edit.text().strip()
            outdir = Path(outdir_text).resolve() if outdir_text else default_outdir(input_file, fmt)

            self.log.clear()
            self.set_controls_enabled(False)
            self.progress.setRange(0, 0)
            self.progress.show()

            self.worker = ExtractWorker(
                input_file,
                outdir,
                fmt,
                include_gog=self.gog_checkbox.isChecked(),
                mojo_extract_archives=self.mojo_extract_checkbox.isChecked(),
            )
            self.worker.line_output.connect(self.append_log)
            self.worker.progress_update.connect(self.update_progress)
            self.worker.finished_result.connect(self.on_finished)
            self.worker.start()

        def on_finished(self, success: bool, message: str, fmt: str):
            self.progress.hide()
            self.set_controls_enabled(True)
            self.worker = None
            if success:
                QMessageBox.information(self, "Done", message)
            else:
                QMessageBox.critical(self, "Failed", message)

        def closeEvent(self, event):
            if self.worker is not None and self.worker.isRunning():
                QMessageBox.warning(
                    self,
                    "Extraction in progress",
                    "An extraction is still running. Please wait for it to finish before closing.",
                )
                event.ignore()
            else:
                event.accept()

    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    return app.exec()


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="extract-installer",
        description="Extracts AppImage, Flatpak, Inno Setup, GOG MojoSetup, or "
        "macOS .pkg/XAR installers, auto-detecting the format unless --format "
        "is given.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "filename",
        nargs="?",
        default=None,
        help="Path to the installer file. Optional when using --gui.",
    )
    parser.add_argument(
        "--format",
        choices=FORMATS,
        default=None,
        help="Force a specific format instead of auto-detecting.",
    )
    parser.add_argument(
        "--outdir",
        type=str,
        default=None,
        help="Directory to write the extracted content into. "
        "Defaults to a name based on the input file and detected format.",
    )
    parser.add_argument(
        "--tmpdir",
        type=str,
        default=None,
        help="Temporary/staging directory used during extraction (unused for mojo). "
        "Defaults to a fresh directory under the system temp location.",
    )
    parser.add_argument(
        "--gog",
        action="store_true",
        help="Inno-only: also extract GOG.com game metadata files (innoextract --gog).",
    )
    parser.add_argument(
        "--no-extract",
        action="store_true",
        help="Mojo-only: only split the installer into unpacker.sh, mojosetup.tar.gz, "
        "and data.zip — don't automatically extract the two archives.",
    )
    parser.add_argument(
        "--gui",
        action="store_true",
        help="Launch a PySide6 GUI instead of running from the command line.",
    )
    args = parser.parse_args()

    if args.gui:
        return main_gui(args.filename)

    if args.filename is None:
        parser.error("filename is required unless --gui is used")

    return main_cli(args)


if __name__ == "__main__":
    sys.exit(main())
