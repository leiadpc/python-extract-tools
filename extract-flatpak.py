#!/usr/bin/env python3

import argparse
import subprocess
import sys
import shutil
import tempfile
from pathlib import Path
from typing import Callable

OutputCallback = Callable[[str], None]


def run_command(
    cmd_list: list[str],
    description: str = "command",
    output: OutputCallback = print,
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
        )
    except FileNotFoundError:
        output(f"Error: Command '{cmd_list[0]}' not found.")
        output("Please ensure 'ostree' is installed and in your PATH.")
        raise

    assert proc.stdout is not None
    for line in proc.stdout:
        output(line.rstrip("\n"))
    returncode = proc.wait()

    if returncode != 0:
        output(f"Error: {description} failed with exit code {returncode}")
        return False
    return True


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
    commit_filename_stem = commit_file_path.stem
    parent_dir_name = commit_file_path.parent.name

    return parent_dir_name + commit_filename_stem


def list_files(startpath: Path, output: OutputCallback = print) -> None:
    """
    Reports every file and directory under startpath via `output`.

    Paths are reported relative to the CWD (prefixed with './') if startpath
    is a direct child of the CWD, otherwise as absolute paths.
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
            return "." if str(rel) == "." else f"./{rel}"
        return str(p)

    output(display(startpath))

    if not startpath.is_dir():
        return

    try:
        for entry in sorted(startpath.rglob("*")):
            output(display(entry))
    except PermissionError:
        output(f"Error: Permission denied while listing '{startpath}'.")


def extract(input_file: Path, outdir: Path, tmpdir: Path, output: OutputCallback = print) -> bool:
    """Runs the full extract pipeline. Returns True on success."""
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

    output("Files extracted:")
    list_files(outdir, output)
    output("DONE.")
    return True


def run_extraction(
    input_file: Path,
    outdir: Path,
    tmpdir_arg: Path | None,
    output: OutputCallback = print,
) -> tuple[bool, str]:
    """
    Validates paths, manages the temp directory lifecycle, and runs `extract`.
    Returns (success, message). Shared by both the CLI and GUI entry points.
    """
    if not input_file.is_file():
        return False, f"Input file not found: {input_file}"

    if outdir.exists():
        return False, f"Output directory already exists: {outdir}"

    if tmpdir_arg is not None:
        tmpdir = tmpdir_arg
        if tmpdir.exists():
            return False, f"Temporary directory already exists: {tmpdir}"
        tmpdir.mkdir(parents=True)
    else:
        tmpdir = Path(tempfile.mkdtemp(prefix="flatpak-extract-"))

    try:
        success = extract(input_file, outdir, tmpdir, output)
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
        return True, f"Extracted to {outdir}"
    return False, "Extract process failed."


# --- CLI entry point ---

def main_cli(args: argparse.Namespace) -> int:
    input_file = Path(args.filename).resolve()

    outdir = (
        Path(f"{input_file.stem}-flatpak").resolve()
        if args.outdir is None
        else Path(args.outdir).resolve()
    )
    tmpdir = Path(args.tmpdir).resolve() if args.tmpdir is not None else None

    success, message = run_extraction(input_file, outdir, tmpdir, output=print)
    if not success:
        print(f"\n{message}", file=sys.stderr)
        return 1
    return 0


# --- GUI entry point (PySide6, optional) ---

def main_gui(initial_filename: str | None) -> int:
    try:
        from PySide6.QtCore import Qt, QThread, Signal
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
        )
    except ImportError:
        print(
            "Error: --gui requires PySide6. Install it with:\n"
            "    pip install PySide6",
            file=sys.stderr,
        )
        return 1

    class ExtractWorker(QThread):
        line_output = Signal(str)
        finished_result = Signal(bool, str)

        def __init__(self, input_file: Path, outdir: Path):
            super().__init__()
            self.input_file = input_file
            self.outdir = outdir

        def run(self):
            success, message = run_extraction(
                self.input_file, self.outdir, None, output=self.line_output.emit
            )
            self.finished_result.emit(success, message)

    class MainWindow(QWidget):
        def __init__(self):
            super().__init__()
            self.setWindowTitle("Flatpak Extract")
            self.resize(640, 480)
            self.worker: ExtractWorker | None = None

            layout = QVBoxLayout(self)

            # Input file row
            input_row = QHBoxLayout()
            self.input_edit = QLineEdit()
            self.input_edit.setPlaceholderText("Path to .flatpak file")
            input_browse = QPushButton("Browse…")
            input_browse.clicked.connect(self.browse_input)
            input_row.addWidget(QLabel("Input:"))
            input_row.addWidget(self.input_edit)
            input_row.addWidget(input_browse)
            layout.addLayout(input_row)

            # Output dir row
            output_row = QHBoxLayout()
            self.output_edit = QLineEdit()
            self.output_edit.setPlaceholderText("Defaults to a folder named after the input file")
            output_browse = QPushButton("Browse…")
            output_browse.clicked.connect(self.browse_output)
            output_row.addWidget(QLabel("Output:"))
            output_row.addWidget(self.output_edit)
            output_row.addWidget(output_browse)
            layout.addLayout(output_row)

            # Extract button + progress bar
            action_row = QHBoxLayout()
            self.extract_button = QPushButton("Extract")
            self.extract_button.clicked.connect(self.start_extraction)
            self.progress = QProgressBar()
            self.progress.setRange(0, 0)  # indeterminate
            self.progress.hide()
            action_row.addWidget(self.extract_button)
            action_row.addWidget(self.progress)
            layout.addLayout(action_row)

            # Log output
            self.log = QTextEdit()
            self.log.setReadOnly(True)
            self.log.setFontFamily("monospace")
            layout.addWidget(self.log)

            if initial_filename:
                self.input_edit.setText(initial_filename)

        def browse_input(self):
            path, _ = QFileDialog.getOpenFileName(
                self, "Select .flatpak file", "", "Flatpak files (*.flatpak);;All files (*)"
            )
            if path:
                self.input_edit.setText(path)

        def browse_output(self):
            path = QFileDialog.getExistingDirectory(self, "Select output directory")
            if path:
                self.output_edit.setText(path)

        def append_log(self, line: str):
            self.log.append(line)

        def start_extraction(self):
            input_text = self.input_edit.text().strip()
            if not input_text:
                QMessageBox.warning(self, "Missing input", "Please choose a .flatpak file first.")
                return

            input_file = Path(input_text).resolve()
            outdir_text = self.output_edit.text().strip()
            outdir = (
                Path(outdir_text).resolve()
                if outdir_text
                else Path(f"{input_file.stem}-flatpak").resolve()
            )

            self.log.clear()
            self.extract_button.setEnabled(False)
            self.progress.show()

            self.worker = ExtractWorker(input_file, outdir)
            self.worker.line_output.connect(self.append_log)
            self.worker.finished_result.connect(self.on_finished)
            self.worker.start()

        def on_finished(self, success: bool, message: str):
            self.progress.hide()
            self.extract_button.setEnabled(True)
            if success:
                QMessageBox.information(self, "Done", message)
            else:
                QMessageBox.critical(self, "Failed", message)

    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    return app.exec()


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="flatpak-extract",
        description="Extracts a .flatpak file.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "filename",
        help="Path to the input .flatpak file. Optional when using --gui.",
        type=str,
        nargs="?",
        default=None,
    )
    parser.add_argument(
        "--outdir",
        help="Directory to write the content into. "
        "Defaults to '<filename-stem>-flatpak' in the current directory.",
        type=str,
        default=None,
    )
    parser.add_argument(
        "--tmpdir",
        help="Temporary directory for the OSTree repository. "
        "Defaults to a fresh directory under the system temp location.",
        type=str,
        default=None,
    )
    parser.add_argument(
        "--gui",
        help="Launch a PySide6 GUI instead of running from the command line.",
        action="store_true",
    )
    args = parser.parse_args()

    if args.gui:
        return main_gui(args.filename)

    if args.filename is None:
        parser.error("filename is required unless --gui is used")

    return main_cli(args)


if __name__ == "__main__":
    sys.exit(main())
