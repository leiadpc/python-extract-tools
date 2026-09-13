#!/usr/bin/env python3

import argparse
import io
import re
import shutil
import sys
import tarfile
import zipfile
from pathlib import Path
from typing import Callable, Optional

OutputCallback = Callable[[str], None]
ProgressCallback = Callable[[int, int], None]

FILESIZE_RE = re.compile(r'filesizes="(\d+?)"')
OFFSET_RE = re.compile(r'offset=`head -n (\d+?) "\$0"')


def extract_gog(
    input_path: Path,
    output_path: Path,
    output: OutputCallback = print,
    progress: Optional[ProgressCallback] = None,
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
    succeeds. If False, the split is all that happens — the raw
    mojosetup.tar.gz and data.zip files are left as-is.

    Returns (success, message).

    `progress`, if given, is called as progress(bytes_done, bytes_total) once
    per phase — while the game data archive is copied out of the installer,
    then (when extract_archives is True) while mojosetup.tar.gz is untarred,
    then while data.zip is unzipped.
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
            # Read the first 10kb so we can determine the script line number
            beginning = game_bin.read(10240).decode("utf-8", errors="ignore")
            offset_match = OFFSET_RE.search(beginning)
            if offset_match is None:
                return False, "Could not find the makeself offset marker — is this a GOG .sh installer?"
            script_lines = int(offset_match.group(1))

            # Read that many lines to determine the script size
            game_bin.seek(0, io.SEEK_SET)
            for _ in range(script_lines):
                game_bin.readline()
            script_size = game_bin.tell()
            output(f"Makeself script size: {script_size}")

            # Read the script
            game_bin.seek(0, io.SEEK_SET)
            script_bin = game_bin.read(script_size)
            unpacker_path.write_bytes(script_bin)
            script = script_bin.decode("utf-8", errors="ignore")

            # Filesize is for the MojoSetup archive, not the actual game data
            filesize_match = FILESIZE_RE.search(script)
            if filesize_match is None:
                return False, "Could not find the MojoSetup archive filesize in the unpacker script."
            filesize = int(filesize_match.group(1))
            output(f"MojoSetup archive size: {filesize}")

            # Extract the setup archive
            game_bin.seek(script_size, io.SEEK_SET)
            with open(mojosetup_path, "wb") as setup_f:
                setup_f.write(game_bin.read(filesize))

            # Extract the game data archive (everything remaining), reporting
            # progress since this is typically the largest part by far.
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

    if extract_archives:
        output(f"Extracting {mojosetup_path.name} …")
        try:
            with tarfile.open(mojosetup_path) as tf:
                members = tf.getmembers()

                # Same zip-slip style guard as data.zip below, applied to tar members.
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

                # Validate every entry stays inside data_extract_dir before writing
                # anything, to guard against a zip-slip path-traversal archive.
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

    output("DONE.")
    return True, (
        f"Split into {output_path} "
        f"(mojosetup.tar.gz and data.zip left un-extracted)"
    )


# --- CLI entry point ---

def main_cli(args: argparse.Namespace) -> int:
    input_path = Path(args.filename).resolve()
    output_path = (
        Path(args.outdir).resolve()
        if args.outdir is not None
        else Path(input_path.stem).resolve()
    )

    success, message = extract_gog(
        input_path, output_path, output=print, extract_archives=not args.no_extract
    )
    if not success:
        print(f"\n{message}", file=sys.stderr)
        return 1
    return 0


# --- GUI entry point (PySide6, optional) ---

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
        progress_update = Signal(int)  # percent, 0-100
        finished_result = Signal(bool, str)

        def __init__(self, input_path: Path, output_path: Path, extract_archives: bool):
            super().__init__()
            self.input_path = input_path
            self.output_path = output_path
            self.extract_archives = extract_archives
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
            success, message = extract_gog(
                self.input_path,
                self.output_path,
                output=self.line_output.emit,
                progress=self._on_progress,
                extract_archives=self.extract_archives,
            )
            self.finished_result.emit(success, message)

    class MainWindow(QWidget):
        def __init__(self):
            super().__init__()
            self.setWindowTitle("GOG Installer Extract")
            self.resize(640, 480)
            self.worker: ExtractWorker | None = None

            layout = QVBoxLayout(self)

            # Input file row
            input_row = QHBoxLayout()
            self.input_edit = QLineEdit()
            self.input_edit.setPlaceholderText("Path to GOG .sh installer")
            self.input_browse = QPushButton("Browse…")
            self.input_browse.clicked.connect(self.browse_input)
            input_row.addWidget(QLabel("Input:"))
            input_row.addWidget(self.input_edit)
            input_row.addWidget(self.input_browse)
            layout.addLayout(input_row)

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

            # Extract-archives option
            self.extract_checkbox = QCheckBox("Extract mojosetup.tar.gz and data.zip after splitting")
            self.extract_checkbox.setChecked(True)
            layout.addWidget(self.extract_checkbox)

            # Extract button + progress bar
            action_row = QHBoxLayout()
            self.extract_button = QPushButton("Extract")
            self.extract_button.clicked.connect(self.start_extraction)
            self.progress = QProgressBar()
            self.progress.setRange(0, 0)  # indeterminate until we know the data size
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
                self, "Select GOG installer", "", "Installer scripts (*.sh);;All files (*)"
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
            # Switch from indeterminate to a real percentage once we have one.
            if self.progress.maximum() == 0:
                self.progress.setRange(0, 100)
            self.progress.setValue(percent)

        def set_controls_enabled(self, enabled: bool):
            self.extract_button.setEnabled(enabled)
            self.input_browse.setEnabled(enabled)
            self.output_browse.setEnabled(enabled)
            self.input_edit.setEnabled(enabled)
            self.output_edit.setEnabled(enabled)
            self.extract_checkbox.setEnabled(enabled)

        def start_extraction(self):
            input_text = self.input_edit.text().strip()
            if not input_text:
                QMessageBox.warning(self, "Missing input", "Please choose a GOG installer file first.")
                return

            input_path = Path(input_text).resolve()
            output_text = self.output_edit.text().strip()
            output_path = (
                Path(output_text).resolve()
                if output_text
                else Path(input_path.stem).resolve()
            )

            self.log.clear()
            self.set_controls_enabled(False)
            self.progress.setRange(0, 0)  # back to indeterminate until first progress update
            self.progress.show()

            self.worker = ExtractWorker(
                input_path, output_path, self.extract_checkbox.isChecked()
            )
            self.worker.line_output.connect(self.append_log)
            self.worker.progress_update.connect(self.update_progress)
            self.worker.finished_result.connect(self.on_finished)
            self.worker.start()

        def on_finished(self, success: bool, message: str):
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
        prog="gogextract",
        description="Splits a GOG MojoSetup installer into its unpacker script, "
        "setup archive, and game data archive.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "filename",
        help="Path to the GOG .sh installer. Optional when using --gui.",
        type=str,
        nargs="?",
        default=None,
    )
    parser.add_argument(
        "outdir",
        help="Directory to write the extracted files into. "
        "Defaults to a folder named after the input file, in the current directory.",
        type=str,
        nargs="?",
        default=None,
    )
    parser.add_argument(
        "--gui",
        help="Launch a PySide6 GUI instead of running from the command line.",
        action="store_true",
    )
    parser.add_argument(
        "--no-extract",
        help="Only split the installer into unpacker.sh, mojosetup.tar.gz, and "
        "data.zip — don't automatically extract the two archives.",
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
