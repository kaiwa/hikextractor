import sys
import os
import stat
import subprocess
import traceback
from datetime import datetime
from typing import Optional, Set

from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QLineEdit, QLabel, QFileDialog, QTableWidget,
    QTableWidgetItem, QHeaderView, QCheckBox, QProgressBar, QMessageBox,
    QGridLayout, QDialog, QListWidget, QDialogButtonBox,
    QStyledItemDelegate, QComboBox, QStyle, QFrame,
)
from PyQt6.QtCore import (
    Qt, QObject, QRunnable, QThreadPool, pyqtSignal, QDir, QSize, QSettings, QRectF,
)
from PyQt6.QtGui import (
    QIcon, QPixmap, QImage, QPainter, QPainterPath, QColor, QFontDatabase, QPalette,
)

# Import your forensic logic from the other file
try:
    from hikvision_parser import HikvisionParser, MasterBlock, HIKBTREEEntry
except ImportError:
    print("Error: Could not import hikvision_parser. Make sure it's in the same directory.")
    sys.exit(1)


# --- 0. Device Selection Dialog ---
class DeviceSelectDialog(QDialog):
    """Dialog that lists available block devices via lsblk."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Select Block Device")
        self.setMinimumWidth(500)
        self.selected_device = None
        self._setup_ui()
        self._populate_devices()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.addWidget(QLabel("Available block devices (double-click or select and press OK):"))
        self.device_list = QListWidget()
        self.device_list.itemDoubleClicked.connect(self._accept_selection)
        layout.addWidget(self.device_list)
        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self._accept_selection)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def _populate_devices(self):
        try:
            result = subprocess.run(
                ["lsblk", "-dpno", "NAME,SIZE,MODEL"],
                capture_output=True, text=True, timeout=5
            )
            lines = [l.strip() for l in result.stdout.splitlines() if l.strip()]
            if lines:
                for line in lines:
                    self.device_list.addItem(line)
            else:
                self.device_list.addItem("No block devices found")
        except FileNotFoundError:
            self.device_list.addItem("lsblk not available — type device path manually in the input field")
        except Exception as e:
            self.device_list.addItem(f"Error listing devices: {e}")

    def _accept_selection(self):
        item = self.device_list.currentItem()
        if item:
            # First token is the device path (e.g. /dev/sdb)
            self.selected_device = item.text().split()[0]
            self.accept()


# --- 1. Worker Signals (Communication from Thread to GUI) ---
class WorkerSignals(QObject):
    """Defines signals available from a running worker thread."""
    result_metadata = pyqtSignal(MasterBlock, list)  # MasterBlock + HIKBTREEEntries
    export_started = pyqtSignal(int)                  # Total items to export
    export_progress = pyqtSignal(int, str)            # Current item index, filename
    export_skipped = pyqtSignal(int)                  # Number of segments skipped due to I/O errors
    error = pyqtSignal(tuple)                         # (exc_type, exc_value, traceback_str)
    finished = pyqtSignal()                           # No data


# --- 2. Worker Runnable (The Background Task) ---
class ParserWorker(QRunnable):
    """
    Worker thread to run long-running tasks (parsing and export).
    Inherits from QRunnable to utilize QThreadPool.
    """
    def __init__(self, parser: HikvisionParser, dest_folder: str, raw: bool, entry_list: list = None):
        super().__init__()
        self.parser = parser
        self.dest_folder = dest_folder
        self.raw = raw
        self.entry_list = entry_list or []
        self.signals = WorkerSignals()

    def run(self):
        try:
            # --- PHASE 1: PARSING (Only runs if entry_list is empty) ---
            if not self.entry_list:
                master, entries = self.parser.parse_metadata()
                self.signals.result_metadata.emit(master, entries)
                self.entry_list = entries
                
            # --- PHASE 2: EXPORTING ---
            total_entries = len(self.entry_list)
            if total_entries > 0 and self.dest_folder:
                block_size = self.parser.master_block.size_data_block
                total_mb = max(1, (total_entries * block_size) // (1024 * 1024))
                self.signals.export_started.emit(total_mb)

                completed_bytes = 0
                io_errors = 0
                for i, entry in enumerate(self.entry_list):
                    ch = f"CH-{entry.channel:02d}"

                    if entry.recording:
                        completed_bytes += block_size
                        self.signals.export_progress.emit(
                            completed_bytes // (1024 * 1024),
                            f"Skipping {ch} (Recording)"
                        )
                        continue

                    base = completed_bytes  # captured for the closure below

                    def on_progress(done, total, _base=base, _ch=ch, _i=i):
                        mb_done = (_base + done) // (1024 * 1024)
                        if done < total:
                            self.signals.export_progress.emit(
                                mb_done,
                                f"Reading {_ch} ({_i+1}/{total_entries}): "
                                f"{done//(1024*1024)}/{total//(1024*1024)} MB"
                            )
                        else:
                            self.signals.export_progress.emit(
                                mb_done,
                                f"Converting {_ch} ({_i+1}/{total_entries})…"
                            )

                    try:
                        filename = self.parser.export_video_block(
                            entry, self.dest_folder, self.raw, on_progress=on_progress
                        )
                    except OSError as e:
                        io_errors += 1
                        completed_bytes += block_size
                        self.signals.export_progress.emit(
                            completed_bytes // (1024 * 1024),
                            f"Skipped {ch} ({i+1}/{total_entries}): I/O error — {e}"
                        )
                        continue
                    completed_bytes += block_size
                    self.signals.export_progress.emit(
                        completed_bytes // (1024 * 1024),
                        f"Done ({i+1}/{total_entries}): {os.path.basename(filename)}"
                    )
                self.signals.export_skipped.emit(io_errors)

        except Exception as e:
            # Catch any exception and emit it to the main thread
            self.signals.error.emit((type(e), e, traceback.format_exc()))
        finally:
            self.signals.finished.emit()


_channel_dots: dict[int, QIcon] = {}


def _channel_dot(channel: int) -> QIcon:
    """Returns a small colored dot, unique per channel, readable on light and dark themes."""
    if channel not in _channel_dots:
        hue = (channel * 53) % 360   # 53 is coprime with 360 → good spread
        pixmap = QPixmap(24, 24)
        pixmap.fill(Qt.GlobalColor.transparent)
        p = QPainter(pixmap)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        p.setPen(Qt.PenStyle.NoPen)
        p.setBrush(QColor.fromHsv(hue, 170, 210))
        p.drawEllipse(4, 4, 16, 16)
        p.end()
        _channel_dots[channel] = QIcon(pixmap)
    return _channel_dots[channel]


# Item data role holding the calendar-day parity (0/1) used for day banding
DAY_ROLE = Qt.ItemDataRole.UserRole + 2


# --- 3. Day-band delegate ---
class DayBorderDelegate(QStyledItemDelegate):
    """Shades alternate calendar days and paints rounded thumbnails in col 0."""

    def paint(self, painter: QPainter, option, index):
        # Derived from the palette (not fixed colors) so the banding follows light/dark
        # mode. AlternateBase can't be used: some themes (e.g. Adwaita dark) set it == Base.
        if index.data(DAY_ROLE):
            base = option.palette.color(QPalette.ColorRole.Base)
            text = option.palette.color(QPalette.ColorRole.Text)
            t = 0.06
            band = QColor.fromRgbF(
                base.redF() + (text.redF() - base.redF()) * t,
                base.greenF() + (text.greenF() - base.greenF()) * t,
                base.blueF() + (text.blueF() - base.blueF()) * t,
            )
            painter.fillRect(option.rect, band)
        super().paint(painter, option, index)

        if index.column() == 0:
            pixmap = index.data(Qt.ItemDataRole.UserRole)
            if isinstance(pixmap, QPixmap) and not pixmap.isNull():
                target = option.rect.adjusted(4, 4, -4, -4)
                dpr = painter.device().devicePixelRatioF()  # stay sharp on HiDPI screens
                scaled = pixmap.scaled(
                    target.size() * dpr,
                    Qt.AspectRatioMode.KeepAspectRatio,
                    Qt.TransformationMode.SmoothTransformation,
                )
                w = scaled.width() / dpr
                h = scaled.height() / dpr
                rect = QRectF(target.x() + (target.width() - w) / 2,
                              target.y() + (target.height() - h) / 2, w, h)
                clip = QPainterPath()
                clip.addRoundedRect(rect, 4, 4)
                painter.save()
                painter.setRenderHint(QPainter.RenderHint.Antialiasing)
                painter.setClipPath(clip)
                painter.drawPixmap(rect, scaled, QRectF(scaled.rect()))
                painter.restore()


# --- 4. Thumbnail worker ---
class ThumbnailSignals(QObject):
    # offset_datablock (object: offsets exceed 32-bit int), thumbnail image.
    # QImage rather than QPixmap: QPixmap must only be created in the GUI thread.
    ready = pyqtSignal(object, QImage)
    done = pyqtSignal(object)          # offset_datablock, emitted on success and failure


class ThumbnailWorker(QRunnable):
    """Reads the first few MB of a video block and extracts a preview frame via ffmpeg."""

    READ_SIZE = 4 * 1024 * 1024  # First 4 MB is enough to hit an I-frame

    def __init__(self, source_path: str, entry: HIKBTREEEntry, block_size: int):
        super().__init__()
        self.source_path = source_path
        self.entry = entry
        self.block_size = block_size
        self.signals = ThumbnailSignals()

    def run(self):
        offset = self.entry.offset_datablock
        try:
            image = self._extract()
            if image is not None:
                self.signals.ready.emit(offset, image)
        except Exception:
            pass
        finally:
            self.signals.done.emit(offset)

    def _extract(self) -> Optional[QImage]:
        read_size = min(self.READ_SIZE, self.block_size)
        start = self.entry.offset_datablock

        st = os.stat(self.source_path)
        if stat.S_ISBLK(st.st_mode):
            fd = os.open(self.source_path, os.O_RDONLY)
            try:
                data = os.pread(fd, read_size, start)
            finally:
                os.close(fd)
        else:
            with open(self.source_path, "rb") as f:
                f.seek(start)
                data = f.read(read_size)

        # Locate MPEG-PS pack start code
        nal_pos = data.find(b"\x00\x00\x01\xba")
        if nal_pos < 0:
            return None
        data = data[nal_pos:]

        # Decode only keyframes and write the JPEG to stdout (no temp file)
        proc = subprocess.run(
            [
                "ffmpeg",
                "-loglevel", "error",
                "-nostdin",
                "-threads", "1",  # several run in parallel; don't let each grab every core
                "-err_detect", "ignore_err",
                "-skip_frame", "nokey",
                "-f", "mpeg",
                "-i", "pipe:0",
                "-frames:v", "1",
                "-vf", "scale=160:-1",
                "-f", "image2pipe", "-c:v", "mjpeg",
                "pipe:1",
            ],
            input=data,
            capture_output=True,
            timeout=15,
            preexec_fn=lambda: os.nice(19),
        )
        if not proc.stdout:
            return None
        image = QImage.fromData(proc.stdout, "JPG")
        return None if image.isNull() else image


def _theme_icon(name: str, fallback: QStyle.StandardPixmap) -> QIcon:
    """Icon from the desktop icon theme, falling back to Qt's built-in one."""
    return QIcon.fromTheme(name, QApplication.style().standardIcon(fallback))


def _make_bold(widget: QWidget):
    """Bold the widget's own (system) font instead of replacing the font family."""
    font = widget.font()
    font.setBold(True)
    widget.setFont(font)


# --- 5. Main GUI Window ---
class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Hikvision DVR Forensic Extractor")
        self.setGeometry(100, 100, 1050, 720)

        self.threadpool = QThreadPool()
        self.thumb_pool = QThreadPool()
        self.thumb_pool.setMaxThreadCount(max(2, min(6, (os.cpu_count() or 2) // 2)))
        self.current_parser: Optional[HikvisionParser] = None
        self._elevated_devices: list[str] = []  # devices we chmod'd; restored on close
        self._delegate = DayBorderDelegate(self)
        self._thumb_cache: dict[tuple, QPixmap] = {}
        self._thumb_pending: set[tuple] = set()   # thumbnails queued or running
        self._row_by_offset: dict[int, int] = {}  # offset_datablock -> table row
        self._all_entries: list = []
        self._sort_col: int = 2          # default: start time
        self._sort_asc: bool = True

        self._setup_ui()

    def _setup_ui(self):
        # Central Widget and Main Layout
        central_widget = QWidget()
        main_layout = QVBoxLayout(central_widget)
        main_layout.setContentsMargins(12, 12, 12, 6)
        main_layout.setSpacing(10)
        self.setCentralWidget(central_widget)

        # --- A. Input Selection Widget ---
        input_group = QWidget()
        input_layout = QGridLayout(input_group)
        input_layout.setContentsMargins(0, 0, 0, 0)

        self.input_path_line = QLineEdit()
        self.input_path_line.setPlaceholderText("Select a disk image or block device (e.g. /dev/sdb)")
        self.input_path_line.setClearButtonEnabled(True)
        self.input_path_line.textChanged.connect(self._on_input_changed)
        self.btn_open_file = QPushButton(
            _theme_icon("document-open", QStyle.StandardPixmap.SP_DialogOpenButton), "Open Image…")
        self.btn_open_file.clicked.connect(self.select_input_file)
        self.btn_open_device = QPushButton(
            _theme_icon("drive-harddisk", QStyle.StandardPixmap.SP_DriveHDIcon), "Select Device…")
        self.btn_open_device.clicked.connect(self.select_device)

        self.output_path_line = QLineEdit()
        self.output_path_line.setReadOnly(True)
        self.output_path_line.setPlaceholderText("Select an output folder for videos")
        self.output_path_line.setText(QSettings("hikextractor", "gui").value("output_dir", ""))
        self.btn_select_output = QPushButton(
            _theme_icon("folder", QStyle.StandardPixmap.SP_DirIcon), "Choose Folder…")
        self.btn_select_output.clicked.connect(self.select_output_directory)

        self.btn_parse = QPushButton("Parse Metadata")
        self.btn_parse.clicked.connect(self.start_parsing)
        _make_bold(self.btn_parse)
        self.btn_parse.setEnabled(False)  # Enable after input is set

        # Layout for Input
        input_layout.addWidget(QLabel("Input:"), 0, 0)
        input_layout.addWidget(self.input_path_line, 0, 1)
        btn_open_layout = QHBoxLayout()
        btn_open_layout.setContentsMargins(0, 0, 0, 0)
        btn_open_layout.addWidget(self.btn_open_file)
        btn_open_layout.addWidget(self.btn_open_device)
        input_layout.addLayout(btn_open_layout, 0, 2)

        input_layout.addWidget(QLabel("Output folder:"), 1, 0)
        input_layout.addWidget(self.output_path_line, 1, 1)
        input_layout.addWidget(self.btn_select_output, 1, 2)

        input_layout.addWidget(self.btn_parse, 2, 2)

        main_layout.addWidget(input_group)

        # --- B. Metadata Display ---
        self.metadata_label = QLabel("Ready. Select a disk image file or a block device to begin.")
        self.metadata_label.setWordWrap(True)
        self.metadata_label.setFrameShape(QFrame.Shape.StyledPanel)
        self.metadata_label.setMargin(8)
        self.metadata_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        main_layout.addWidget(self.metadata_label)

        # --- C. Results Table (HIKBTREE Entries) ---
        self.table_segments = QTableWidget()
        self.table_segments.setColumnCount(6)
        self.table_segments.setHorizontalHeaderLabels(
            ["Preview", "Channel", "Start Time (UTC)", "End Time (UTC)", "Recording", "Data Offset"]
        )
        hdr = self.table_segments.horizontalHeader()
        hdr.setSectionResizeMode(0, QHeaderView.ResizeMode.Fixed)
        self.table_segments.setColumnWidth(0, 170)
        hdr.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        hdr.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        hdr.setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        hdr.setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
        hdr.setSectionResizeMode(5, QHeaderView.ResizeMode.ResizeToContents)
        hdr.setDefaultAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
        hdr.setHighlightSections(False)
        self.table_segments.verticalHeader().setDefaultSectionSize(90)
        self.table_segments.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table_segments.setSelectionMode(QTableWidget.SelectionMode.ExtendedSelection)
        self.table_segments.verticalHeader().setVisible(False)
        self.table_segments.setShowGrid(False)
        self.table_segments.setWordWrap(False)
        self.table_segments.setIconSize(QSize(12, 12))
        self.table_segments.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table_segments.setItemDelegate(self._delegate)
        hdr.setSectionsClickable(True)
        hdr.sectionClicked.connect(self._on_header_clicked)

        # --- C2. Channel filter bar ---
        filter_layout = QHBoxLayout()
        filter_layout.addWidget(QLabel("Show:"))
        self.combo_channel_filter = QComboBox()
        self.combo_channel_filter.addItem("All channels")
        self.combo_channel_filter.setMinimumWidth(160)
        self.combo_channel_filter.currentIndexChanged.connect(self._apply_channel_filter)
        filter_layout.addWidget(self.combo_channel_filter)
        filter_layout.addStretch()
        main_layout.addLayout(filter_layout)

        main_layout.addWidget(self.table_segments)

        # --- D. Export Controls ---
        export_control_layout = QHBoxLayout()

        self.checkbox_raw = QCheckBox("Export as raw H.264 (.h264)")
        self.btn_export_selected = QPushButton(
            _theme_icon("document-save", QStyle.StandardPixmap.SP_DialogSaveButton), "Export Selected")
        self.btn_export_selected.clicked.connect(self.start_export_selected)
        _make_bold(self.btn_export_selected)
        self.btn_export_selected.setEnabled(False) # Enabled after parsing

        export_control_layout.addWidget(self.checkbox_raw)
        export_control_layout.addStretch()
        export_control_layout.addWidget(self.btn_export_selected)

        main_layout.addLayout(export_control_layout)

        # Status Bar, with the progress bar at its right edge
        self.status_bar = self.statusBar()
        self.progress_bar = QProgressBar()
        self.progress_bar.setMaximumWidth(220)
        self.progress_bar.setVisible(False)
        self.status_bar.addPermanentWidget(self.progress_bar)

    # --- UI Logic Methods ---
    def _on_input_changed(self, text: str):
        """Enable Parse button as soon as input field has any text."""
        self.btn_parse.setEnabled(bool(text.strip()))

    def _set_input(self, path: str):
        """Set the input path, initialise the parser, and check device permissions."""
        self.input_path_line.setText(path)
        self.current_parser = HikvisionParser(path)
        self.status_bar.showMessage(f"Input set: {path}")

        # If this is a block device we can't read, offer privilege escalation
        if os.path.exists(path):
            try:
                st = os.stat(path)
                if stat.S_ISBLK(st.st_mode) and not os.access(path, os.R_OK):
                    self._prompt_escalate(path)
            except OSError:
                pass

    def _prompt_escalate(self, device_path: str):
        """Ask the user to grant read permission on the device via pkexec."""
        reply = QMessageBox.question(
            self,
            "Elevated Privileges Required",
            f"Reading <b>{device_path}</b> requires root access.<br><br>"
            "Grant read permission to this device? You will be prompted for your password.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        if reply == QMessageBox.StandardButton.Yes:
            self._grant_device_access(device_path)

    def _grant_device_access(self, device_path: str):
        """Run pkexec chmod o+r on the device so we can read it as a normal user."""
        try:
            result = subprocess.run(
                ["pkexec", "chmod", "o+r", device_path],
                capture_output=True,
            )
            if result.returncode == 0:
                self._elevated_devices.append(device_path)
                self.status_bar.showMessage(f"Read access granted to {device_path}")
            else:
                err = result.stderr.decode("utf-8", "ignore").strip()
                QMessageBox.warning(
                    self,
                    "Access Denied",
                    f"Could not grant read access to <b>{device_path}</b>.<br><br>"
                    f"{err}<br><br>"
                    f"You can do it manually with:<br><code>sudo chmod o+r {device_path}</code>",
                )
        except FileNotFoundError:
            QMessageBox.warning(
                self,
                "pkexec Not Found",
                f"Please grant access manually from a terminal:<br><br>"
                f"<code>sudo chmod o+r {device_path}</code>",
            )

    def closeEvent(self, event):
        """Restore device permissions that were relaxed during this session."""
        for device in self._elevated_devices:
            subprocess.run(["pkexec", "chmod", "o-r", device], capture_output=True)
        super().closeEvent(event)

    def select_input_file(self):
        """Opens a file dialog for a disk image."""
        settings = QSettings("hikextractor", "gui")
        start_dir = settings.value("input_dir", "")
        filename, _ = QFileDialog.getOpenFileName(
            self,
            "Open Hikvision Disk Image",
            start_dir if start_dir and os.path.isdir(start_dir) else QDir.homePath(),
            "Raw Disk Images (*.dd *.img *.bin);;All Files (*)"
        )
        if filename:
            settings.setValue("input_dir", os.path.dirname(filename))
            self._set_input(filename)

    def select_device(self):
        """Opens the device selection dialog populated by lsblk."""
        dlg = DeviceSelectDialog(self)
        if dlg.exec() == QDialog.DialogCode.Accepted and dlg.selected_device:
            self._set_input(dlg.selected_device)

    def select_output_directory(self):
        """Opens a directory dialog for the output folder."""
        saved_output = QSettings("hikextractor", "gui").value("output_dir", "")
        directory = QFileDialog.getExistingDirectory(
            self,
            "Select Output Directory",
            saved_output if saved_output and os.path.isdir(saved_output) else QDir.homePath()
        )
        if directory:
            self.output_path_line.setText(directory)
            QSettings("hikextractor", "gui").setValue("output_dir", directory)
            self.status_bar.showMessage(f"Output folder set: {directory}")

    def start_parsing(self):
        """Starts the metadata parsing process in a worker thread."""
        input_path = self.input_path_line.text().strip()
        if not input_path:
            QMessageBox.critical(self, "Error", "No input path specified.")
            return
        if not os.path.exists(input_path):
            QMessageBox.critical(self, "Error", f"Not found: {input_path}")
            return
        st = os.stat(input_path)
        if not (stat.S_ISREG(st.st_mode) or stat.S_ISBLK(st.st_mode)):
            QMessageBox.critical(self, "Error", "Input must be a regular file or block device.")
            return
        if not os.access(input_path, os.R_OK):
            if stat.S_ISBLK(os.stat(input_path).st_mode):
                self._prompt_escalate(input_path)
                if not os.access(input_path, os.R_OK):
                    return  # User cancelled or grant failed
            else:
                QMessageBox.critical(self, "Permission Denied", f"Cannot read: {input_path}")
                return
        # Reinitialise parser in case path was typed manually
        self.current_parser = HikvisionParser(input_path)

        self.btn_parse.setEnabled(False)
        self.btn_export_selected.setEnabled(False)
        self.status_bar.showMessage("Starting metadata parsing. Please wait...")
        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, 0)  # Indeterminate mode
        
        # Reset table and metadata display; drop thumbnail jobs not yet started
        self.thumb_pool.clear()
        self._thumb_pending.clear()
        self._row_by_offset.clear()
        self.table_segments.setRowCount(0)
        self.metadata_label.setText("Parsing...")
        
        # Create and start the worker for parsing
        worker = ParserWorker(self.current_parser, None, False)
        worker.signals.result_metadata.connect(self.parsing_complete)
        worker.signals.error.connect(self.worker_error)
        worker.signals.finished.connect(self.worker_finished)
        self.threadpool.start(worker)

    def parsing_complete(self, master: MasterBlock, entry_list: list[HIKBTREEEntry]):
        """Slot called when metadata parsing is done."""

        # 1. Update Metadata Display
        metadata_text = (
            f"<b>HD Signature:</b> {master.signature.decode('utf-8')}<br>"
            f"<b>Filesystem Version:</b> {master.version.decode('utf-8')}<br>"
            f"<b>Data Block Size:</b> {master.size_data_block / (1024*1024):.2f} MB<br>"
            f"<b>Time System Init:</b> {master.time_system_init:%Y-%m-%d %H:%M}"
        )
        self.metadata_label.setText(metadata_text)

        # 2. Store entries and populate the table
        self._all_entries = list(entry_list)
        self._sort_col = 2
        self._sort_asc = True
        self._populate_table(self._all_entries)

        # 3. Populate channel filter (block signals to avoid triggering filter during rebuild)
        self.combo_channel_filter.blockSignals(True)
        self.combo_channel_filter.clear()
        self.combo_channel_filter.addItem("All channels")
        for ch in sorted({e.channel for e in entry_list}):
            self.combo_channel_filter.addItem(f"Channel {ch:02d}", userData=ch)
        self.combo_channel_filter.blockSignals(False)

        self.status_bar.showMessage(f"Parsing complete. Found {len(entry_list)} video segments.")
        self.btn_export_selected.setEnabled(True)

    def _sorted_entries(self, col: int, ascending: bool) -> list:
        """Return _all_entries sorted by the given column with secondary sort by date."""
        _min = datetime.min
        if col == 1:  # Channel → secondary sort by start time
            key = lambda e: (e.channel, e.start_timestamp or _min)
        elif col == 2:  # Start time
            key = lambda e: e.start_timestamp or _min
        elif col == 3:  # End time
            key = lambda e: e.end_timestamp or _min
        else:
            return list(self._all_entries)
        return sorted(self._all_entries, key=key, reverse=not ascending)

    def _on_header_clicked(self, col: int):
        """Sort the table by the clicked column; toggle direction on repeated clicks."""
        if col == 0 or not self._all_entries:  # Preview column — not sortable
            return
        if col == self._sort_col:
            self._sort_asc = not self._sort_asc
        else:
            self._sort_col = col
            self._sort_asc = True
        self._populate_table(self._sorted_entries(self._sort_col, self._sort_asc))
        # Update sort indicator
        hdr = self.table_segments.horizontalHeader()
        hdr.setSortIndicatorShown(True)
        hdr.setSortIndicator(
            self._sort_col,
            Qt.SortOrder.AscendingOrder if self._sort_asc else Qt.SortOrder.DescendingOrder,
        )

    def _populate_table(self, entries: list):
        """Fill the segment table with the given (pre-sorted) entry list."""
        block_size = self.current_parser.master_block.size_data_block

        # Band alternate calendar days (painted by the delegate from the palette)
        row_days: list[int] = []
        prev_date = None
        day_index = -1
        for entry in entries:
            current_date = entry.start_timestamp.date() if entry.start_timestamp else None
            if current_date != prev_date:
                day_index += 1
                prev_date = current_date
            row_days.append(day_index % 2)

        mono = QFontDatabase.systemFont(QFontDatabase.SystemFont.FixedFont)
        right = Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter
        dim = self.table_segments.palette().color(QPalette.ColorRole.PlaceholderText)

        self.table_segments.setRowCount(len(entries))
        self._row_by_offset = {}
        for row, entry in enumerate(entries):
            self._row_by_offset[entry.offset_datablock] = row
            day = row_days[row]

            def _item(text="", _day=day, muted=False):
                it = QTableWidgetItem(text)
                it.setData(DAY_ROLE, _day)
                it.setFlags(it.flags() & ~Qt.ItemFlag.ItemIsEditable)
                if muted:
                    it.setForeground(dim)
                return it

            # Preview placeholder (thumbnail filled in asynchronously)
            preview_item = _item()
            self.table_segments.setItem(row, 0, preview_item)

            ch_item = _item(f"{entry.channel:02d}")
            ch_item.setIcon(_channel_dot(entry.channel))
            self.table_segments.setItem(row, 1, ch_item)

            # Blocks still being written when the DVR stopped carry no timestamps
            if entry.start_timestamp:
                start_item = _item(f"{entry.start_timestamp:%Y-%m-%d %H:%M:%S}")
            else:
                start_item = _item("In progress" if entry.recording else "N/A", muted=True)
                font = start_item.font()
                font.setItalic(True)
                start_item.setFont(font)
            start_item.setData(Qt.ItemDataRole.UserRole + 1, entry)  # entry reference for export
            self.table_segments.setItem(row, 2, start_item)

            if entry.end_timestamp:
                end_item = _item(f"{entry.end_timestamp:%Y-%m-%d %H:%M:%S}")
            else:
                end_item = _item("—", muted=True)
            self.table_segments.setItem(row, 3, end_item)

            recording_item = _item("In progress" if entry.recording else "—", muted=not entry.recording)
            self.table_segments.setItem(row, 4, recording_item)
            offset_item = _item(f"0x{entry.offset_datablock:X}")
            offset_item.setFont(mono)
            offset_item.setTextAlignment(right)
            self.table_segments.setItem(row, 5, offset_item)

            # Serve from cache or kick off thumbnail generation. In-progress blocks
            # are included: their start is usually written already; if not, the
            # worker simply yields no image and the cell stays empty.
            cache_key = (self.current_parser.source_path, entry.offset_datablock)
            if cache_key in self._thumb_cache:
                preview_item.setData(Qt.ItemDataRole.UserRole, self._thumb_cache[cache_key])
            elif cache_key not in self._thumb_pending:  # re-sorting must not re-queue
                self._thumb_pending.add(cache_key)
                worker = ThumbnailWorker(self.current_parser.source_path, entry, block_size)
                worker.signals.ready.connect(self._on_thumbnail_ready)
                worker.signals.done.connect(self._on_thumbnail_done)
                self.thumb_pool.start(worker)

        self.table_segments.resizeColumnsToContents()
        self.table_segments.setColumnWidth(0, 170)  # keep preview column fixed after resize

    def _on_thumbnail_ready(self, offset: int, image: QImage):
        """Slot: stores the thumbnail pixmap on the preview cell and populates the cache."""
        if not self.current_parser:
            return
        pixmap = QPixmap.fromImage(image)
        self._thumb_cache[(self.current_parser.source_path, offset)] = pixmap
        row = self._row_by_offset.get(offset)
        if row is not None:
            preview = self.table_segments.item(row, 0)
            if preview:
                preview.setData(Qt.ItemDataRole.UserRole, pixmap)

    def _on_thumbnail_done(self, offset: int):
        """Slot: a thumbnail job finished (successfully or not)."""
        if self.current_parser:
            self._thumb_pending.discard((self.current_parser.source_path, offset))

    def _apply_channel_filter(self):
        """Show only rows matching the selected channel (or all rows)."""
        selected_ch = self.combo_channel_filter.currentData()  # None for "All channels"
        for row in range(self.table_segments.rowCount()):
            item = self.table_segments.item(row, 2)
            entry = item.data(Qt.ItemDataRole.UserRole + 1) if item else None
            hide = selected_ch is not None and (entry is None or entry.channel != selected_ch)
            self.table_segments.setRowHidden(row, hide)

    def start_export_selected(self):
        """Initiates the export process for selected segments."""
        if not self.current_parser or not self.current_parser.entry_list:
            QMessageBox.warning(self, "Warning", "Please parse metadata first.")
            return

        dest_folder = self.output_path_line.text()
        if not os.path.isdir(dest_folder):
            QMessageBox.critical(self, "Error", "Output folder is invalid or not selected.")
            return

        # Get selected rows
        selected_rows = sorted(list(set(index.row() for index in self.table_segments.selectedIndexes())))
        if not selected_rows:
            QMessageBox.warning(self, "Warning", "Please select at least one video segment to export.")
            return

        # Build the list of selected entries (read from table — order may differ from entry_list)
        export_list = []
        for row in selected_rows:
            item = self.table_segments.item(row, 2)
            if item:
                entry = item.data(Qt.ItemDataRole.UserRole + 1)
                if entry:
                    export_list.append(entry)
        
        self.btn_export_selected.setEnabled(False)
        self.btn_parse.setEnabled(False)
        self.status_bar.showMessage(f"Starting export of {len(export_list)} segments...")
        
        # Start export worker
        worker = ParserWorker(self.current_parser, dest_folder, self.checkbox_raw.isChecked(), export_list)
        self._export_io_errors = 0
        worker.signals.export_started.connect(self.export_started)
        worker.signals.export_progress.connect(self.export_progress)
        worker.signals.export_skipped.connect(self._on_export_skipped)
        worker.signals.error.connect(self.worker_error)
        worker.signals.finished.connect(self.worker_finished)
        self.threadpool.start(worker)

    def export_started(self, total_count: int):
        """Slot for when export starts."""
        self.progress_bar.setRange(0, total_count)
        self.progress_bar.setValue(0)
        self.progress_bar.setVisible(True)

    def export_progress(self, current_index: int, message: str):
        """Slot to update progress bar and status bar during export."""
        self.progress_bar.setValue(current_index)
        self.status_bar.showMessage(f"Exporting ({current_index}/{self.progress_bar.maximum()}) - {message}")

    # --- Worker Management Slots ---
    def worker_error(self, error_tuple: tuple):
        """Handles errors from the worker thread."""
        exc_type, exc_value, traceback_str = error_tuple
        QMessageBox.critical(
            self, 
            "Worker Error", 
            f"An error occurred in the background task:\n\n{exc_value}\n\nTraceback:\n{traceback_str}"
        )
        
    def worker_finished(self):
        """Slot called when any worker thread (parse or export) finishes."""
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(100)
        self.progress_bar.setVisible(False)
        
        self.btn_parse.setEnabled(True)
        if self.current_parser and self.current_parser.entry_list:
            self.btn_export_selected.setEnabled(True)
        
        if "Starting metadata parsing" in self.status_bar.currentMessage():
            self.status_bar.showMessage("Metadata Parsing Complete.", 5000)
        elif "Starting export" in self.status_bar.currentMessage():
            n = getattr(self, "_export_io_errors", 0)
            suffix = f"  ({n} segment{'s' if n != 1 else ''} skipped due to I/O errors)" if n else ""
            self.status_bar.showMessage(f"Export Complete.{suffix}", 8000)

    def _on_export_skipped(self, count: int):
        self._export_io_errors = count


if __name__ == "__main__":
    # On GNOME, take fonts, colors and file dialogs from GTK. Other desktops
    # (e.g. KDE) already provide their own platform theme; an explicit
    # QT_QPA_PLATFORMTHEME from the user always wins.
    if "GNOME" in os.environ.get("XDG_CURRENT_DESKTOP", "").upper():
        os.environ.setdefault("QT_QPA_PLATFORMTHEME", "gtk3")
    app = QApplication(sys.argv)
    app.setApplicationDisplayName("HikExtractor")
    app.setDesktopFileName("hikextractor")
    app.setWindowIcon(QIcon.fromTheme("camera-video"))
    if app.style().name().lower() == "windows":  # the legacy Win95 look: prefer Fusion
        app.setStyle("Fusion")
    window = MainWindow()
    window.show()
    sys.exit(app.exec())
