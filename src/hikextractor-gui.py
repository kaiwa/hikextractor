import sys
import os
import stat
import subprocess
import traceback
import tempfile
from typing import Optional, Set

from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QLineEdit, QLabel, QFileDialog, QTableWidget,
    QTableWidgetItem, QHeaderView, QCheckBox, QProgressBar, QMessageBox,
    QGridLayout, QSizePolicy, QDialog, QListWidget, QDialogButtonBox,
    QStyledItemDelegate, QComboBox,
)
from PyQt6.QtCore import (
    Qt, QObject, QRunnable, QThreadPool, pyqtSignal, QDir, QSize, QSettings,
)
from PyQt6.QtGui import QFont, QIcon, QPixmap, QPainter, QPen, QColor, QBrush

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

                    filename = self.parser.export_video_block(
                        entry, self.dest_folder, self.raw, on_progress=on_progress
                    )
                    completed_bytes += block_size
                    self.signals.export_progress.emit(
                        completed_bytes // (1024 * 1024),
                        f"Done ({i+1}/{total_entries}): {os.path.basename(filename)}"
                    )

        except Exception as e:
            # Catch any exception and emit it to the main thread
            self.signals.error.emit((type(e), e, traceback.format_exc()))
        finally:
            self.signals.finished.emit()


def _channel_brush(channel: int) -> QBrush:
    """Returns a muted, dark-theme-friendly color unique to each channel number."""
    hue = (channel * 53) % 360   # 53 is coprime with 360 → good spread
    return QBrush(QColor.fromHsv(hue, 130, 130))


# --- 3. Day-border delegate ---
class DayBorderDelegate(QStyledItemDelegate):
    """Paints thumbnails in col 0, scaled to fit the cell."""

    def paint(self, painter: QPainter, option, index):
        super().paint(painter, option, index)

        if index.column() == 0:
            pixmap = index.data(Qt.ItemDataRole.UserRole)
            if isinstance(pixmap, QPixmap) and not pixmap.isNull():
                target = option.rect.adjusted(2, 2, -2, -2)
                scaled = pixmap.scaled(
                    target.size(),
                    Qt.AspectRatioMode.KeepAspectRatio,
                    Qt.TransformationMode.SmoothTransformation,
                )
                x = target.x() + (target.width() - scaled.width()) // 2
                y = target.y() + (target.height() - scaled.height()) // 2
                painter.drawPixmap(x, y, scaled)


# --- 4. Thumbnail worker ---
class ThumbnailSignals(QObject):
    ready = pyqtSignal(int, QPixmap)   # row, thumbnail pixmap


class ThumbnailWorker(QRunnable):
    """Reads the first few MB of a video block and extracts a preview frame via ffmpeg."""

    READ_SIZE = 4 * 1024 * 1024  # First 4 MB is enough to hit an I-frame

    def __init__(self, row: int, source_path: str, entry: HIKBTREEEntry, block_size: int):
        super().__init__()
        self.row = row
        self.source_path = source_path
        self.entry = entry
        self.block_size = block_size
        self.signals = ThumbnailSignals()

    def run(self):
        try:
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
                return
            data = data[nal_pos:]

            tmp_fd, tmp_path = tempfile.mkstemp(suffix=".jpg")
            os.close(tmp_fd)
            try:
                proc = subprocess.Popen(
                    [
                        "ffmpeg",
                        "-err_detect", "ignore_err",
                        "-i", "pipe:0",
                        "-frames:v", "1",
                        "-vf", "scale=160:-1",
                        "-loglevel", "error",
                        "-y", tmp_path,
                    ],
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )
                proc.communicate(input=data, timeout=15)
                if os.path.exists(tmp_path) and os.path.getsize(tmp_path) > 0:
                    pixmap = QPixmap(tmp_path)
                    if not pixmap.isNull():
                        self.signals.ready.emit(self.row, pixmap)
            except Exception:
                pass
            finally:
                try:
                    os.unlink(tmp_path)
                except OSError:
                    pass
        except Exception:
            pass


# --- 5. Main GUI Window ---
class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Hikvision DVR Forensic Extractor — Image & Device")
        self.setGeometry(100, 100, 1050, 720)

        self.threadpool = QThreadPool()
        self.thumb_pool = QThreadPool()
        self.thumb_pool.setMaxThreadCount(2)
        self.current_parser: Optional[HikvisionParser] = None
        self._elevated_devices: list[str] = []  # devices we chmod'd; restored on close
        self._delegate = DayBorderDelegate(self)
        self._thumb_cache: dict[tuple, QPixmap] = {}

        self._setup_ui()
        self._apply_style()

    def _setup_ui(self):
        # Central Widget and Main Layout
        central_widget = QWidget()
        main_layout = QVBoxLayout(central_widget)
        self.setCentralWidget(central_widget)

        # --- A. Input Selection Widget ---
        input_group = QWidget()
        input_layout = QGridLayout(input_group)
        input_layout.setContentsMargins(0, 0, 0, 0)
        
        self.input_path_line = QLineEdit()
        self.input_path_line.setPlaceholderText("Select a disk image or block device (e.g. /dev/sdb)")
        self.input_path_line.textChanged.connect(self._on_input_changed)
        self.btn_open_file = QPushButton("Open Image")
        self.btn_open_file.setObjectName("btn_file")
        self.btn_open_file.clicked.connect(self.select_input_file)
        self.btn_open_device = QPushButton("Select Device")
        self.btn_open_device.setObjectName("btn_device")
        self.btn_open_device.clicked.connect(self.select_device)

        self.output_path_line = QLineEdit()
        self.output_path_line.setReadOnly(True)
        saved_output = QSettings("hikextractor", "gui").value("output_dir", "")
        self.output_path_line.setText(saved_output if saved_output else "Select an output directory for videos")
        self.btn_select_output = QPushButton("Select Output Folder")
        self.btn_select_output.clicked.connect(self.select_output_directory)

        self.btn_parse = QPushButton("1. PARSE METADATA")
        self.btn_parse.clicked.connect(self.start_parsing)
        self.btn_parse.setFont(QFont("Arial", 10, QFont.Weight.Bold))
        self.btn_parse.setEnabled(False)  # Enable after input is set

        # Layout for Input
        input_layout.addWidget(QLabel("Input:"), 0, 0)
        input_layout.addWidget(self.input_path_line, 0, 1)
        btn_open_layout = QHBoxLayout()
        btn_open_layout.setSpacing(6)
        btn_open_layout.setContentsMargins(0, 0, 0, 0)
        btn_open_layout.addWidget(self.btn_open_file)
        btn_open_layout.addWidget(self.btn_open_device)
        btn_open_container = QWidget()
        btn_open_container.setLayout(btn_open_layout)
        input_layout.addWidget(btn_open_container, 0, 2)
        
        input_layout.addWidget(QLabel("Output Folder:"), 1, 0)
        input_layout.addWidget(self.output_path_line, 1, 1)
        input_layout.addWidget(self.btn_select_output, 1, 2)
        
        input_layout.addWidget(self.btn_parse, 2, 0, 1, 3) # Span all columns

        main_layout.addWidget(input_group)
        
        # --- B. Metadata Display ---
        self.metadata_label = QLabel("Ready. Select a disk image file or a block device to begin.")
        self.metadata_label.setWordWrap(True)
        self.metadata_label.setStyleSheet("padding: 10px; border: 1px dashed #555555;")
        main_layout.addWidget(self.metadata_label)
        main_layout.addSpacing(15)

        # --- C. Results Table (HIKBTREE Entries) ---
        self.table_segments = QTableWidget()
        self.table_segments.setColumnCount(6)
        self.table_segments.setHorizontalHeaderLabels(
            ["Preview", "CH", "Start Time (UTC)", "End Time (UTC)", "Recording", "Data Offset"]
        )
        hdr = self.table_segments.horizontalHeader()
        hdr.setSectionResizeMode(0, QHeaderView.ResizeMode.Fixed)
        self.table_segments.setColumnWidth(0, 170)
        hdr.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        hdr.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        hdr.setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        hdr.setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
        hdr.setSectionResizeMode(5, QHeaderView.ResizeMode.ResizeToContents)
        self.table_segments.verticalHeader().setDefaultSectionSize(90)
        self.table_segments.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table_segments.setSelectionMode(QTableWidget.SelectionMode.ExtendedSelection)
        self.table_segments.verticalHeader().setVisible(False)
        self.table_segments.setItemDelegate(self._delegate)

        # --- C2. Channel filter bar ---
        filter_layout = QHBoxLayout()
        self.combo_channel_filter = QComboBox()
        self.combo_channel_filter.addItem("All channels")
        self.combo_channel_filter.setMinimumWidth(160)
        self.combo_channel_filter.currentIndexChanged.connect(self._apply_channel_filter)
        filter_layout.addWidget(self.combo_channel_filter)
        filter_layout.addStretch()
        main_layout.addLayout(filter_layout)

        main_layout.addWidget(self.table_segments)
        
        # --- D. Export Controls & Progress ---
        export_control_layout = QHBoxLayout()
        
        self.checkbox_raw = QCheckBox("Export as Raw H.264 (.h264)")
        self.btn_export_selected = QPushButton("2. EXPORT SELECTED")
        self.btn_export_selected.clicked.connect(self.start_export_selected)
        self.btn_export_selected.setFont(QFont("Arial", 10, QFont.Weight.Bold))
        self.btn_export_selected.setEnabled(False) # Enabled after parsing

        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        
        export_control_layout.addWidget(self.checkbox_raw)
        export_control_layout.addWidget(self.progress_bar)
        export_control_layout.addWidget(self.btn_export_selected)

        main_layout.addLayout(export_control_layout)

        # Status Bar
        self.status_bar = self.statusBar()

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
        filename, _ = QFileDialog.getOpenFileName(
            self,
            "Open Hikvision Disk Image",
            QDir.homePath(),
            "Raw Disk Images (*.dd *.img *.bin);;All Files (*)"
        )
        if filename:
            self._set_input(filename)

    def select_device(self):
        """Opens the device selection dialog populated by lsblk."""
        dlg = DeviceSelectDialog(self)
        if dlg.exec() == QDialog.DialogCode.Accepted and dlg.selected_device:
            self._set_input(dlg.selected_device)

    def select_output_directory(self):
        """Opens a directory dialog for the output folder."""
        directory = QFileDialog.getExistingDirectory(
            self,
            "Select Output Directory",
            QDir.homePath()
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
        
        # Reset table and metadata display
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

        # 2. Populate the table
        self.table_segments.setRowCount(len(entry_list))

        # Assign alternating background colors per calendar day
        DAY_COLORS = [QBrush(QColor("#3e3e3e")), QBrush(QColor("#4c4c4c"))]
        row_brushes: list[QBrush] = []
        prev_date = None
        day_index = -1
        for entry in entry_list:
            current_date = entry.start_timestamp.date() if entry.start_timestamp else None
            if current_date != prev_date:
                day_index += 1
                prev_date = current_date
            row_brushes.append(DAY_COLORS[day_index % 2])

        block_size = master.size_data_block
        for row, entry in enumerate(entry_list):
            brush = row_brushes[row]

            def _item(text=""):
                it = QTableWidgetItem(text)
                it.setBackground(brush)
                return it

            # Preview placeholder (thumbnail filled in asynchronously)
            preview_item = _item()
            preview_item.setFlags(preview_item.flags() & ~Qt.ItemFlag.ItemIsEditable)
            self.table_segments.setItem(row, 0, preview_item)

            ch_item = QTableWidgetItem(f"{entry.channel:02d}")
            ch_item.setBackground(_channel_brush(entry.channel))
            self.table_segments.setItem(row, 1, ch_item)

            start_time = f"{entry.start_timestamp:%Y-%m-%d %H:%M:%S}" if entry.start_timestamp else "N/A"
            self.table_segments.setItem(row, 2, _item(start_time))

            end_time = f"{entry.end_timestamp:%Y-%m-%d %H:%M:%S}" if entry.end_timestamp else "N/A"
            self.table_segments.setItem(row, 3, _item(end_time))

            self.table_segments.setItem(row, 4, _item("Yes" if entry.recording else "No"))
            self.table_segments.setItem(row, 5, _item(f"0x{entry.offset_datablock:X}"))

            # Serve from cache or kick off thumbnail generation
            if not entry.recording:
                cache_key = (self.current_parser.source_path, entry.offset_datablock)
                if cache_key in self._thumb_cache:
                    preview_item.setData(Qt.ItemDataRole.UserRole, self._thumb_cache[cache_key])
                else:
                    worker = ThumbnailWorker(row, self.current_parser.source_path, entry, block_size)
                    worker.signals.ready.connect(self._on_thumbnail_ready)
                    self.thumb_pool.start(worker)

        self.table_segments.resizeColumnsToContents()
        self.table_segments.setColumnWidth(0, 170)  # keep preview column fixed after resize

        # Populate channel filter (block signals to avoid triggering filter during rebuild)
        self.combo_channel_filter.blockSignals(True)
        self.combo_channel_filter.clear()
        self.combo_channel_filter.addItem("All channels")
        for ch in sorted({e.channel for e in entry_list}):
            self.combo_channel_filter.addItem(f"Channel {ch:02d}", userData=ch)
        self.combo_channel_filter.blockSignals(False)

        self.status_bar.showMessage(f"Parsing complete. Found {len(entry_list)} video segments.")
        self.btn_export_selected.setEnabled(True)

    def _on_thumbnail_ready(self, row: int, pixmap: QPixmap):
        """Slot: stores the thumbnail pixmap on the preview cell and populates the cache."""
        item = self.table_segments.item(row, 0)
        if item:
            item.setData(Qt.ItemDataRole.UserRole, pixmap)
        if self.current_parser and row < len(self.current_parser.entry_list):
            entry = self.current_parser.entry_list[row]
            self._thumb_cache[(self.current_parser.source_path, entry.offset_datablock)] = pixmap

    def _apply_channel_filter(self):
        """Show only rows matching the selected channel (or all rows)."""
        selected_ch = self.combo_channel_filter.currentData()  # None for "All channels"
        entry_list = self.current_parser.entry_list if self.current_parser else []
        for row, entry in enumerate(entry_list):
            hide = selected_ch is not None and entry.channel != selected_ch
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
            
        # Build the list of selected entries
        export_list = [self.current_parser.entry_list[row] for row in selected_rows]
        
        self.btn_export_selected.setEnabled(False)
        self.btn_parse.setEnabled(False)
        self.status_bar.showMessage(f"Starting export of {len(export_list)} segments...")
        
        # Start export worker
        worker = ParserWorker(self.current_parser, dest_folder, self.checkbox_raw.isChecked(), export_list)
        worker.signals.export_started.connect(self.export_started)
        worker.signals.export_progress.connect(self.export_progress)
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
            self.status_bar.showMessage("Export Complete.", 5000)


    # --- Modern Styling (QSS) ---
    def _apply_style(self):
        """Applies a simple dark theme using Qt Style Sheets."""
        self.setStyleSheet("""
            QMainWindow {
                background-color: #2e2e2e;
                color: #ffffff;
            }
            QLabel, QCheckBox {
                color: #cccccc;
            }
            QPushButton {
                background-color: #4CAF50;
                color: white;
                border: 1px solid #388E3C;
                padding: 8px 15px;
                border-radius: 4px;
            }
            QPushButton:hover {
                background-color: #45a049;
            }
            QPushButton:disabled {
                background-color: #555555;
                color: #999999;
            }
            QPushButton#btn_file {
                background-color: #5a5a5a;
                border: 1px solid #444444;
            }
            QPushButton#btn_file:hover {
                background-color: #6a6a6a;
            }
            QPushButton#btn_device {
                background-color: #1a6eb5;
                border: 1px solid #144f80;
            }
            QPushButton#btn_device:hover {
                background-color: #1e80d0;
            }
            QLineEdit {
                background-color: #3e3e3e;
                color: white;
                border: 1px solid #555555;
                padding: 5px;
            }
            QTableWidget {
                background-color: #3e3e3e;
                color: white;
                gridline-color: #555555;
                selection-background-color: #1e87f0; /* Blue highlight */
                border: 1px solid #555555;
            }
            QHeaderView::section {
                background-color: #505050;
                color: white;
                padding: 4px;
                border: 1px solid #444444;
            }
            QProgressBar {
                border: 1px solid #555555;
                border-radius: 5px;
                text-align: center;
                color: white;
                background-color: #3e3e3e;
            }
            QProgressBar::chunk {
                background-color: #4CAF50;
                margin: 0px;
            }
        """)


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())