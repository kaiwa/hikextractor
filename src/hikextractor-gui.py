import sys
import os
import stat
import subprocess
import traceback
from datetime import datetime, timedelta
from typing import Optional, Set

from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QLineEdit, QLabel, QFileDialog, QTableWidget,
    QTableWidgetItem, QHeaderView, QMessageBox, QGridLayout, QDialog, QListWidget,
    QDialogButtonBox, QStyledItemDelegate, QStyle, QFrame, QToolButton,
    QAbstractButton, QAbstractItemView, QScrollArea, QSizePolicy, QToolTip,
)
from PyQt6.QtCore import (
    Qt, QObject, QRunnable, QThreadPool, pyqtSignal, QDir, QSize, QSettings, QRectF,
    QPointF, QTimer, QItemSelection, QItemSelectionModel,
)
from PyQt6.QtGui import (
    QIcon, QPixmap, QImage, QPainter, QPainterPath, QColor, QFont, QFontDatabase,
    QFontMetrics, QPalette, QPen, QBrush, QLinearGradient, QGradient,
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


# --- 3. Theme (colors and type from the "HikExtractor Redesign" design) ---
class C:
    """Design palette; the design's oklch values converted to sRGB."""
    WINDOW = "#fbfaf8"
    BAR = "#f5f3f0"            # footer
    SIDEBAR = "#f8f6f4"        # sidebar and table header
    BORDER = "#e0deda"
    ROW_BORDER = "#e9e7e5"
    FIELD_BORDER = "#d0cdc9"
    BTN_HOVER = "#f6f5f2"
    TEXT = "#1d1a15"
    TEXT_SOFT = "#4b4742"
    MUTED = "#66635d"
    LANE_LABEL = "#58554f"
    CLEAR = "#75716b"
    BADGE_BG = "#f0eeeb"
    TRACK = "#f0eeeb"
    DARK = "#24211c"
    DARK_HOVER = "#383530"
    LINK = "#0e5794"
    LINK_HOVER = "#003b75"
    SIDE_HOVER = "#edebe7"
    CHECK_ON = "#302d28"
    CHECK_OFF = "#b9b7b3"
    ROW_SEL = "#e5f0fc"
    ROW_HOVER = "#edf2f8"
    STRIPE_A = "#e0deda"
    STRIPE_B = "#edebe7"
    PROG_RUN = "#4081d2"
    PROG_DONE = "#51a556"
    TOGGLE_OFF = "#c6c4c0"
    EXPORT = "#2769b7"
    EXPORT_HOVER = "#155aa7"
    EXPORT_OFF = "#b9bec4"


SANS = "IBM Plex Sans"
MONO = "IBM Plex Mono"
FONT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fonts")

# The first four match the design's CH01–CH04; the rest continue around the hue wheel
CHANNEL_COLORS = [
    "#ba9c13", "#61b565", "#00b9b2", "#5fa1f3", "#e97871", "#c480d4", "#dd8736", "#9e8eef",
    "#94ab39", "#00b1da", "#de77ab", "#22b988", "#e67d58", "#8696f5", "#d0901e", "#00b6c7",
]


def channel_color(channel: int) -> QColor:
    return QColor(CHANNEL_COLORS[(channel - 1) % len(CHANNEL_COLORS)])


def ui_font(px: int, weight=QFont.Weight.Normal, mono=False, spacing_em=0.0, italic=False) -> QFont:
    font = QFont(MONO if mono else SANS)
    font.setPixelSize(px)
    font.setWeight(weight)
    font.setItalic(italic)
    if spacing_em:
        font.setLetterSpacing(QFont.SpacingType.AbsoluteSpacing, px * spacing_em)
    return font


# Timestamps from the disk are naive; treat them as-is (no local-time conversion)
EPOCH = datetime(1970, 1, 1)


def _secs(dt: datetime) -> float:
    return (dt - EPOCH).total_seconds()


def _from_secs(s: float) -> datetime:
    return EPOCH + timedelta(seconds=s)


def fmt_duration(seconds: float) -> str:
    s = int(round(seconds))
    return f"{s // 3600}:{s % 3600 // 60:02d}:{s % 60:02d}"


def fmt_size(n_bytes: float) -> str:
    mb = n_bytes / (1024 * 1024)
    if mb >= 1024 * 1024:
        return f"{mb / (1024 * 1024):.2f} TB"
    if mb >= 1024:
        return f"{mb / 1024:.2f} GB"
    return f"{mb:.0f} MB"


def source_size(path: str) -> Optional[int]:
    """Size of a disk image or block device, or None if it can't be opened."""
    try:
        fd = os.open(path, os.O_RDONLY)
    except OSError:
        return None
    try:
        return os.lseek(fd, 0, os.SEEK_END)
    except OSError:
        return None
    finally:
        os.close(fd)


def paint_checkbox(p: QPainter, rect: QRectF, state: str):
    """Design checkbox: state is 'none', 'some' (dash) or 'all' (check mark)."""
    on = state != "none"
    p.save()
    p.setRenderHint(QPainter.RenderHint.Antialiasing)
    p.setPen(QPen(QColor(C.CHECK_ON if on else C.CHECK_OFF), 1.5))
    p.setBrush(QColor(C.CHECK_ON) if on else QColor("white"))
    p.drawRoundedRect(rect.adjusted(0.75, 0.75, -0.75, -0.75), 3.5, 3.5)
    if on:
        pen = QPen(QColor("white"), 1.6)
        pen.setCapStyle(Qt.PenCapStyle.RoundCap)
        pen.setJoinStyle(Qt.PenJoinStyle.RoundJoin)
        p.setPen(pen)
        x, y = rect.x(), rect.y()
        if state == "all":
            path = QPainterPath(QPointF(x + 4.2, y + 8.3))
            path.lineTo(x + 6.8, y + 10.9)
            path.lineTo(x + 11.8, y + 5.3)
            p.setBrush(Qt.BrushStyle.NoBrush)
            p.drawPath(path)
        else:
            p.drawLine(QPointF(x + 4.5, y + 8), QPointF(x + 11.5, y + 8))
    p.restore()


def cell_content_rect(rect, col: int, last_col: int = 7) -> QRectF:
    """Cell rect minus the design's row padding (20px sides) and 12px column gap."""
    left = 20 if col == 0 else 0
    right = 20 if col == last_col else 12
    return QRectF(rect.left() + left, rect.top(), rect.width() - left - right, rect.height())


STYLESHEET = f"""
QMainWindow, QWidget#central, QDialog, QMessageBox {{ background: {C.WINDOW}; }}
QLabel {{ color: {C.TEXT}; }}
QFrame#topbar {{ background: {C.WINDOW}; border-bottom: 1px solid {C.BORDER}; }}
QFrame#sidebar {{ background: {C.SIDEBAR}; border-right: 1px solid {C.BORDER}; }}
QScrollArea#sidebarScroll {{ background: {C.SIDEBAR}; border: none; }}
QFrame#footer {{ background: {C.BAR}; border-top: 1px solid {C.BORDER}; }}
QFrame#field, QLineEdit#field {{
    background: white; border: 1px solid {C.FIELD_BORDER}; border-radius: 7px; color: {C.TEXT};
}}
QLineEdit#field {{ padding: 0 11px; }}
QLineEdit#bare {{ background: transparent; border: none; padding: 0; color: {C.TEXT}; }}
QLabel#badge {{ background: {C.BADGE_BG}; color: {C.TEXT_SOFT}; border-radius: 4px; padding: 3px 8px; }}
QLabel#muted {{ color: {C.MUTED}; }}
QLabel#status, QLabel#summary {{ color: {C.TEXT_SOFT}; }}
QToolButton#clear {{ border: none; background: transparent; color: {C.CLEAR}; padding: 2px 6px; }}
QToolButton#clear:hover {{ color: {C.TEXT}; }}
QPushButton {{
    background: white; color: {C.TEXT}; border: 1px solid {C.FIELD_BORDER};
    border-radius: 7px; padding: 0 14px; min-height: 34px;
}}
QPushButton:hover {{ background: {C.BTN_HOVER}; }}
QPushButton:disabled {{ color: {C.CHECK_OFF}; }}
QPushButton#primary {{ background: {C.DARK}; color: white; border: none; padding: 0 18px; }}
QPushButton#primary:hover {{ background: {C.DARK_HOVER}; }}
QPushButton#primary:disabled {{ background: {C.CHECK_OFF}; color: white; }}
QPushButton#export {{ background: {C.EXPORT}; color: white; border: none; padding: 0 18px; }}
QPushButton#export:hover {{ background: {C.EXPORT_HOVER}; }}
QPushButton#export:disabled {{ background: {C.EXPORT_OFF}; color: white; }}
QPushButton#link {{ background: transparent; border: none; color: {C.LINK}; padding: 0; min-height: 0; }}
QPushButton#link:hover {{ color: {C.LINK_HOVER}; }}
QTableWidget {{ background: {C.WINDOW}; border: none; }}
QHeaderView {{ background: {C.SIDEBAR}; border: none; }}
QListWidget {{
    background: white; border: 1px solid {C.FIELD_BORDER}; border-radius: 7px; padding: 4px; color: {C.TEXT};
}}
QListWidget::item {{ padding: 6px; border-radius: 4px; }}
QListWidget::item:selected {{ background: {C.ROW_SEL}; color: {C.TEXT}; }}
QToolTip {{ background: {C.DARK}; color: white; border: none; padding: 4px 8px; }}
QScrollBar:vertical {{ background: transparent; width: 10px; margin: 2px; }}
QScrollBar:horizontal {{ background: transparent; height: 10px; margin: 2px; }}
QScrollBar::handle {{ background: {C.FIELD_BORDER}; border-radius: 3px; min-height: 30px; min-width: 30px; }}
QScrollBar::handle:hover {{ background: {C.CHECK_OFF}; }}
QScrollBar::add-line, QScrollBar::sub-line {{ width: 0; height: 0; }}
QScrollBar::add-page, QScrollBar::sub-page {{ background: transparent; }}
"""


def light_palette() -> QPalette:
    """The design is light-only; keep stock widgets (dialogs, menus) consistent with it."""
    pal = QPalette()
    roles = {
        QPalette.ColorRole.Window: C.WINDOW,
        QPalette.ColorRole.WindowText: C.TEXT,
        QPalette.ColorRole.Base: "#ffffff",
        QPalette.ColorRole.AlternateBase: C.SIDEBAR,
        QPalette.ColorRole.Text: C.TEXT,
        QPalette.ColorRole.Button: "#ffffff",
        QPalette.ColorRole.ButtonText: C.TEXT,
        QPalette.ColorRole.Highlight: C.EXPORT,
        QPalette.ColorRole.HighlightedText: "#ffffff",
        QPalette.ColorRole.PlaceholderText: C.MUTED,
        QPalette.ColorRole.ToolTipBase: C.DARK,
        QPalette.ColorRole.ToolTipText: "#ffffff",
        QPalette.ColorRole.Link: C.LINK,
        QPalette.ColorRole.Mid: C.BORDER,
    }
    for role, color in roles.items():
        pal.setColor(role, QColor(color))
    return pal


class SectionLabel(QLabel):
    """Small uppercase section title ("SOURCE", "CHANNELS", ...)."""

    def __init__(self, text: str, parent=None):
        super().__init__(text.upper(), parent)
        self.setObjectName("muted")
        self.setFont(ui_font(11, QFont.Weight.Medium, spacing_em=0.06))


class ThinProgress(QWidget):
    """4px progress track: blue while running (animated when indeterminate), green when done."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFixedSize(120, 4)
        self._max = 100
        self._value = 0
        self._phase = 0.0
        self._timer = QTimer(self)
        self._timer.setInterval(30)
        self._timer.timeout.connect(self._tick)

    def setRange(self, minimum: int, maximum: int):
        self._max = maximum
        if maximum == 0:
            self._timer.start()
        else:
            self._timer.stop()
        self.update()

    def setValue(self, value: int):
        self._value = value
        self.update()

    def maximum(self) -> int:
        return self._max

    def _tick(self):
        self._phase = (self._phase + 0.02) % 1.3
        self.update()

    def paintEvent(self, event):
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        p.setPen(Qt.PenStyle.NoPen)
        track = QPainterPath()
        track.addRoundedRect(QRectF(self.rect()), 2, 2)
        p.setClipPath(track)
        p.fillRect(self.rect(), QColor(C.BORDER))
        w = self.width()
        if self._max == 0:  # indeterminate: a sliding segment
            p.fillRect(QRectF((self._phase - 0.3) * w, 0, 0.3 * w, self.height()), QColor(C.PROG_RUN))
        elif self._value > 0:
            done = self._value >= self._max
            p.fillRect(QRectF(0, 0, w * min(1.0, self._value / self._max), self.height()),
                       QColor(C.PROG_DONE if done else C.PROG_RUN))


class ToggleSwitch(QAbstractButton):
    """Switch-style checkbox with its label, e.g. "Raw H.264 .h264"."""

    def __init__(self, text: str, suffix: str, parent=None):
        super().__init__(parent)
        self.setCheckable(True)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self._text = text + " "
        self._suffix = suffix
        self._font = ui_font(13)
        self._suffix_font = ui_font(11, mono=True)

    def sizeHint(self) -> QSize:
        w = (38 + QFontMetrics(self._font).horizontalAdvance(self._text)
             + QFontMetrics(self._suffix_font).horizontalAdvance(self._suffix))
        return QSize(w + 2, 22)

    def paintEvent(self, event):
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        y = (self.height() - 18) / 2
        p.setPen(Qt.PenStyle.NoPen)
        p.setBrush(QColor(C.CHECK_ON if self.isChecked() else C.TOGGLE_OFF))
        p.drawRoundedRect(QRectF(0, y, 30, 18), 9, 9)
        knob_x = 14 if self.isChecked() else 2
        p.setBrush(QColor(40, 36, 30, 50))  # soft shadow
        p.drawEllipse(QRectF(knob_x, y + 3, 14, 14))
        p.setBrush(QColor("white"))
        p.drawEllipse(QRectF(knob_x, y + 2, 14, 14))

        fm = QFontMetrics(self._font)
        baseline = (self.height() + fm.ascent() - fm.descent()) / 2
        p.setFont(self._font)
        p.setPen(QColor(C.TEXT))
        p.drawText(QPointF(38, baseline), self._text)
        p.setFont(self._suffix_font)
        p.setPen(QColor(C.MUTED))
        p.drawText(QPointF(38 + fm.horizontalAdvance(self._text), baseline), self._suffix)


class ChannelRow(QWidget):
    """Sidebar row: visibility checkbox, color dot, "CH 01", segment count and hours."""
    toggled = pyqtSignal(int)

    def __init__(self, channel: int, count: int, hours: float, parent=None):
        super().__init__(parent)
        self.channel = channel
        self.checked = True
        self._stats = f"{count} seg · {hours:.1f}h"
        self._hover = False
        self.setFixedHeight(32)
        self.setCursor(Qt.CursorShape.PointingHandCursor)

    def set_checked(self, checked: bool):
        self.checked = checked
        self.update()

    def enterEvent(self, event):
        self._hover = True
        self.update()

    def leaveEvent(self, event):
        self._hover = False
        self.update()

    def mouseReleaseEvent(self, event):
        if event.button() == Qt.MouseButton.LeftButton and self.rect().contains(event.position().toPoint()):
            self.toggled.emit(self.channel)

    def paintEvent(self, event):
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        if self._hover:
            p.setPen(Qt.PenStyle.NoPen)
            p.setBrush(QColor(C.SIDE_HOVER))
            p.drawRoundedRect(QRectF(self.rect()), 6, 6)
        paint_checkbox(p, QRectF(8, 8, 16, 16), "all" if self.checked else "none")
        p.setPen(Qt.PenStyle.NoPen)
        p.setBrush(channel_color(self.channel))
        p.drawEllipse(QRectF(34, 12, 8, 8))
        text_rect = QRectF(52, 0, self.width() - 60, self.height())
        p.setFont(ui_font(13, QFont.Weight.Medium))
        p.setPen(QColor(C.TEXT))
        p.drawText(text_rect, Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft,
                   f"CH {self.channel:02d}")
        p.setFont(ui_font(11, mono=True))
        p.setPen(QColor(C.MUTED))
        p.drawText(text_rect, Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignRight, self._stats)


class CoverageView(QWidget):
    """Per-channel timeline of all timed segments; clicking a bar toggles its selection."""
    barClicked = pyqtSignal(object)  # offset_datablock (object: exceeds 32-bit int)

    PAD_T, PAD_X, PAD_B = 16, 20, 14
    HEAD_H, HEAD_GAP = 16, 10
    LANE_H, GAP = 16, 6
    LABEL_W, LABEL_GAP = 40, 10
    TICK_H = 14
    # Candidate tick spacings; the smallest giving at most 8 intervals is used
    STEPS = [3600, 2 * 3600, 3 * 3600, 6 * 3600, 12 * 3600, 86400, 2 * 86400, 7 * 86400,
             14 * 86400, 30 * 86400, 91 * 86400, 182 * 86400, 365 * 86400]

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setMouseTracking(True)
        self._segs: list[tuple] = []      # (channel, start_s, end_s, entry)
        self._channels: list[int] = []
        self._hidden: set = set()
        self._selected: set = set()       # offset_datablock values
        self._hits: list[tuple] = []      # (QRectF, entry), rebuilt on paint
        self._t0 = self._t1 = 0.0
        self._ticks: list[tuple] = []     # (t, label, align)
        self._range_label = ""
        self.setVisible(False)

    def set_entries(self, entries: list):
        self._segs = [
            (e.channel, _secs(e.start_timestamp), _secs(e.end_timestamp), e)
            for e in entries if e.start_timestamp and e.end_timestamp
        ]
        self._channels = sorted({s[0] for s in self._segs})
        self._hidden = set()
        self._selected = set()
        if self._segs:
            self._compute_axis()
        self._relayout()

    def set_hidden(self, hidden: set):
        self._hidden = set(hidden)
        self._relayout()

    def set_selected(self, offsets: set):
        self._selected = offsets
        self.update()

    def _lanes(self) -> list[int]:
        return [ch for ch in self._channels if ch not in self._hidden]

    def _relayout(self):
        n = len(self._lanes())
        self.setVisible(bool(self._segs) and n > 0)
        self.setFixedHeight(self.PAD_T + self.HEAD_H + self.HEAD_GAP
                            + n * (self.LANE_H + self.GAP) + self.TICK_H + self.PAD_B + 1)
        self.update()

    def _compute_axis(self):
        lo = min(s[1] for s in self._segs)
        hi = max(s[2] for s in self._segs)
        for step in self.STEPS:
            t0 = (lo // step) * step
            t1 = -(-hi // step) * step
            if (t1 - t0) / step <= 8:
                break
        if t1 <= t0:
            t1 = t0 + step
        self._t0, self._t1 = t0, t1
        long_span = t1 - t0 > 365 * 86400
        ticks = []
        t, i = t0, 0
        while t <= t1 + 0.5:
            d = _from_secs(t)
            if step < 86400:
                midnight = d.hour == 0 and d.minute == 0
                label = d.strftime("%m-%d %H:%M") if i == 0 or midnight else d.strftime("%H:%M")
            else:
                label = d.strftime("%Y-%m-%d") if long_span else d.strftime("%m-%d")
            align = "left" if i == 0 else ("right" if t + step > t1 + 0.5 else "center")
            ticks.append((t, label, align))
            t += step
            i += 1
        self._ticks = ticks
        self._range_label = (f"{_from_secs(t0):%Y-%m-%d} → {_from_secs(t1):%Y-%m-%d}"
                             " · gaps shown as empty track")

    def paintEvent(self, event):
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        w, h = self.width(), self.height()
        p.fillRect(self.rect(), QColor(C.WINDOW))
        p.setPen(QColor(C.BORDER))
        p.drawLine(0, h - 1, w, h - 1)

        x0 = self.PAD_X
        inner_w = w - 2 * self.PAD_X
        head = QRectF(x0, self.PAD_T, inner_w, self.HEAD_H)
        p.setFont(ui_font(11, QFont.Weight.Medium, spacing_em=0.06))
        p.setPen(QColor(C.MUTED))
        p.drawText(head, Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter, "COVERAGE")
        p.setFont(ui_font(12))
        p.drawText(head, Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter, self._range_label)

        track_x = x0 + self.LABEL_W + self.LABEL_GAP
        track_w = max(1.0, x0 + inner_w - track_x)
        span = max(1.0, self._t1 - self._t0)
        y = self.PAD_T + self.HEAD_H + self.HEAD_GAP
        self._hits = []
        label_font = ui_font(11, mono=True)
        for ch in self._lanes():
            p.setFont(label_font)
            p.setPen(QColor(C.LANE_LABEL))
            p.drawText(QRectF(x0, y, self.LABEL_W, self.LANE_H),
                       Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter, f"CH{ch:02d}")
            p.setPen(Qt.PenStyle.NoPen)
            p.setBrush(QColor(C.TRACK))
            p.drawRoundedRect(QRectF(track_x, y, track_w, self.LANE_H), 3, 3)

            bars = []
            for seg_ch, start, end, entry in self._segs:
                if seg_ch != ch:
                    continue
                bx = track_x + (start - self._t0) / span * track_w
                bw = max(2.0, (end - start) / span * track_w)
                bars.append((QRectF(bx, y + 2, bw, self.LANE_H - 4), entry))
            color = channel_color(ch)
            faded = QColor(color)
            faded.setAlphaF(0.45)
            # Unselected first so selected bars (and their ring) sit on top
            bars.sort(key=lambda b: b[1].offset_datablock in self._selected)
            for rect, entry in bars:
                on = entry.offset_datablock in self._selected
                p.setPen(Qt.PenStyle.NoPen)
                p.setBrush(color if on else faded)
                p.drawRoundedRect(rect, 2, 2)
                if on:
                    p.setPen(QPen(QColor(C.DARK), 1.5))
                    p.setBrush(Qt.BrushStyle.NoBrush)
                    p.drawRoundedRect(rect.adjusted(-0.75, -0.75, 0.75, 0.75), 2.5, 2.5)
                self._hits.append((rect, entry))
            y += self.LANE_H + self.GAP

        p.setFont(ui_font(10, mono=True))
        p.setPen(QColor(C.MUTED))
        fm = QFontMetrics(p.font())
        for t, label, align in self._ticks:
            tx = track_x + (t - self._t0) / span * track_w
            tw = fm.horizontalAdvance(label)
            lx = tx if align == "left" else (tx - tw if align == "right" else tx - tw / 2)
            p.drawText(QRectF(lx, y, tw + 2, self.TICK_H),
                       Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignTop, label)

    def _hit(self, pos) -> Optional[HIKBTREEEntry]:
        for rect, entry in reversed(self._hits):
            if rect.adjusted(-1, -2, 1, 2).contains(pos):
                return entry
        return None

    def mouseMoveEvent(self, event):
        entry = self._hit(event.position())
        if entry:
            self.setCursor(Qt.CursorShape.PointingHandCursor)
            QToolTip.showText(
                event.globalPosition().toPoint(),
                f"CH{entry.channel:02d}  {entry.start_timestamp:%Y-%m-%d %H:%M:%S}"
                f" → {entry.end_timestamp:%H:%M:%S}",
                self,
            )
        else:
            self.unsetCursor()
            QToolTip.hideText()

    def mouseReleaseEvent(self, event):
        if event.button() == Qt.MouseButton.LeftButton:
            entry = self._hit(event.position())
            if entry:
                self.barClicked.emit(entry.offset_datablock)


ENTRY_ROLE = Qt.ItemDataRole.UserRole + 1   # on column 0: the row's HIKBTREEEntry
THUMB_ROLE = Qt.ItemDataRole.UserRole       # on column 1: the preview QPixmap


class SegmentHeader(QHeaderView):
    """Uppercase column titles, a select-all checkbox and the sort arrow on Start."""
    LABELS = ["", "Preview", "Channel", "Start", "End", "Duration", "Size", "Offset"]
    RIGHT = {5, 6, 7}

    def __init__(self, parent=None):
        super().__init__(Qt.Orientation.Horizontal, parent)
        self.check_state = "none"
        self.sort_asc = True
        self.setFixedHeight(36)
        self.setSectionsClickable(True)
        self.setHighlightSections(False)

    def paintSection(self, p: QPainter, rect, idx: int):
        p.save()
        p.fillRect(rect, QColor(C.SIDEBAR))
        p.setPen(QColor(C.BORDER))
        p.drawLine(rect.left(), rect.bottom(), rect.right(), rect.bottom())
        content = cell_content_rect(rect, idx)
        if idx == 0:
            paint_checkbox(p, QRectF(content.left(), rect.top() + (rect.height() - 16) / 2, 16, 16),
                           self.check_state)
        else:
            text = self.LABELS[idx].upper()
            if idx == 3:
                text += " ↑" if self.sort_asc else " ↓"
            p.setFont(ui_font(11, QFont.Weight.Medium, spacing_em=0.04))
            p.setPen(QColor(C.MUTED))
            h_align = Qt.AlignmentFlag.AlignRight if idx in self.RIGHT else Qt.AlignmentFlag.AlignLeft
            p.drawText(content, h_align | Qt.AlignmentFlag.AlignVCenter, text)
        p.restore()


class SegmentDelegate(QStyledItemDelegate):
    """Paints each segment cell as in the design: checkbox, preview, dot, mono values."""

    def __init__(self, table):
        super().__init__(table)
        self.table = table
        self.mono12 = ui_font(12, mono=True)
        self.mono12i = ui_font(12, mono=True, italic=True)
        self.mono13 = ui_font(13, mono=True)

    def sizeHint(self, option, index) -> QSize:
        return QSize(0, 70)

    def paint(self, p: QPainter, option, index):
        row, col = index.row(), index.column()
        rect = option.rect
        selected = bool(option.state & QStyle.StateFlag.State_Selected)
        p.save()
        entry = self.table.entry_at(row)
        exportable = entry is not None and not entry.recording
        hover = exportable and row == self.table.hover_row
        bg = C.ROW_SEL if selected else (C.ROW_HOVER if hover else C.WINDOW)
        p.fillRect(rect, QColor(bg))
        p.setPen(QColor(C.ROW_BORDER))
        p.drawLine(rect.left(), rect.bottom(), rect.right(), rect.bottom())

        if entry is not None:
            c = cell_content_rect(rect, col)
            p.setClipRect(c)
            cy = rect.top() + rect.height() / 2
            left = Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter
            right = Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter
            if col == 0:
                if not exportable:
                    p.setOpacity(0.35)  # in-progress blocks can't be selected for export
                paint_checkbox(p, QRectF(c.left(), cy - 8, 16, 16), "all" if selected else "none")
            elif col == 1:
                self._paint_thumb(p, QRectF(c.left(), cy - 27, 96, 54), index.data(THUMB_ROLE))
            elif col == 2:
                p.setRenderHint(QPainter.RenderHint.Antialiasing)
                p.setPen(Qt.PenStyle.NoPen)
                p.setBrush(channel_color(entry.channel))
                p.drawEllipse(QRectF(c.left(), cy - 4, 8, 8))
                p.setFont(self.mono13)
                p.setPen(QColor(C.TEXT))
                p.drawText(c.adjusted(16, 0, 0, 0), left, f"{entry.channel:02d}")
            elif col in (3, 4):
                ts = entry.start_timestamp if col == 3 else entry.end_timestamp
                if ts:
                    date = f"{ts:%Y-%m-%d} "
                    p.setFont(self.mono12)
                    p.setPen(QColor(C.MUTED))
                    p.drawText(c, left, date)
                    p.setPen(QColor(C.TEXT))
                    advance = QFontMetrics(self.mono12).horizontalAdvance(date)
                    p.drawText(c.adjusted(advance, 0, 0, 0), left, f"{ts:%H:%M:%S}")
                elif col == 3 and entry.recording:
                    # Blocks still being written when the DVR stopped carry no timestamps
                    p.setFont(self.mono12i)
                    p.setPen(QColor(C.MUTED))
                    p.drawText(c, left, "In progress")
                else:
                    p.setFont(self.mono12)
                    p.setPen(QColor(C.MUTED))
                    p.drawText(c, left, "—" if entry.recording else "N/A")
            elif col == 5:
                p.setFont(self.mono12)
                if entry.start_timestamp and entry.end_timestamp:
                    p.setPen(QColor(C.TEXT))
                    p.drawText(c, right, fmt_duration(
                        (entry.end_timestamp - entry.start_timestamp).total_seconds()))
                else:
                    p.setPen(QColor(C.MUTED))
                    p.drawText(c, right, "—")
            elif col == 6:
                p.setFont(self.mono12)
                p.setPen(QColor(C.TEXT))
                p.drawText(c, right, fmt_size(self.table.block_size))
            elif col == 7:
                p.setFont(self.mono12)
                p.setPen(QColor(C.TEXT_SOFT))
                p.drawText(c, right, f"0x{entry.offset_datablock:X}")
        p.restore()

    @staticmethod
    def _paint_thumb(p: QPainter, r: QRectF, pixmap):
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        p.setRenderHint(QPainter.RenderHint.SmoothPixmapTransform)
        clip = QPainterPath()
        clip.addRoundedRect(r, 4, 4)
        p.setClipPath(clip)
        if isinstance(pixmap, QPixmap) and not pixmap.isNull():
            # Fill the 16:9 box, cropping the frame's excess edges
            pw, ph = pixmap.width(), pixmap.height()
            scale = max(r.width() / pw, r.height() / ph)
            sw, sh = r.width() / scale, r.height() / scale
            p.drawPixmap(r, pixmap, QRectF((pw - sw) / 2, (ph - sh) / 2, sw, sh))
        else:
            # Diagonal stripes, as the design's placeholder frame
            period = 12 / 2 ** 0.5
            grad = QLinearGradient(r.topLeft(), r.topLeft() + QPointF(period, period))
            grad.setSpread(QGradient.Spread.RepeatSpread)
            grad.setColorAt(0.0, QColor(C.STRIPE_A))
            grad.setColorAt(0.4999, QColor(C.STRIPE_A))
            grad.setColorAt(0.5, QColor(C.STRIPE_B))
            grad.setColorAt(1.0, QColor(C.STRIPE_B))
            p.fillRect(r, QBrush(grad))


class SegmentTable(QTableWidget):
    """Segment list; clicking a row toggles it (checkbox semantics)."""
    WIDTHS = {0: 48, 1: 108, 2: 76, 5: 84, 6: 84, 7: 130}

    def __init__(self, parent=None):
        super().__init__(0, 8, parent)
        self.hover_row = -1
        self.block_size = 0
        self.empty_text = ""
        header = SegmentHeader(self)
        self.setHorizontalHeader(header)
        for col, width in self.WIDTHS.items():
            header.setSectionResizeMode(col, QHeaderView.ResizeMode.Fixed)
            self.setColumnWidth(col, width)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
        self.verticalHeader().setVisible(False)
        self.verticalHeader().setDefaultSectionSize(70)
        self.setShowGrid(False)
        self.setFrameShape(QFrame.Shape.NoFrame)
        self.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.setSelectionMode(QAbstractItemView.SelectionMode.MultiSelection)
        self.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.setVerticalScrollMode(QAbstractItemView.ScrollMode.ScrollPerPixel)
        self.setHorizontalScrollMode(QAbstractItemView.ScrollMode.ScrollPerPixel)
        self.setWordWrap(False)
        self.setMouseTracking(True)
        self.setItemDelegate(SegmentDelegate(self))

    def entry_at(self, row: int):
        item = self.item(row, 0)
        return item.data(ENTRY_ROLE) if item else None

    def selectable_rows(self) -> list[int]:
        """Visible rows that can be selected for export (not in-progress blocks)."""
        return [r for r in range(self.rowCount())
                if not self.isRowHidden(r) and (e := self.entry_at(r)) is not None and not e.recording]

    def mouseMoveEvent(self, event):
        row = self.rowAt(int(event.position().y()))
        if row != self.hover_row:
            self.hover_row = row
            self.viewport().update()
        super().mouseMoveEvent(event)

    def leaveEvent(self, event):
        self.hover_row = -1
        self.viewport().update()
        super().leaveEvent(event)

    def paintEvent(self, event):
        super().paintEvent(event)
        if self.rowCount() == 0 and self.empty_text:
            p = QPainter(self.viewport())
            p.setFont(ui_font(13))
            p.setPen(QColor(C.MUTED))
            p.drawText(self.viewport().rect(), Qt.AlignmentFlag.AlignCenter, self.empty_text)


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


# --- 5. Main GUI Window ---
class MainWindow(QMainWindow):
    READY_TEXT = "Ready. Select a disk image or a block device to begin."

    def __init__(self):
        super().__init__()
        self.setWindowTitle("Hikvision DVR Forensic Extractor")
        self.setMinimumSize(960, 560)
        # 75% of the screen (capped at the design's 1280x860): GNOME auto-maximizes
        # new windows that cover most of the work area.
        area = QApplication.primaryScreen().availableGeometry()
        size = QSize(min(1280, max(960, int(area.width() * 0.75))),
                     min(860, max(560, int(area.height() * 0.75))))
        self.resize(size)
        self.move(area.center().x() - size.width() // 2, area.center().y() - size.height() // 2)

        self.threadpool = QThreadPool()
        self.thumb_pool = QThreadPool()
        self.thumb_pool.setMaxThreadCount(max(2, min(6, (os.cpu_count() or 2) // 2)))
        self.current_parser: Optional[HikvisionParser] = None
        self._elevated_devices: list[str] = []  # devices we chmod'd; restored on close
        self._thumb_cache: dict[tuple, QPixmap] = {}
        self._thumb_pending: set[tuple] = set()   # thumbnails queued or running
        self._row_by_offset: dict[int, int] = {}  # offset_datablock -> table row
        self._all_entries: list = []
        self._hidden_channels: set[int] = set()
        self._channel_rows: dict[int, ChannelRow] = {}
        self._sort_asc: bool = True
        self._task: Optional[str] = None          # "parse" / "export" while a worker runs
        self._export_count = 0
        self._export_io_errors = 0

        self._setup_ui()

    def _setup_ui(self):
        central = QWidget()
        central.setObjectName("central")
        root = QVBoxLayout(central)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)
        self.setCentralWidget(central)

        root.addWidget(self._build_topbar())

        body = QHBoxLayout()
        body.setContentsMargins(0, 0, 0, 0)
        body.setSpacing(0)
        body.addWidget(self._build_sidebar())

        main = QVBoxLayout()
        main.setContentsMargins(0, 0, 0, 0)
        main.setSpacing(0)
        self.coverage = CoverageView()
        self.coverage.barClicked.connect(self._toggle_offset)
        main.addWidget(self.coverage)
        self.table_segments = SegmentTable()
        self.table_segments.empty_text = self.READY_TEXT
        self.table_segments.selectionModel().selectionChanged.connect(self._on_selection_changed)
        self.table_segments.horizontalHeader().sectionClicked.connect(self._on_header_clicked)
        main.addWidget(self.table_segments, 1)
        body.addLayout(main, 1)
        root.addLayout(body, 1)

        root.addWidget(self._build_footer())
        self._update_selection_ui()

    def _build_topbar(self) -> QWidget:
        top = QFrame()
        top.setObjectName("topbar")
        grid = QGridLayout(top)
        grid.setContentsMargins(20, 16, 20, 16)
        grid.setHorizontalSpacing(16)
        grid.setVerticalSpacing(6)
        grid.setColumnStretch(0, 13)  # the design's 1.3fr : 1fr
        grid.setColumnStretch(1, 10)

        mono13 = ui_font(13, mono=True)

        # Source: path, size badge and clear button inside one field
        source_field = QFrame()
        source_field.setObjectName("field")
        source_field.setFixedHeight(36)
        field_layout = QHBoxLayout(source_field)
        field_layout.setContentsMargins(12, 0, 6, 0)
        field_layout.setSpacing(10)
        self.input_path_line = QLineEdit()
        self.input_path_line.setObjectName("bare")
        self.input_path_line.setFont(mono13)
        self.input_path_line.setPlaceholderText("Disk image or block device, e.g. /dev/sdb")
        self.input_path_line.returnPressed.connect(self._on_source_entered)
        self.input_path_line.textChanged.connect(self._on_input_changed)
        self.source_badge = QLabel()
        self.source_badge.setObjectName("badge")
        self.source_badge.setFont(ui_font(11))
        self.source_badge.setVisible(False)
        self.btn_clear = QToolButton()
        self.btn_clear.setObjectName("clear")
        self.btn_clear.setText("×")
        self.btn_clear.setFont(ui_font(16))
        self.btn_clear.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_clear.setToolTip("Clear source")
        self.btn_clear.setVisible(False)
        self.btn_clear.clicked.connect(self._clear_input)
        field_layout.addWidget(self.input_path_line, 1)
        field_layout.addWidget(self.source_badge, 0, Qt.AlignmentFlag.AlignVCenter)
        field_layout.addWidget(self.btn_clear)

        self.btn_open_file = QPushButton("Open image…")
        self.btn_open_file.clicked.connect(self.select_input_file)
        self.btn_open_device = QPushButton("Select device…")
        self.btn_open_device.clicked.connect(self.select_device)

        source_row = QHBoxLayout()
        source_row.setSpacing(8)
        source_row.addWidget(source_field, 1)
        source_row.addWidget(self.btn_open_file)
        source_row.addWidget(self.btn_open_device)

        self.output_path_line = QLineEdit()
        self.output_path_line.setObjectName("field")
        self.output_path_line.setFont(mono13)
        self.output_path_line.setFixedHeight(36)
        self.output_path_line.setReadOnly(True)
        self.output_path_line.setPlaceholderText("Choose where videos are saved")
        self.output_path_line.setText(QSettings("hikextractor", "gui").value("output_dir", ""))
        self.btn_select_output = QPushButton("Choose…")
        self.btn_select_output.clicked.connect(self.select_output_directory)

        output_row = QHBoxLayout()
        output_row.setSpacing(8)
        output_row.addWidget(self.output_path_line, 1)
        output_row.addWidget(self.btn_select_output)

        for button in (self.btn_open_file, self.btn_open_device, self.btn_select_output):
            button.setFixedHeight(36)
            button.setFont(ui_font(13))
            button.setCursor(Qt.CursorShape.PointingHandCursor)

        grid.addWidget(SectionLabel("Source"), 0, 0)
        grid.addWidget(SectionLabel("Output folder"), 0, 1)
        self.btn_parse = QPushButton("Parse metadata")
        self.btn_parse.setObjectName("primary")
        self.btn_parse.setFixedHeight(36)
        self.btn_parse.setFont(ui_font(13, QFont.Weight.Medium))
        self.btn_parse.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_parse.setEnabled(False)  # enabled once there is a source path
        self.btn_parse.clicked.connect(self.start_parsing)

        grid.addLayout(source_row, 1, 0)
        grid.addLayout(output_row, 1, 1)
        grid.addWidget(self.btn_parse, 1, 2)
        return top

    def _build_sidebar(self) -> QWidget:
        scroll = QScrollArea()
        scroll.setObjectName("sidebarScroll")
        scroll.setFixedWidth(260)
        scroll.setWidgetResizable(True)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        sidebar = QFrame()
        sidebar.setObjectName("sidebar")
        scroll.setWidget(sidebar)
        layout = QVBoxLayout(sidebar)
        layout.setContentsMargins(16, 18, 16, 18)
        layout.setSpacing(24)

        # Disk metadata
        meta = QVBoxLayout()
        meta.setSpacing(10)
        meta.addWidget(SectionLabel("Disk metadata"))
        meta_grid = QGridLayout()
        meta_grid.setHorizontalSpacing(12)
        meta_grid.setVerticalSpacing(8)
        self._meta_values: dict[str, QLabel] = {}
        for i, key in enumerate(("Signature", "Filesystem", "Block size", "System init")):
            name = QLabel(key)
            name.setObjectName("muted")
            name.setFont(ui_font(12))
            value = QLabel("—")
            value.setFont(ui_font(12, mono=True))
            value.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
            value.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            meta_grid.addWidget(name, i, 0)
            meta_grid.addWidget(value, i, 1)
            self._meta_values[key] = value
        meta_grid.setColumnStretch(1, 1)
        meta.addLayout(meta_grid)
        layout.addLayout(meta)

        # Channels
        channels = QVBoxLayout()
        channels.setSpacing(10)
        head = QHBoxLayout()
        head.addWidget(SectionLabel("Channels"))
        head.addStretch()
        self.btn_show_all = QPushButton("Show all")
        self.btn_show_all.setObjectName("link")
        self.btn_show_all.setFont(ui_font(12))
        self.btn_show_all.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_show_all.clicked.connect(self._show_all_channels)
        head.addWidget(self.btn_show_all)
        channels.addLayout(head)
        self.channel_list = QVBoxLayout()
        self.channel_list.setSpacing(2)
        self.channel_empty = QLabel("No channels yet")
        self.channel_empty.setObjectName("muted")
        self.channel_empty.setFont(ui_font(12))
        self.channel_list.addWidget(self.channel_empty)
        channels.addLayout(self.channel_list)
        layout.addLayout(channels)
        layout.addStretch()
        return scroll

    def _build_footer(self) -> QWidget:
        footer = QFrame()
        footer.setObjectName("footer")
        footer.setFixedHeight(60)
        layout = QHBoxLayout(footer)
        layout.setContentsMargins(20, 0, 20, 0)
        layout.setSpacing(20)

        status = QHBoxLayout()
        status.setSpacing(10)
        self.progress_bar = ThinProgress()
        self.status_label = QLabel(self.READY_TEXT)
        self.status_label.setObjectName("status")
        self.status_label.setFont(ui_font(12))
        # Long export messages must not push the controls on the right
        self.status_label.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Preferred)
        status.addWidget(self.progress_bar)
        status.addWidget(self.status_label, 1)
        layout.addLayout(status, 1)

        self.checkbox_raw = ToggleSwitch("Raw H.264", ".h264")
        layout.addWidget(self.checkbox_raw)

        self.selection_summary = QLabel()
        self.selection_summary.setObjectName("summary")
        self.selection_summary.setFont(ui_font(12, mono=True))
        layout.addWidget(self.selection_summary)

        self.btn_export_selected = QPushButton("Export")
        self.btn_export_selected.setObjectName("export")
        self.btn_export_selected.setFixedHeight(36)
        self.btn_export_selected.setFont(ui_font(13, QFont.Weight.Medium))
        self.btn_export_selected.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_export_selected.clicked.connect(self.start_export_selected)
        layout.addWidget(self.btn_export_selected)
        return footer

    # --- UI Logic Methods ---
    def _set_status(self, text: str):
        self.status_label.setText(text)
        self.status_label.setToolTip(text)

    def _set_busy(self, task: Optional[str]):
        """Lock the inputs while a parse or export worker runs."""
        self._task = task
        idle = task is None
        for widget in (self.input_path_line, self.btn_clear, self.btn_open_file,
                       self.btn_open_device, self.btn_select_output):
            widget.setEnabled(idle)
        self.btn_parse.setText("Parsing…" if task == "parse" else "Parse metadata")
        self.btn_parse.setEnabled(idle and bool(self.input_path_line.text().strip()))
        self._update_selection_ui()

    def _on_input_changed(self, text: str):
        self.btn_clear.setVisible(bool(text))
        self.btn_parse.setEnabled(self._task is None and bool(text.strip()))

    def _on_source_entered(self):
        path = self.input_path_line.text().strip()
        if path and self._task is None:
            self._set_input(path)

    def _set_input(self, path: str):
        """Set the input path and start parsing it right away."""
        self.input_path_line.setText(path)
        self.start_parsing()

    def _update_badge(self, path: str):
        size = source_size(path)
        self.source_badge.setText("Read-only" + (f" · {fmt_size(size)}" if size else ""))
        self.source_badge.setVisible(True)

    def _clear_input(self):
        if self._task is not None:
            return
        self.input_path_line.clear()
        self.source_badge.setVisible(False)
        self.current_parser = None
        self._reset_results()
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        self._set_status(self.READY_TEXT)

    def _reset_results(self):
        """Empty the table, sidebar and timeline; drop thumbnail jobs not yet started."""
        self.thumb_pool.clear()
        self._thumb_pending.clear()
        self._row_by_offset.clear()
        self._all_entries = []
        self._hidden_channels = set()
        self.table_segments.setRowCount(0)
        self.coverage.set_entries([])
        for value in self._meta_values.values():
            value.setText("—")
        self._rebuild_channel_rows()
        self._update_selection_ui()

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
                self._set_status(f"Read access granted to {device_path}")
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
            self._set_status(f"Output folder set: {directory}")

    def start_parsing(self):
        """Starts the metadata parsing process in a worker thread."""
        if self._task is not None:
            return
        input_path = self.input_path_line.text().strip()
        if not input_path:
            return
        if not os.path.exists(input_path):
            QMessageBox.critical(self, "Error", f"Not found: {input_path}")
            return
        st = os.stat(input_path)
        if not (stat.S_ISREG(st.st_mode) or stat.S_ISBLK(st.st_mode)):
            QMessageBox.critical(self, "Error", "Input must be a regular file or block device.")
            return
        if not os.access(input_path, os.R_OK):
            if stat.S_ISBLK(st.st_mode):
                self._prompt_escalate(input_path)
                if not os.access(input_path, os.R_OK):
                    self._set_status(f"No read access to {input_path}")
                    return  # User cancelled or grant failed
            else:
                QMessageBox.critical(self, "Permission Denied", f"Cannot read: {input_path}")
                return
        self._update_badge(input_path)
        self.current_parser = HikvisionParser(input_path)

        self._reset_results()
        self._set_busy("parse")
        self._set_status("Reading index blocks…")
        self.progress_bar.setRange(0, 0)  # Indeterminate mode

        # Create and start the worker for parsing
        worker = ParserWorker(self.current_parser, None, False)
        worker.signals.result_metadata.connect(self.parsing_complete)
        worker.signals.error.connect(self.worker_error)
        worker.signals.finished.connect(self.worker_finished)
        self.threadpool.start(worker)

    def parsing_complete(self, master: MasterBlock, entry_list: list[HIKBTREEEntry]):
        """Slot called when metadata parsing is done."""
        self._meta_values["Signature"].setText(master.signature.decode("utf-8", "replace"))
        self._meta_values["Filesystem"].setText(master.version.decode("utf-8", "replace"))
        self._meta_values["Block size"].setText(f"{master.size_data_block / (1024 * 1024):.2f} MB")
        self._meta_values["System init"].setText(f"{master.time_system_init:%Y-%m-%d %H:%M}")

        self._all_entries = list(entry_list)
        self._hidden_channels = set()
        self._sort_asc = True
        self.table_segments.horizontalHeader().sort_asc = True
        self.table_segments.block_size = master.size_data_block
        self.coverage.set_entries(self._all_entries)
        self._rebuild_channel_rows()
        self._populate_table(self._sorted_entries())
        self._update_parse_status()

    def _update_parse_status(self):
        n_channels = len({e.channel for e in self._all_entries})
        text = (f"Parsing complete · {len(self._all_entries)} segments across "
                f"{n_channels} channel{'s' if n_channels != 1 else ''}")
        if self._hidden_channels:
            shown = sum(1 for e in self._all_entries if e.channel not in self._hidden_channels)
            text += f" · {shown} shown"
        self._set_status(text)

    def _rebuild_channel_rows(self):
        for row in self._channel_rows.values():
            row.deleteLater()
        self._channel_rows = {}
        for ch in sorted({e.channel for e in self._all_entries}):
            entries = [e for e in self._all_entries if e.channel == ch]
            hours = sum((e.end_timestamp - e.start_timestamp).total_seconds()
                        for e in entries if e.start_timestamp and e.end_timestamp) / 3600
            row = ChannelRow(ch, len(entries), hours)
            row.toggled.connect(self._toggle_channel)
            self.channel_list.addWidget(row)
            self._channel_rows[ch] = row
        self.channel_empty.setVisible(not self._channel_rows)

    def _toggle_channel(self, channel: int):
        if channel in self._hidden_channels:
            self._hidden_channels.discard(channel)
        else:
            self._hidden_channels.add(channel)
        self._apply_channel_filter()

    def _show_all_channels(self):
        self._hidden_channels = set()
        self._apply_channel_filter()

    def _apply_channel_filter(self):
        """Hide rows and timeline lanes of unchecked channels."""
        for ch, row in self._channel_rows.items():
            row.set_checked(ch not in self._hidden_channels)
        for row in range(self.table_segments.rowCount()):
            entry = self.table_segments.entry_at(row)
            self.table_segments.setRowHidden(row, entry is not None and entry.channel in self._hidden_channels)
        self.coverage.set_hidden(self._hidden_channels)
        self._update_parse_status()
        self._update_selection_ui()

    def _sorted_entries(self) -> list:
        """Entries by start time; in-progress blocks (no timestamp) sort first."""
        _min = datetime.min
        return sorted(self._all_entries, key=lambda e: e.start_timestamp or _min,
                      reverse=not self._sort_asc)

    def _on_header_clicked(self, col: int):
        if not self._all_entries:
            return
        if col == 0:
            self._toggle_all_visible()
        elif col == 3:  # Start: flip sort direction
            self._sort_asc = not self._sort_asc
            self.table_segments.horizontalHeader().sort_asc = self._sort_asc
            self._populate_table(self._sorted_entries())

    def _toggle_all_visible(self):
        visible = self.table_segments.selectable_rows()
        if not visible:
            return
        sel = self.table_segments.selectionModel()
        all_selected = all(sel.isRowSelected(r) for r in visible)
        flag = QItemSelectionModel.SelectionFlag.Deselect if all_selected else QItemSelectionModel.SelectionFlag.Select
        selection = QItemSelection()
        model = self.table_segments.model()
        for r in visible:
            selection.select(model.index(r, 0), model.index(r, 7))
        sel.select(selection, flag)

    def _toggle_offset(self, offset: int):
        """Timeline bar clicked: toggle that segment's row."""
        row = self._row_by_offset.get(offset)
        if row is None:
            return
        index = self.table_segments.model().index(row, 0)
        self.table_segments.selectionModel().select(
            index, QItemSelectionModel.SelectionFlag.Toggle | QItemSelectionModel.SelectionFlag.Rows)
        self.table_segments.scrollTo(index)

    def _selected_entries(self) -> list:
        rows = sorted(i.row() for i in self.table_segments.selectionModel().selectedRows())
        return [e for e in (self.table_segments.entry_at(r) for r in rows) if e is not None]

    def _on_selection_changed(self, *_):
        self._update_selection_ui()

    def _update_selection_ui(self):
        """Refresh everything derived from the selection: summary, export button, header, timeline."""
        if not hasattr(self, "btn_export_selected"):
            return  # still building the UI
        selected = self._selected_entries()
        n = len(selected)
        if n:
            seconds = sum((e.end_timestamp - e.start_timestamp).total_seconds()
                          for e in selected if e.start_timestamp and e.end_timestamp)
            size = n * self.table_segments.block_size
            self.selection_summary.setText(f"{n} selected · {fmt_duration(seconds)} · {fmt_size(size)}")
            self.btn_export_selected.setText(f"Export {n} segment{'s' if n != 1 else ''}")
        else:
            self.selection_summary.setText("Nothing selected")
            self.btn_export_selected.setText("Export")
        self.btn_export_selected.setEnabled(n > 0 and self._task is None)

        table = self.table_segments
        visible = table.selectable_rows()
        sel = table.selectionModel()
        n_vis_sel = sum(1 for r in visible if sel.isRowSelected(r))
        header = table.horizontalHeader()
        header.check_state = ("none" if n_vis_sel == 0
                              else "all" if n_vis_sel == len(visible) else "some")
        header.viewport().update()
        self.coverage.set_selected({e.offset_datablock for e in selected})

    def _populate_table(self, entries: list):
        """Fill the segment table with the given (pre-sorted) entries, keeping the selection."""
        table = self.table_segments
        keep = {e.offset_datablock for e in self._selected_entries()}
        block_size = self.current_parser.master_block.size_data_block

        table.blockSignals(True)
        table.selectionModel().blockSignals(True)
        table.clearSelection()
        table.setRowCount(len(entries))
        self._row_by_offset = {}
        selection = QItemSelection()
        model = table.model()
        for row, entry in enumerate(entries):
            self._row_by_offset[entry.offset_datablock] = row
            for col in range(8):
                item = QTableWidgetItem()
                flags = item.flags() & ~Qt.ItemFlag.ItemIsEditable
                if entry.recording:
                    # Blocks still being written when the DVR stopped can't be exported
                    flags &= ~Qt.ItemFlag.ItemIsSelectable
                    item.setToolTip("Still being written when the DVR stopped; can't be exported")
                item.setFlags(flags)
                table.setItem(row, col, item)
            table.item(row, 0).setData(ENTRY_ROLE, entry)
            table.setRowHidden(row, entry.channel in self._hidden_channels)
            if entry.offset_datablock in keep:
                selection.select(model.index(row, 0), model.index(row, 7))

            # Serve from cache or kick off thumbnail generation. In-progress blocks
            # are included: their start is usually written already; if not, the
            # worker simply yields no image and the placeholder stays.
            cache_key = (self.current_parser.source_path, entry.offset_datablock)
            if cache_key in self._thumb_cache:
                table.item(row, 1).setData(THUMB_ROLE, self._thumb_cache[cache_key])
            elif cache_key not in self._thumb_pending:  # re-sorting must not re-queue
                self._thumb_pending.add(cache_key)
                worker = ThumbnailWorker(self.current_parser.source_path, entry, block_size)
                worker.signals.ready.connect(self._on_thumbnail_ready)
                worker.signals.done.connect(self._on_thumbnail_done)
                self.thumb_pool.start(worker)
        table.selectionModel().select(selection, QItemSelectionModel.SelectionFlag.Select)
        table.selectionModel().blockSignals(False)
        table.blockSignals(False)
        table.viewport().update()
        self._update_selection_ui()

    def _on_thumbnail_ready(self, offset: int, image: QImage):
        """Slot: stores the thumbnail pixmap on the preview cell and populates the cache."""
        if not self.current_parser:
            return
        pixmap = QPixmap.fromImage(image)
        self._thumb_cache[(self.current_parser.source_path, offset)] = pixmap
        row = self._row_by_offset.get(offset)
        if row is not None:
            preview = self.table_segments.item(row, 1)
            if preview:
                preview.setData(THUMB_ROLE, pixmap)

    def _on_thumbnail_done(self, offset: int):
        """Slot: a thumbnail job finished (successfully or not)."""
        if self.current_parser:
            self._thumb_pending.discard((self.current_parser.source_path, offset))

    def start_export_selected(self):
        """Initiates the export process for selected segments."""
        if not self.current_parser or not self.current_parser.entry_list:
            QMessageBox.warning(self, "Warning", "Please select a source first.")
            return

        dest_folder = self.output_path_line.text()
        if not os.path.isdir(dest_folder):
            QMessageBox.critical(self, "Error", "Output folder is invalid or not selected.")
            return

        export_list = self._selected_entries()
        if not export_list:
            QMessageBox.warning(self, "Warning", "Please select at least one video segment to export.")
            return

        self._export_count = len(export_list)
        self._export_io_errors = 0
        self._set_busy("export")
        self._set_status(f"Starting export of {len(export_list)} segments…")

        # Start export worker
        worker = ParserWorker(self.current_parser, dest_folder, self.checkbox_raw.isChecked(), export_list)
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

    def export_progress(self, current_index: int, message: str):
        """Slot to update progress bar and status during export."""
        self.progress_bar.setValue(current_index)
        self._set_status(f"Exporting · {message}")

    def _on_export_skipped(self, count: int):
        self._export_io_errors = count

    # --- Worker Management Slots ---
    def worker_error(self, error_tuple: tuple):
        """Handles errors from the worker thread."""
        exc_type, exc_value, traceback_str = error_tuple
        self._failed = True
        QMessageBox.critical(
            self,
            "Worker Error",
            f"An error occurred in the background task:\n\n{exc_value}\n\nTraceback:\n{traceback_str}"
        )

    def worker_finished(self):
        """Slot called when any worker thread (parse or export) finishes."""
        task = self._task
        failed = getattr(self, "_failed", False)
        self._failed = False
        self._set_busy(None)
        self.progress_bar.setRange(0, 1)
        self.progress_bar.setValue(0 if failed else 1)

        if task == "parse" and failed:
            self._set_status("Parsing failed.")
        elif task == "export":
            if failed:
                self._set_status("Export failed.")
                return
            ext = "h264" if self.checkbox_raw.isChecked() else "mp4"
            done = self._export_count - self._export_io_errors
            text = f"Exported {done} segment{'s' if done != 1 else ''} as .{ext} to {self.output_path_line.text()}"
            if self._export_io_errors:
                text += f" · {self._export_io_errors} skipped due to I/O errors"
            self._set_status(text)


def load_fonts():
    """Register the bundled IBM Plex fonts; Qt falls back to system fonts without them."""
    if os.path.isdir(FONT_DIR):
        for name in sorted(os.listdir(FONT_DIR)):
            if name.endswith(".ttf"):
                QFontDatabase.addApplicationFont(os.path.join(FONT_DIR, name))


if __name__ == "__main__":
    # On GNOME, use GTK's native file dialogs. Other desktops (e.g. KDE) already
    # provide their own platform theme; an explicit QT_QPA_PLATFORMTHEME always wins.
    if "GNOME" in os.environ.get("XDG_CURRENT_DESKTOP", "").upper():
        os.environ.setdefault("QT_QPA_PLATFORMTHEME", "gtk3")
    app = QApplication(sys.argv)
    app.setApplicationDisplayName("HikExtractor")
    app.setDesktopFileName("hikextractor")
    app.setWindowIcon(QIcon.fromTheme("camera-video"))
    load_fonts()
    app.setStyle("Fusion")
    app.setPalette(light_palette())
    app.setFont(ui_font(13))
    app.setStyleSheet(STYLESHEET)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())
