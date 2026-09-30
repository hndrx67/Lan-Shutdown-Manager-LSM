"""
LAN Shutdown Manager
=====================
A PyQt5 desktop app to scan the local network for Windows computers and
send remote shutdown / restart / abort commands to selected machines.

Requirements:
    pip install PyQt5

Run:
    python lan_shutdown_manager.py

Notes:
    - This tool relies on Windows' built-in `shutdown.exe /m \\HOST`.
    - Target machines need: RPC/SMB reachable (port 445), the caller's
      account must be an admin on the target, and on non-domain PCs
      HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System
      \\LocalAccountTokenFilterPolicy should be set to 1 (DWORD).
    - Designed to run on Windows (uses the Windows `shutdown` command).
"""

import ipaddress
import socket
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed

from PyQt5.QtCore import Qt, QThread, pyqtSignal
from PyQt5.QtGui import QDesktopServices
from PyQt5.QtWidgets import (
    QApplication,
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QHeaderView,
    QSpinBox,
    QComboBox,
    QCheckBox,
    QTextEdit,
    QGroupBox,
    QMessageBox,
    QAbstractItemView,
    QProgressBar,
)

APP_NAME = "LAN Shutdown Manager"
APP_VERSION = "1.0"


# --------------------------------------------------------------------------
# Networking helpers
# --------------------------------------------------------------------------

def get_local_subnet_prefix():
    """Best-effort guess of the local /24 prefix, e.g. '192.168.1'."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        parts = local_ip.split(".")
        return ".".join(parts[:3])
    except Exception:
        return "192.168.1"


def ping_host(ip: str, timeout_ms: int = 800) -> bool:
    """Ping a single host using the OS ping command. Windows-flavored args,
    falls back to POSIX args if not on Windows."""
    if sys.platform.startswith("win"):
        cmd = ["ping", "-n", "1", "-w", str(timeout_ms), ip]
    else:
        cmd = ["ping", "-c", "1", "-W", str(max(1, timeout_ms // 1000)), ip]
    try:
        result = subprocess.run(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=(timeout_ms / 1000) + 1,
        )
        return result.returncode == 0
    except Exception:
        return False


def port_open(ip: str, port: int = 445, timeout: float = 0.6) -> bool:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            return sock.connect_ex((ip, port)) == 0
    except Exception:
        return False


def resolve_hostname(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ""


# --------------------------------------------------------------------------
# Background scan worker
# --------------------------------------------------------------------------

class ScanWorker(QThread):
    host_found = pyqtSignal(str, str, bool)   # ip, hostname, shutdown_port_open
    progress = pyqtSignal(int, int)           # done, total
    finished_scan = pyqtSignal()

    def __init__(self, subnet_prefix: str, start: int = 1, end: int = 254, parent=None):
        super().__init__(parent)
        self.subnet_prefix = subnet_prefix
        self.range_start = start
        self.range_end = end
        self._stop_requested = False

    def stop(self):
        self._stop_requested = True

    def _check(self, ip: str):
        if self._stop_requested:
            return None
        if ping_host(ip):
            hostname = resolve_hostname(ip)
            shutdown_ready = port_open(ip, 445)
            return (ip, hostname, shutdown_ready)
        return None

    def run(self):
        ips = [f"{self.subnet_prefix}.{i}" for i in range(self.range_start, self.range_end + 1)]
        total = len(ips)
        done = 0
        with ThreadPoolExecutor(max_workers=60) as executor:
            futures = {executor.submit(self._check, ip): ip for ip in ips}
            for future in as_completed(futures):
                if self._stop_requested:
                    break
                done += 1
                self.progress.emit(done, total)
                result = future.result()
                if result:
                    ip, hostname, shutdown_ready = result
                    self.host_found.emit(ip, hostname, shutdown_ready)
        self.finished_scan.emit()


# --------------------------------------------------------------------------
# Background shutdown-command worker
# --------------------------------------------------------------------------

class CommandWorker(QThread):
    log = pyqtSignal(str)
    finished_all = pyqtSignal()

    def __init__(self, targets, action: str, delay: int, message: str,
                 force: bool, username: str, password: str, parent=None):
        super().__init__(parent)
        self.targets = targets  # list of (ip_or_name, display_label)
        self.action = action    # "shutdown" | "restart" | "abort"
        self.delay = delay
        self.message = message
        self.force = force
        self.username = username
        self.password = password

    def _authenticate(self, target: str) -> bool:
        if not self.username:
            return True
        cmd = ["net", "use", f"\\\\{target}\\IPC$"]
        if self.password:
            cmd.append(self.password)
        cmd += ["/user:" + self.username]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            return result.returncode == 0
        except Exception:
            return False

    def run(self):
        for target, label in self.targets:
            if self.username:
                ok = self._authenticate(target)
                if not ok:
                    self.log.emit(f"[{label}] Authentication failed, trying anyway...")

            if self.action == "abort":
                cmd = ["shutdown", "/a", "/m", f"\\\\{target}"]
            else:
                flag = "/r" if self.action == "restart" else "/s"
                cmd = ["shutdown", flag, "/m", f"\\\\{target}", "/t", str(self.delay)]
                if self.force:
                    cmd.append("/f")
                if self.message:
                    cmd += ["/c", self.message]

            try:
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
                if result.returncode == 0:
                    self.log.emit(f"[{label}] OK: {self.action} command sent.")
                else:
                    err = (result.stderr or result.stdout or "unknown error").strip()
                    self.log.emit(f"[{label}] FAILED (code {result.returncode}): {err}")
            except FileNotFoundError:
                self.log.emit("shutdown.exe not found. This tool must run on Windows.")
                break
            except Exception as e:
                self.log.emit(f"[{label}] ERROR: {e}")

        self.finished_all.emit()


# --------------------------------------------------------------------------
# Main window
# --------------------------------------------------------------------------

class LanShutdownManager(QWidget):
    def __init__(self):
        super().__init__()
        self.scan_worker = None
        self.cmd_worker = None
        self._build_ui()
        self._center_on_screen()

    # ---- UI construction ----
    def _build_ui(self):
        self.setWindowTitle(f"{APP_NAME} v{APP_VERSION}")
        self.resize(820, 600)

        root = QVBoxLayout(self)

        # --- Scan controls ---
        scan_box = QGroupBox("Network Scan")
        scan_layout = QHBoxLayout()

        scan_layout.addWidget(QLabel("Subnet prefix:"))
        self.subnet_input = QLineEdit(get_local_subnet_prefix())
        self.subnet_input.setPlaceholderText("e.g. 192.168.1")
        self.subnet_input.setFixedWidth(140)
        scan_layout.addWidget(self.subnet_input)

        scan_layout.addWidget(QLabel("Range:"))
        self.range_start = QSpinBox()
        self.range_start.setRange(1, 254)
        self.range_start.setValue(1)
        self.range_end = QSpinBox()
        self.range_end.setRange(1, 254)
        self.range_end.setValue(254)
        scan_layout.addWidget(self.range_start)
        scan_layout.addWidget(QLabel("to"))
        scan_layout.addWidget(self.range_end)

        self.scan_btn = QPushButton("Scan Network")
        self.scan_btn.clicked.connect(self.start_scan)
        scan_layout.addWidget(self.scan_btn)

        self.stop_scan_btn = QPushButton("Stop")
        self.stop_scan_btn.clicked.connect(self.stop_scan)
        self.stop_scan_btn.setEnabled(False)
        scan_layout.addWidget(self.stop_scan_btn)

        scan_layout.addStretch()
        scan_box.setLayout(scan_layout)
        root.addWidget(scan_box)

        self.progress_bar = QProgressBar()
        self.progress_bar.setValue(0)
        root.addWidget(self.progress_bar)

        # --- Results table ---
        self.table = QTableWidget(0, 4)
        self.table.setHorizontalHeaderLabels(["Select", "IP Address", "Hostname", "Shutdown Ready (445)"])
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        root.addWidget(self.table)

        sel_layout = QHBoxLayout()
        select_all_btn = QPushButton("Select All")
        select_all_btn.clicked.connect(lambda: self._set_all_checks(True))
        select_none_btn = QPushButton("Select None")
        select_none_btn.clicked.connect(lambda: self._set_all_checks(False))
        add_manual_btn = QPushButton("Add Manual Target...")
        add_manual_btn.clicked.connect(self.add_manual_target)
        sel_layout.addWidget(select_all_btn)
        sel_layout.addWidget(select_none_btn)
        sel_layout.addWidget(add_manual_btn)
        sel_layout.addStretch()
        root.addLayout(sel_layout)

        # --- Command controls ---
        cmd_box = QGroupBox("Remote Command")
        cmd_layout = QVBoxLayout()

        row1 = QHBoxLayout()
        row1.addWidget(QLabel("Action:"))
        self.action_combo = QComboBox()
        self.action_combo.addItems(["Shutdown", "Restart", "Abort (cancel pending)"])
        row1.addWidget(self.action_combo)

        row1.addWidget(QLabel("Delay (sec):"))
        self.delay_spin = QSpinBox()
        self.delay_spin.setRange(0, 86400)
        self.delay_spin.setValue(60)
        row1.addWidget(self.delay_spin)

        self.force_check = QCheckBox("Force close apps (/f)")
        row1.addWidget(self.force_check)
        row1.addStretch()
        cmd_layout.addLayout(row1)

        row2 = QHBoxLayout()
        row2.addWidget(QLabel("Message:"))
        self.message_input = QLineEdit("Scheduled shutdown by admin.")
        row2.addWidget(self.message_input)
        cmd_layout.addLayout(row2)

        row3 = QHBoxLayout()
        row3.addWidget(QLabel("Username (optional, DOMAIN\\user):"))
        self.username_input = QLineEdit()
        row3.addWidget(self.username_input)
        row3.addWidget(QLabel("Password:"))
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)
        row3.addWidget(self.password_input)
        cmd_layout.addLayout(row3)

        row4 = QHBoxLayout()
        self.send_btn = QPushButton("Send Command to Selected")
        self.send_btn.clicked.connect(self.send_command)
        self.send_btn.setStyleSheet("font-weight: bold;")
        row4.addWidget(self.send_btn)
        row4.addStretch()
        cmd_layout.addLayout(row4)

        cmd_box.setLayout(cmd_layout)
        root.addWidget(cmd_box)

        # --- Log ---
        root.addWidget(QLabel("Log:"))
        self.log_box = QTextEdit()
        self.log_box.setReadOnly(True)
        self.log_box.setFixedHeight(140)
        root.addWidget(self.log_box)

    def _center_on_screen(self):
        screen_geometry = QApplication.desktop().availableGeometry()
        x = (screen_geometry.width() - self.width()) // 2 + screen_geometry.x()
        y = (screen_geometry.height() - self.height()) // 2 + screen_geometry.y()
        self.move(x, y)

    # ---- Scan handling ----
    def start_scan(self):
        prefix = self.subnet_input.text().strip()
        try:
            ipaddress.ip_address(prefix + ".1")
        except ValueError:
            QMessageBox.warning(self, "Invalid subnet", "Enter a valid subnet prefix, e.g. 192.168.1")
            return

        self.table.setRowCount(0)
        self.progress_bar.setValue(0)
        self.scan_btn.setEnabled(False)
        self.stop_scan_btn.setEnabled(True)
        self._log(f"Scanning {prefix}.{self.range_start.value()}-{self.range_end.value()} ...")

        self.scan_worker = ScanWorker(prefix, self.range_start.value(), self.range_end.value())
        self.scan_worker.host_found.connect(self._add_host_row)
        self.scan_worker.progress.connect(self._update_progress)
        self.scan_worker.finished_scan.connect(self._scan_finished)
        self.scan_worker.start()

    def stop_scan(self):
        if self.scan_worker:
            self.scan_worker.stop()
            self._log("Stopping scan...")

    def _update_progress(self, done, total):
        pct = int((done / total) * 100) if total else 0
        self.progress_bar.setValue(pct)

    def _scan_finished(self):
        self.scan_btn.setEnabled(True)
        self.stop_scan_btn.setEnabled(False)
        self._log(f"Scan complete. {self.table.rowCount()} host(s) found.")

    def _add_host_row(self, ip, hostname, shutdown_ready):
        row = self.table.rowCount()
        self.table.insertRow(row)

        check = QCheckBox()
        cell_widget = QWidget()
        layout = QHBoxLayout(cell_widget)
        layout.addWidget(check)
        layout.setAlignment(Qt.AlignCenter)
        layout.setContentsMargins(0, 0, 0, 0)
        self.table.setCellWidget(row, 0, cell_widget)

        self.table.setItem(row, 1, QTableWidgetItem(ip))
        self.table.setItem(row, 2, QTableWidgetItem(hostname or "(unknown)"))
        ready_item = QTableWidgetItem("Yes" if shutdown_ready else "No")
        self.table.setItem(row, 3, ready_item)

    def _set_all_checks(self, checked: bool):
        for row in range(self.table.rowCount()):
            cell_widget = self.table.cellWidget(row, 0)
            if cell_widget:
                checkbox = cell_widget.findChild(QCheckBox)
                if checkbox:
                    checkbox.setChecked(checked)

    def add_manual_target(self):
        from PyQt5.QtWidgets import QInputDialog
        text, ok = QInputDialog.getText(self, "Add Manual Target", "Enter IP address or hostname:")
        if ok and text.strip():
            self._add_host_row(text.strip(), "(manual entry)", True)

    # ---- Command handling ----
    def _selected_targets(self):
        targets = []
        for row in range(self.table.rowCount()):
            cell_widget = self.table.cellWidget(row, 0)
            checkbox = cell_widget.findChild(QCheckBox) if cell_widget else None
            if checkbox and checkbox.isChecked():
                ip_item = self.table.item(row, 1)
                host_item = self.table.item(row, 2)
                ip = ip_item.text() if ip_item else ""
                label = host_item.text() if host_item and host_item.text() != "(unknown)" else ip
                if ip:
                    targets.append((ip, label))
        return targets

    def send_command(self):
        targets = self._selected_targets()
        if not targets:
            QMessageBox.information(self, "No targets", "Select at least one computer first.")
            return

        action_map = {
            "Shutdown": "shutdown",
            "Restart": "restart",
            "Abort (cancel pending)": "abort",
        }
        action = action_map[self.action_combo.currentText()]

        if action != "abort":
            names = ", ".join(label for _, label in targets)
            confirm = QMessageBox.question(
                self,
                "Confirm",
                f"Send {action.upper()} command to {len(targets)} computer(s)?\n\n{names}",
                QMessageBox.Yes | QMessageBox.No,
            )
            if confirm != QMessageBox.Yes:
                return

        self.send_btn.setEnabled(False)
        self._log(f"Sending '{action}' to {len(targets)} target(s)...")

        self.cmd_worker = CommandWorker(
            targets=targets,
            action=action,
            delay=self.delay_spin.value(),
            message=self.message_input.text(),
            force=self.force_check.isChecked(),
            username=self.username_input.text().strip(),
            password=self.password_input.text(),
        )
        self.cmd_worker.log.connect(self._log)
        self.cmd_worker.finished_all.connect(lambda: self.send_btn.setEnabled(True))
        self.cmd_worker.start()

    def _log(self, text: str):
        self.log_box.append(text)


def main():
    app = QApplication(sys.argv)
    app.setApplicationName(APP_NAME)
    window = LanShutdownManager()
    window.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()