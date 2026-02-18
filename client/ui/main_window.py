"""
Game Accelerator Client GUI
游戏加速器客户端图形界面
"""

import sys
import os
import asyncio
import logging
from typing import Optional, Dict, Any, List
from datetime import datetime

from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QPushButton, QLineEdit, QComboBox, QTabWidget,
    QGroupBox, QFormLayout, QCheckBox, QSpinBox, QTableWidget,
    QTableWidgetItem, QHeaderView, QProgressBar, QMessageBox,
    QSystemTrayIcon, QMenu, QAction, QFrame, QScrollArea,
    QListWidget, QListWidgetItem, QSplitter, QTextEdit, QDialog,
    QDialogButtonBox, QFileDialog
)
from PyQt5.QtCore import (
    Qt, QTimer, pyqtSignal, QThread, QSize, QPropertyAnimation,
    QEasingCurve, QRect
)
from PyQt5.QtGui import (
    QIcon, QFont, QColor, QPalette, QLinearGradient, QPainter,
    QBrush, QPen
)

logger = logging.getLogger(__name__)


class AsyncWorker(QThread):
    """异步工作线程"""

    finished = pyqtSignal(object)
    error = pyqtSignal(str)

    def __init__(self, coro, parent=None):
        super().__init__(parent)
        self._coro = coro

    def run(self):
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            result = loop.run_until_complete(self._coro)
            loop.close()
            self.finished.emit(result)
        except Exception as e:
            self.error.emit(str(e))


class StyleManager:
    """样式管理器"""

    DARK_THEME = """
    QMainWindow, QWidget {
        background-color: #1a1a2e;
        color: #eaeaea;
    }
    QPushButton {
        background-color: #16213e;
        color: #eaeaea;
        border: 1px solid #0f3460;
        border-radius: 5px;
        padding: 8px 16px;
        font-size: 13px;
    }
    QPushButton:hover {
        background-color: #0f3460;
        border: 1px solid #e94560;
    }
    QPushButton:pressed {
        background-color: #e94560;
    }
    QPushButton:disabled {
        background-color: #2a2a4a;
        color: #666;
    }
    QLineEdit, QComboBox, QSpinBox {
        background-color: #16213e;
        color: #eaeaea;
        border: 1px solid #0f3460;
        border-radius: 4px;
        padding: 6px;
        font-size: 13px;
    }
    QLineEdit:focus, QComboBox:focus, QSpinBox:focus {
        border: 1px solid #e94560;
    }
    QComboBox::drop-down {
        border: none;
        width: 20px;
    }
    QComboBox::down-arrow {
        image: none;
        border-left: 5px solid transparent;
        border-right: 5px solid transparent;
        border-top: 5px solid #eaeaea;
        margin-right: 5px;
    }
    QTabWidget::pane {
        border: 1px solid #0f3460;
        border-radius: 5px;
        background-color: #1a1a2e;
    }
    QTabBar::tab {
        background-color: #16213e;
        color: #eaeaea;
        padding: 10px 20px;
        margin-right: 2px;
        border-top-left-radius: 4px;
        border-top-right-radius: 4px;
    }
    QTabBar::tab:selected {
        background-color: #0f3460;
        border-bottom: 2px solid #e94560;
    }
    QTabBar::tab:hover:!selected {
        background-color: #0f3460;
    }
    QGroupBox {
        border: 1px solid #0f3460;
        border-radius: 5px;
        margin-top: 10px;
        padding-top: 10px;
        font-weight: bold;
    }
    QGroupBox::title {
        subcontrol-origin: margin;
        left: 10px;
        padding: 0 5px;
        color: #e94560;
    }
    QTableWidget {
        background-color: #16213e;
        color: #eaeaea;
        border: 1px solid #0f3460;
        border-radius: 5px;
        gridline-color: #0f3460;
    }
    QTableWidget::item {
        padding: 5px;
    }
    QTableWidget::item:selected {
        background-color: #0f3460;
    }
    QHeaderView::section {
        background-color: #0f3460;
        color: #eaeaea;
        padding: 8px;
        border: none;
        border-bottom: 1px solid #1a1a2e;
    }
    QProgressBar {
        background-color: #16213e;
        border: 1px solid #0f3460;
        border-radius: 4px;
        text-align: center;
        color: #eaeaea;
    }
    QProgressBar::chunk {
        background-color: #e94560;
        border-radius: 3px;
    }
    QScrollBar:vertical {
        background-color: #16213e;
        width: 12px;
        border-radius: 6px;
    }
    QScrollBar::handle:vertical {
        background-color: #0f3460;
        border-radius: 6px;
        min-height: 20px;
    }
    QScrollBar::handle:vertical:hover {
        background-color: #e94560;
    }
    QListWidget {
        background-color: #16213e;
        color: #eaeaea;
        border: 1px solid #0f3460;
        border-radius: 5px;
    }
    QListWidget::item {
        padding: 8px;
    }
    QListWidget::item:selected {
        background-color: #0f3460;
        border-radius: 3px;
    }
    QListWidget::item:hover:!selected {
        background-color: #1a1a2e;
    }
    QLabel {
        color: #eaeaea;
    }
    QCheckBox {
        color: #eaeaea;
    }
    QCheckBox::indicator {
        width: 18px;
        height: 18px;
        border-radius: 3px;
        border: 1px solid #0f3460;
        background-color: #16213e;
    }
    QCheckBox::indicator:checked {
        background-color: #e94560;
        border: 1px solid #e94560;
    }
    """

    @classmethod
    def apply_dark_theme(cls, app: QApplication):
        app.setStyleSheet(cls.DARK_THEME)


class StatusIndicator(QWidget):
    """状态指示器"""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._status = "disconnected"
        self.setFixedSize(16, 16)

    def set_status(self, status: str):
        self._status = status
        self.update()

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)

        if self._status == "connected":
            color = QColor("#00ff00")
        elif self._status == "connecting":
            color = QColor("#ffaa00")
        elif self._status == "error":
            color = QColor("#ff0000")
        else:
            color = QColor("#888888")

        painter.setBrush(QBrush(color))
        painter.setPen(Qt.NoPen)
        painter.drawEllipse(2, 2, 12, 12)


class ConnectionPanel(QWidget):
    """连接面板"""

    connect_clicked = pyqtSignal(str, str, str, int)
    disconnect_clicked = pyqtSignal()
    node_selected = pyqtSignal(str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self._init_ui()

    def _init_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(15)

        header = QLabel("游戏加速器")
        header.setFont(QFont("Microsoft YaHei", 24, QFont.Bold))
        header.setAlignment(Qt.AlignCenter)
        header.setStyleSheet("color: #e94560;")
        layout.addWidget(header)

        status_frame = QFrame()
        status_frame.setStyleSheet("""
            QFrame {
                background-color: #16213e;
                border-radius: 10px;
                padding: 10px;
            }
        """)
        status_layout = QHBoxLayout(status_frame)

        self._status_indicator = StatusIndicator()
        status_layout.addWidget(self._status_indicator)

        self._status_label = QLabel("未连接")
        self._status_label.setFont(QFont("Microsoft YaHei", 14))
        status_layout.addWidget(self._status_label)
        status_layout.addStretch()

        self._latency_label = QLabel("延迟: --")
        self._latency_label.setFont(QFont("Microsoft YaHei", 12))
        status_layout.addWidget(self._latency_label)

        layout.addWidget(status_frame)

        login_group = QGroupBox("账户登录")
        login_layout = QFormLayout(login_group)

        self._username_edit = QLineEdit()
        self._username_edit.setPlaceholderText("请输入用户名")
        login_layout.addRow("用户名:", self._username_edit)

        self._password_edit = QLineEdit()
        self._password_edit.setPlaceholderText("请输入密码")
        self._password_edit.setEchoMode(QLineEdit.Password)
        login_layout.addRow("密码:", self._password_edit)

        layout.addWidget(login_group)

        node_group = QGroupBox("选择节点")
        node_layout = QVBoxLayout(node_group)

        self._region_combo = QComboBox()
        self._region_combo.addItem("自动选择", "auto")
        self._region_combo.addItem("华东", "east_china")
        self._region_combo.addItem("华南", "south_china")
        self._region_combo.addItem("华北", "north_china")
        self._region_combo.addItem("海外", "overseas")
        node_layout.addWidget(QLabel("地区:"))
        node_layout.addWidget(self._region_combo)

        self._node_list = QListWidget()
        self._node_list.setMinimumHeight(150)
        self._node_list.itemClicked.connect(self._on_node_clicked)
        node_layout.addWidget(self._node_list)

        self._refresh_btn = QPushButton("刷新节点")
        self._refresh_btn.clicked.connect(self._refresh_nodes)
        node_layout.addWidget(self._refresh_btn)

        layout.addWidget(node_group)

        self._connect_btn = QPushButton("连接")
        self._connect_btn.setMinimumHeight(50)
        self._connect_btn.setFont(QFont("Microsoft YaHei", 14, QFont.Bold))
        self._connect_btn.clicked.connect(self._on_connect_clicked)
        layout.addWidget(self._connect_btn)

        layout.addStretch()

    def _on_connect_clicked(self):
        if self._connect_btn.text() == "连接":
            username = self._username_edit.text().strip()
            password = self._password_edit.text().strip()
            region = self._region_combo.currentData()

            if not username or not password:
                QMessageBox.warning(self, "提示", "请输入用户名和密码")
                return

            self.connect_clicked.emit(username, password, region, 0)
        else:
            self.disconnect_clicked.emit()

    def _on_node_clicked(self, item: QListWidgetItem):
        node_id = item.data(Qt.UserRole)
        self.node_selected.emit(node_id)

    def _refresh_nodes(self):
        pass

    def set_status(self, status: str, message: str = ""):
        self._status_indicator.set_status(status)
        if message:
            self._status_label.setText(message)

        if status == "connected":
            self._connect_btn.setText("断开连接")
            self._connect_btn.setStyleSheet("background-color: #e94560;")
        else:
            self._connect_btn.setText("连接")
            self._connect_btn.setStyleSheet("")

    def set_latency(self, latency_ms: float):
        self._latency_label.setText(f"延迟: {latency_ms:.1f}ms")

    def update_nodes(self, nodes: List[Dict[str, Any]]):
        self._node_list.clear()
        for node in nodes:
            item = QListWidgetItem(
                f"{node.get('name', 'Unknown')} - {node.get('latency', 0)}ms"
            )
            item.setData(Qt.UserRole, node.get('node_id'))
            self._node_list.addItem(item)

    def set_connecting(self):
        self.set_status("connecting", "连接中...")
        self._connect_btn.setEnabled(False)

    def set_connected(self):
        self.set_status("connected", "已连接")
        self._connect_btn.setEnabled(True)

    def set_disconnected(self):
        self.set_status("disconnected", "未连接")
        self._connect_btn.setEnabled(True)

    def set_error(self, message: str):
        self.set_status("error", f"错误: {message}")
        self._connect_btn.setEnabled(True)


class StatsPanel(QWidget):
    """统计面板"""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._init_ui()

    def _init_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(15)

        header = QLabel("连接统计")
        header.setFont(QFont("Microsoft YaHei", 16, QFont.Bold))
        layout.addWidget(header)

        stats_group = QGroupBox("实时数据")
        stats_layout = QFormLayout(stats_group)

        self._bytes_in_label = QLabel("0 B")
        stats_layout.addRow("接收流量:", self._bytes_in_label)

        self._bytes_out_label = QLabel("0 B")
        stats_layout.addRow("发送流量:", self._bytes_out_label)

        self._packets_label = QLabel("0")
        stats_layout.addRow("数据包:", self._packets_label)

        self._latency_label = QLabel("0 ms")
        stats_layout.addRow("平均延迟:", self._latency_label)

        self._uptime_label = QLabel("00:00:00")
        stats_layout.addRow("连接时长:", self._uptime_label)

        layout.addWidget(stats_group)

        games_group = QGroupBox("检测到的游戏")
        games_layout = QVBoxLayout(games_group)

        self._games_table = QTableWidget()
        self._games_table.setColumnCount(4)
        self._games_table.setHorizontalHeaderLabels(["游戏", "PID", "CPU", "内存"])
        self._games_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self._games_table.setSelectionBehavior(QTableWidget.SelectRows)
        games_layout.addWidget(self._games_table)

        layout.addWidget(games_group)

        layout.addStretch()

    def update_stats(self, stats: Dict[str, Any]):
        def format_bytes(b: int) -> str:
            for unit in ['B', 'KB', 'MB', 'GB']:
                if b < 1024:
                    return f"{b:.1f} {unit}"
                b /= 1024
            return f"{b:.1f} TB"

        # 网络客户端流量
        network_bytes_in = stats.get('bytes_received', 0)
        network_bytes_out = stats.get('bytes_sent', 0)
        
        # SOCKS5 代理流量
        socks5_bytes_in = stats.get('socks5_bytes_in', 0)
        socks5_bytes_out = stats.get('socks5_bytes_out', 0)
        
        # 端口转发流量
        forward_bytes_in = stats.get('forward_bytes_in', 0)
        forward_bytes_out = stats.get('forward_bytes_out', 0)
        
        # 总流量
        total_bytes_in = network_bytes_in + socks5_bytes_in + forward_bytes_in
        total_bytes_out = network_bytes_out + socks5_bytes_out + forward_bytes_out
        
        self._bytes_in_label.setText(format_bytes(total_bytes_in))
        self._bytes_out_label.setText(format_bytes(total_bytes_out))
        self._packets_label.setText(str(stats.get('packets_sent', 0)))

        latency = stats.get('latency_ms', 0)
        self._latency_label.setText(f"{latency:.1f} ms")

        connect_time = stats.get('connect_time', 0)
        if connect_time:
            import time
            uptime = int(time.time() - connect_time)
            hours = uptime // 3600
            minutes = (uptime % 3600) // 60
            seconds = uptime % 60
            self._uptime_label.setText(f"{hours:02d}:{minutes:02d}:{seconds:02d}")

    def update_games(self, games: List[Dict[str, Any]]):
        self._games_table.setRowCount(len(games))
        for i, game in enumerate(games):
            self._games_table.setItem(i, 0, QTableWidgetItem(game.get('game_name', '')))
            self._games_table.setItem(i, 1, QTableWidgetItem(str(game.get('pid', 0))))
            self._games_table.setItem(i, 2, QTableWidgetItem(f"{game.get('cpu_percent', 0):.1f}%"))
            self._games_table.setItem(i, 3, QTableWidgetItem(f"{game.get('memory_percent', 0):.1f}%"))


class SettingsPanel(QWidget):
    """设置面板"""

    settings_changed = pyqtSignal(dict)

    def __init__(self, parent=None):
        super().__init__(parent)
        self._init_ui()

    def _init_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(15)

        header = QLabel("设置")
        header.setFont(QFont("Microsoft YaHei", 16, QFont.Bold))
        layout.addWidget(header)

        connection_group = QGroupBox("连接设置")
        connection_layout = QFormLayout(connection_group)

        self._server_edit = QLineEdit("127.0.0.1")
        connection_layout.addRow("服务器地址:", self._server_edit)

        self._port_spin = QSpinBox()
        self._port_spin.setRange(1, 65535)
        self._port_spin.setValue(8388)
        connection_layout.addRow("服务器端口:", self._port_spin)

        self._auto_reconnect = QCheckBox("自动重连")
        self._auto_reconnect.setChecked(True)
        connection_layout.addRow(self._auto_reconnect)

        self._auto_start = QCheckBox("开机自启动")
        connection_layout.addRow(self._auto_start)

        self._minimize_to_tray = QCheckBox("最小化到系统托盘")
        self._minimize_to_tray.setChecked(True)
        connection_layout.addRow(self._minimize_to_tray)

        layout.addWidget(connection_group)

        proxy_group = QGroupBox("代理设置")
        proxy_layout = QFormLayout(proxy_group)

        self._socks5_port = QSpinBox()
        self._socks5_port.setRange(1, 65535)
        self._socks5_port.setValue(1080)
        proxy_layout.addRow("SOCKS5端口:", self._socks5_port)

        self._udp_port = QSpinBox()
        self._udp_port.setRange(1, 65535)
        self._udp_port.setValue(1081)
        proxy_layout.addRow("UDP代理端口:", self._udp_port)

        layout.addWidget(proxy_group)

        game_group = QGroupBox("游戏检测")
        game_layout = QVBoxLayout(game_group)

        self._auto_detect = QCheckBox("自动检测游戏进程")
        self._auto_detect.setChecked(True)
        game_layout.addWidget(self._auto_detect)

        self._accelerate_all = QCheckBox("加速所有游戏流量")
        game_layout.addWidget(self._accelerate_all)

        layout.addWidget(game_group)

        save_btn = QPushButton("保存设置")
        save_btn.clicked.connect(self._save_settings)
        layout.addWidget(save_btn)

        layout.addStretch()

    def _save_settings(self):
        settings = {
            "server": {
                "host": self._server_edit.text(),
                "port": self._port_spin.value(),
            },
            "connection": {
                "auto_reconnect": self._auto_reconnect.isChecked(),
                "auto_start": self._auto_start.isChecked(),
                "minimize_to_tray": self._minimize_to_tray.isChecked(),
            },
            "proxy": {
                "socks5_port": self._socks5_port.value(),
                "udp_port": self._udp_port.value(),
            },
            "game": {
                "auto_detect": self._auto_detect.isChecked(),
                "accelerate_all": self._accelerate_all.isChecked(),
            },
        }
        self.settings_changed.emit(settings)

    def load_settings(self, settings: Dict[str, Any]):
        server = settings.get("server", {})
        self._server_edit.setText(server.get("host", "127.0.0.1"))
        self._port_spin.setValue(server.get("port", 8388))

        connection = settings.get("connection", {})
        self._auto_reconnect.setChecked(connection.get("auto_reconnect", True))
        self._auto_start.setChecked(connection.get("auto_start", False))
        self._minimize_to_tray.setChecked(connection.get("minimize_to_tray", True))

        proxy = settings.get("proxy", {})
        self._socks5_port.setValue(proxy.get("socks5_port", 1080))
        self._udp_port.setValue(proxy.get("udp_port", 1081))

        game = settings.get("game", {})
        self._auto_detect.setChecked(game.get("auto_detect", True))
        self._accelerate_all.setChecked(game.get("accelerate_all", False))


class MainWindow(QMainWindow):
    """主窗口"""

    def __init__(self):
        super().__init__()
        self._init_ui()
        self._setup_tray()

    def _init_ui(self):
        self.setWindowTitle("游戏加速器")
        self.setMinimumSize(800, 600)
        self.resize(900, 700)

        central_widget = QWidget()
        self.setCentralWidget(central_widget)

        layout = QHBoxLayout(central_widget)
        layout.setContentsMargins(0, 0, 0, 0)

        sidebar = self._create_sidebar()
        layout.addWidget(sidebar)

        self._content_stack = QTabWidget()
        self._content_stack.tabBar().hide()

        self._connection_panel = ConnectionPanel()
        self._stats_panel = StatsPanel()
        self._settings_panel = SettingsPanel()

        self._content_stack.addTab(self._connection_panel, "连接")
        self._content_stack.addTab(self._stats_panel, "统计")
        self._content_stack.addTab(self._settings_panel, "设置")

        layout.addWidget(self._content_stack, 1)

        self._timer = QTimer(self)
        self._timer.timeout.connect(self._update_ui)
        self._timer.start(1000)

    def _create_sidebar(self) -> QWidget:
        sidebar = QFrame()
        sidebar.setFixedWidth(200)
        sidebar.setStyleSheet("""
            QFrame {
                background-color: #0f3460;
                border: none;
            }
            QPushButton {
                background-color: transparent;
                color: #eaeaea;
                border: none;
                text-align: left;
                padding: 15px 20px;
                font-size: 14px;
            }
            QPushButton:hover {
                background-color: #16213e;
            }
            QPushButton:checked {
                background-color: #e94560;
            }
        """)

        layout = QVBoxLayout(sidebar)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        logo = QLabel("NAC")
        logo.setAlignment(Qt.AlignCenter)
        logo.setFont(QFont("Microsoft YaHei", 20, QFont.Bold))
        logo.setStyleSheet("color: #e94560; padding: 20px;")
        layout.addWidget(logo)

        self._nav_buttons = []

        nav_items = [
            ("连接", 0),
            ("统计", 1),
            ("设置", 2),
        ]

        for text, index in nav_items:
            btn = QPushButton(text)
            btn.setCheckable(True)
            btn.clicked.connect(lambda checked, i=index: self._switch_page(i))
            layout.addWidget(btn)
            self._nav_buttons.append(btn)

        self._nav_buttons[0].setChecked(True)

        layout.addStretch()

        version = QLabel("v1.0.0")
        version.setAlignment(Qt.AlignCenter)
        version.setStyleSheet("color: #666; padding: 10px;")
        layout.addWidget(version)

        return sidebar

    def _switch_page(self, index: int):
        for i, btn in enumerate(self._nav_buttons):
            btn.setChecked(i == index)
        self._content_stack.setCurrentIndex(index)

    def _setup_tray(self):
        self._tray_icon = QSystemTrayIcon(self)
        self._tray_icon.setToolTip("游戏加速器")

        tray_menu = QMenu()

        show_action = QAction("显示主窗口", self)
        show_action.triggered.connect(self.show)
        tray_menu.addAction(show_action)

        quit_action = QAction("退出", self)
        quit_action.triggered.connect(self.close)
        tray_menu.addAction(quit_action)

        self._tray_icon.setContextMenu(tray_menu)
        self._tray_icon.activated.connect(self._on_tray_activated)
        self._tray_icon.show()

    def _on_tray_activated(self, reason):
        if reason == QSystemTrayIcon.DoubleClick:
            if self.isVisible():
                self.hide()
            else:
                self.show()
                self.activateWindow()

    def _update_ui(self):
        pass

    @property
    def connection_panel(self) -> ConnectionPanel:
        return self._connection_panel

    @property
    def stats_panel(self) -> StatsPanel:
        return self._stats_panel

    @property
    def settings_panel(self) -> SettingsPanel:
        return self._settings_panel

    def closeEvent(self, event):
        if self._tray_icon.isVisible():
            self.hide()
            event.ignore()
        else:
            event.accept()


def run_gui():
    """运行GUI"""
    app = QApplication(sys.argv)
    app.setApplicationName("Game Accelerator")
    app.setApplicationVersion("1.0.0")

    StyleManager.apply_dark_theme(app)

    window = MainWindow()
    window.show()

    sys.exit(app.exec_())


if __name__ == "__main__":
    run_gui()
