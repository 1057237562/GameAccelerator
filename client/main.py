"""
Game Accelerator Client Main Module
游戏加速器客户端主程序
"""

import asyncio
import sys
import os
import json
import logging
import uuid
import time
from typing import Optional, Dict, Any, List
from dataclasses import dataclass, asdict
from pathlib import Path

from PyQt5.QtWidgets import QApplication, QMessageBox
from PyQt5.QtCore import QTimer, QThread, pyqtSignal, QObject

from client.core.network import NetworkClient, ConnectionConfig, ConnectionState
from client.core.process_monitor import ProcessMonitor, TrafficDirector, GameProcess
from client.core.traffic import TrafficInterceptor
from client.ui.main_window import MainWindow, StyleManager


logger = logging.getLogger(__name__)


@dataclass
class ClientConfig:
    """客户端配置"""
    server_host: str = "127.0.0.1"
    server_port: int = 8388
    username: str = ""
    password: str = ""
    auto_reconnect: bool = True
    auto_start: bool = False
    minimize_to_tray: bool = True
    socks5_port: int = 1080
    udp_port: int = 1081
    auto_detect_games: bool = True
    accelerate_all: bool = False
    device_id: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ClientConfig":
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})


class ConfigManager:
    """配置管理器"""

    def __init__(self, config_dir: str = None):
        if config_dir is None:
            config_dir = os.path.join(os.path.expanduser("~"), ".game_accelerator")
        self._config_dir = Path(config_dir)
        self._config_file = self._config_dir / "config.json"
        self._config = ClientConfig()

    @property
    def config(self) -> ClientConfig:
        return self._config

    def load(self) -> ClientConfig:
        """加载配置"""
        try:
            if self._config_file.exists():
                with open(self._config_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    self._config = ClientConfig.from_dict(data)
        except Exception as e:
            logger.error(f"Failed to load config: {e}")

        if not self._config.device_id:
            self._config.device_id = str(uuid.uuid4())

        return self._config

    def save(self, config: ClientConfig = None):
        """保存配置"""
        if config:
            self._config = config

        try:
            self._config_dir.mkdir(parents=True, exist_ok=True)
            with open(self._config_file, 'w', encoding='utf-8') as f:
                json.dump(self._config.to_dict(), f, indent=2, ensure_ascii=False)
        except Exception as e:
            logger.error(f"Failed to save config: {e}")


class SignalBus(QObject):
    """信号总线"""

    connection_changed = pyqtSignal(str)
    stats_updated = pyqtSignal(dict)
    games_updated = pyqtSignal(list)
    nodes_updated = pyqtSignal(list)
    error_occurred = pyqtSignal(str)


class AsyncBridge(QThread):
    """异步桥接器"""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._running = False

    def run(self):
        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)
        self._running = True

        self._loop.run_forever()

    def stop(self):
        if self._loop:
            self._loop.call_soon_threadsafe(self._loop.stop)
        self._running = False
        self.wait()

    def run_coro(self, coro):
        if self._loop and self._running:
            future = asyncio.run_coroutine_threadsafe(coro, self._loop)
            return future


class GameAcceleratorClient:
    """游戏加速器客户端"""

    def __init__(self):
        self._config_manager = ConfigManager()
        self._config = self._config_manager.load()

        self._network_client: Optional[NetworkClient] = None
        self._traffic_director: Optional[TrafficDirector] = None
        self._traffic_interceptor: Optional[TrafficInterceptor] = None

        self._signal_bus = SignalBus()
        self._async_bridge = AsyncBridge()
        self._main_window: Optional[MainWindow] = None

        self._update_timer: Optional[QTimer] = None
        self._connected = False
        self._start_time = 0

    @property
    def signals(self) -> SignalBus:
        return self._signal_bus

    @property
    def is_connected(self) -> bool:
        return self._connected

    def initialize(self, app: QApplication):
        """初始化客户端"""
        self._setup_logging()

        self._async_bridge.start()

        self._main_window = MainWindow()
        self._setup_connections()

        self._update_timer = QTimer()
        self._update_timer.timeout.connect(self._update_status)
        self._update_timer.start(1000)

        self._load_settings()

        logger.info("Client initialized")

    def _setup_logging(self):
        """设置日志"""
        log_dir = os.path.join(os.path.expanduser("~"), ".game_accelerator", "logs")
        os.makedirs(log_dir, exist_ok=True)

        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
            handlers=[
                logging.StreamHandler(),
                logging.FileHandler(
                    os.path.join(log_dir, "client.log"),
                    encoding="utf-8"
                )
            ]
        )

    def _setup_connections(self):
        """设置信号连接"""
        self._main_window.connection_panel.connect_clicked.connect(self._on_connect)
        self._main_window.connection_panel.disconnect_clicked.connect(self._on_disconnect)
        self._main_window.settings_panel.settings_changed.connect(self._on_settings_changed)

        self._signal_bus.connection_changed.connect(self._on_connection_changed)
        self._signal_bus.stats_updated.connect(self._on_stats_updated)
        self._signal_bus.games_updated.connect(self._on_games_updated)
        self._signal_bus.error_occurred.connect(self._on_error)

    def _load_settings(self):
        """加载设置到界面"""
        settings = {
            "server": {
                "host": self._config.server_host,
                "port": self._config.server_port,
            },
            "connection": {
                "auto_reconnect": self._config.auto_reconnect,
                "auto_start": self._config.auto_start,
                "minimize_to_tray": self._config.minimize_to_tray,
            },
            "proxy": {
                "socks5_port": self._config.socks5_port,
                "udp_port": self._config.udp_port,
            },
            "game": {
                "auto_detect": self._config.auto_detect_games,
                "accelerate_all": self._config.accelerate_all,
            },
        }
        self._main_window.settings_panel.load_settings(settings)
        
        # 加载用户名和密码到登录表单
        self._main_window.connection_panel._username_edit.setText(self._config.username)
        self._main_window.connection_panel._password_edit.setText(self._config.password)

    def _on_connect(self, username: str, password: str, region: str, node_id: int):
        """连接按钮点击"""
        self._config.username = username
        self._config.password = password
        
        # 保存用户名和密码到配置文件
        self._config_manager.save(self._config)

        self._main_window.connection_panel.set_connecting()

        self._async_bridge.run_coro(self._connect())

    async def _connect(self):
        """执行连接"""
        try:
            connection_config = ConnectionConfig(
                server_host=self._config.server_host,
                server_port=self._config.server_port,
                username=self._config.username,
                password=self._config.password,
                device_id=self._config.device_id,
                auto_reconnect=self._config.auto_reconnect,
            )

            self._network_client = NetworkClient(connection_config)
            self._network_client.add_state_callback(self._on_network_state_changed)

            success = await self._network_client.connect()

            if success:
                self._connected = True
                self._start_time = time.time()

                await self._start_traffic_interceptor()

                if self._config.auto_detect_games:
                    await self._start_traffic_director()

                self._signal_bus.connection_changed.emit("connected")
            else:
                self._signal_bus.error_occurred.emit("连接失败")

        except Exception as e:
            logger.error(f"Connection error: {e}")
            self._signal_bus.error_occurred.emit(str(e))

    async def _start_traffic_interceptor(self):
        """启动流量拦截器"""
        self._traffic_interceptor = TrafficInterceptor(network_client=self._network_client)
        await self._traffic_interceptor.start(
            socks5_port=self._config.socks5_port,
            udp_port=self._config.udp_port,
            upstream_host=self._config.server_host,
            upstream_port=self._config.server_port
        )

    async def _start_traffic_director(self):
        """启动流量定向器"""
        self._traffic_director = TrafficDirector()
        await self._traffic_director.start()

    def _on_disconnect(self):
        """断开连接按钮点击"""
        self._async_bridge.run_coro(self._disconnect())

    async def _disconnect(self):
        """执行断开连接"""
        try:
            if self._traffic_interceptor:
                await self._traffic_interceptor.stop()
                self._traffic_interceptor = None

            if self._traffic_director:
                await self._traffic_director.stop()
                self._traffic_director = None

            if self._network_client:
                await self._network_client.disconnect()
                self._network_client = None

            self._connected = False
            self._signal_bus.connection_changed.emit("disconnected")

        except Exception as e:
            logger.error(f"Disconnect error: {e}")

    def _on_network_state_changed(self, old_state: ConnectionState, new_state: ConnectionState):
        """网络状态变化"""
        if new_state == ConnectionState.CONNECTED:
            self._signal_bus.connection_changed.emit("connected")
        elif new_state == ConnectionState.DISCONNECTED:
            self._signal_bus.connection_changed.emit("disconnected")
        elif new_state == ConnectionState.RECONNECTING:
            self._signal_bus.connection_changed.emit("reconnecting")
        elif new_state == ConnectionState.ERROR:
            self._signal_bus.error_occurred.emit("连接错误")

    def _on_connection_changed(self, status: str):
        """连接状态变化"""
        if status == "connected":
            self._main_window.connection_panel.set_connected()
        elif status == "disconnected":
            self._main_window.connection_panel.set_disconnected()
        elif status == "reconnecting":
            self._main_window.connection_panel.set_status("connecting", "重连中...")

    def _on_stats_updated(self, stats: Dict[str, Any]):
        """统计更新"""
        self._main_window.stats_panel.update_stats(stats)

    def _on_games_updated(self, games: List[Dict[str, Any]]):
        """游戏列表更新"""
        self._main_window.stats_panel.update_games(games)

    def _on_error(self, message: str):
        """错误处理"""
        self._main_window.connection_panel.set_error(message)
        QMessageBox.warning(self._main_window, "错误", message)

    def _on_settings_changed(self, settings: Dict[str, Any]):
        """设置变更"""
        server = settings.get("server", {})
        self._config.server_host = server.get("host", "127.0.0.1")
        self._config.server_port = server.get("port", 8388)

        connection = settings.get("connection", {})
        self._config.auto_reconnect = connection.get("auto_reconnect", True)
        self._config.auto_start = connection.get("auto_start", False)
        self._config.minimize_to_tray = connection.get("minimize_to_tray", True)

        proxy = settings.get("proxy", {})
        self._config.socks5_port = proxy.get("socks5_port", 1080)
        self._config.udp_port = proxy.get("udp_port", 1081)

        game = settings.get("game", {})
        self._config.auto_detect_games = game.get("auto_detect", True)
        self._config.accelerate_all = game.get("accelerate_all", False)

        self._config_manager.save(self._config)

        QMessageBox.information(self._main_window, "提示", "设置已保存")

    def _update_status(self):
        """更新状态"""
        if not self._connected or not self._network_client:
            return

        stats = self._network_client.stats.to_dict()
        stats["connect_time"] = self._start_time

        # 添加流量拦截器的统计
        if self._traffic_interceptor:
            socks5_stats = self._traffic_interceptor.socks5_stats
            if socks5_stats:
                stats["socks5_bytes_in"] = socks5_stats.total_bytes_in
                stats["socks5_bytes_out"] = socks5_stats.total_bytes_out
                stats["socks5_connections"] = socks5_stats.active_connections
            
            forward_stats = self._traffic_interceptor.get_forward_stats()
            total_forward_in = sum(s.get("bytes_in", 0) for s in forward_stats.values())
            total_forward_out = sum(s.get("bytes_out", 0) for s in forward_stats.values())
            stats["forward_bytes_in"] = total_forward_in
            stats["forward_bytes_out"] = total_forward_out

        self._signal_bus.stats_updated.emit(stats)

        if self._traffic_director:
            games = [
                game.to_dict()
                for game in self._traffic_director.process_monitor.detected_games.values()
            ]
            self._signal_bus.games_updated.emit(games)

            if self._traffic_interceptor:
                ports = self._traffic_director.get_acceleration_ports()
                self._traffic_interceptor.set_accelerated_ports(ports)

    def show_window(self):
        """显示主窗口"""
        self._main_window.show()
        self._main_window.activateWindow()

    def shutdown(self):
        """关闭客户端"""
        self._update_timer.stop()

        if self._async_bridge.run_coro:
            self._async_bridge.run_coro(self._disconnect())

        self._async_bridge.stop()
        logger.info("Client shutdown")


def main():
    """主函数"""
    app = QApplication(sys.argv)
    app.setApplicationName("Game Accelerator")
    app.setApplicationVersion("1.0.0")
    app.setQuitOnLastWindowClosed(False)

    StyleManager.apply_dark_theme(app)

    client = GameAcceleratorClient()
    client.initialize(app)
    client.show_window()

    def on_quit():
        client.shutdown()

    app.aboutToQuit.connect(on_quit)

    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
