"""
Game Process Detection Module
游戏进程识别与流量定向模块
"""

import os
import re
import asyncio
import logging
from typing import Optional, Dict, List, Set, Any, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from enum import IntEnum
import platform

import psutil

from shared.constants import GAME_PORTS, DEFAULT_GAME_PORTS

logger = logging.getLogger(__name__)


class GamePlatform(IntEnum):
    UNKNOWN = 0
    STEAM = 1
    BATTLENET = 2
    ORIGIN = 3
    EPIC = 4
    RIOT = 5
    UPLAY = 6
    PLAYSTATION = 7
    XBOX = 8
    NINTENDO = 9
    CUSTOM = 10


@dataclass
class GameProcess:
    """游戏进程信息"""
    pid: int
    name: str
    exe_path: str
    platform: GamePlatform
    game_name: str = ""
    ports: Set[int] = field(default_factory=set)
    connections: List[Tuple[str, int]] = field(default_factory=list)
    cpu_percent: float = 0.0
    memory_percent: float = 0.0
    create_time: float = 0.0
    is_running: bool = True

    def to_dict(self) -> Dict[str, Any]:
        return {
            "pid": self.pid,
            "name": self.name,
            "exe_path": self.exe_path,
            "platform": self.platform.name,
            "game_name": self.game_name,
            "ports": list(self.ports),
            "connections": self.connections,
            "cpu_percent": self.cpu_percent,
            "memory_percent": self.memory_percent,
            "create_time": self.create_time,
            "is_running": self.is_running,
        }


@dataclass
class GameRule:
    """游戏规则"""
    name: str
    platform: GamePlatform
    process_names: List[str] = field(default_factory=list)
    exe_patterns: List[str] = field(default_factory=list)
    ports: List[int] = field(default_factory=list)
    port_ranges: List[Tuple[int, int]] = field(default_factory=list)
    domains: List[str] = field(default_factory=list)
    enabled: bool = True

    def matches_process(self, process_name: str, exe_path: str) -> bool:
        """检查进程是否匹配"""
        process_name_lower = process_name.lower()
        exe_path_lower = exe_path.lower()

        for name in self.process_names:
            if name.lower() == process_name_lower:
                return True

        for pattern in self.exe_patterns:
            if re.search(pattern, exe_path_lower, re.IGNORECASE):
                return True

        return False

    def get_all_ports(self) -> Set[int]:
        """获取所有端口"""
        ports = set(self.ports)
        for start, end in self.port_ranges:
            ports.update(range(start, end + 1))
        return ports


DEFAULT_GAME_RULES: List[GameRule] = [
    GameRule(
        name="Steam Games",
        platform=GamePlatform.STEAM,
        process_names=["steam", "steam.exe", "steamwebhelper.exe", "gameoverlayui.exe"],
        exe_patterns=[r"steamapps\\common\\", r"steam\\steam.exe"],
        ports=GAME_PORTS.get("steam", []),
    ),
    GameRule(
        name="Battle.net",
        platform=GamePlatform.BATTLENET,
        process_names=["battle.net.exe", "blizzard error reporter.exe", "agent.exe"],
        exe_patterns=[r"battle\.net", r"blizzard"],
        ports=GAME_PORTS.get("battlenet", []),
    ),
    GameRule(
        name="Origin",
        platform=GamePlatform.ORIGIN,
        process_names=["origin.exe", "eabackgroundservice.exe"],
        exe_patterns=[r"origin", r"electronic arts"],
        ports=GAME_PORTS.get("origin", []),
    ),
    GameRule(
        name="Epic Games",
        platform=GamePlatform.EPIC,
        process_names=["epicgameslauncher.exe", "unrealcefsubprocess.exe"],
        exe_patterns=[r"epic games", r"unreal"],
        ports=GAME_PORTS.get("epic", []),
    ),
    GameRule(
        name="Riot Games",
        platform=GamePlatform.RIOT,
        process_names=["leagueclient.exe", "leagueclientux.exe", "valorant.exe", "riotclientservices.exe"],
        exe_patterns=[r"riot games", r"league of legends", r"valorant"],
        ports=GAME_PORTS.get("riot", []),
    ),
    GameRule(
        name="Ubisoft Connect",
        platform=GamePlatform.UPLAY,
        process_names=["upc.exe", "ubisoftgamelauncher.exe", "ubisoftconnect.exe"],
        exe_patterns=[r"ubisoft", r"uplay"],
        ports=GAME_PORTS.get("ubisoft", []),
    ),
    GameRule(
        name="PlayStation",
        platform=GamePlatform.PLAYSTATION,
        process_names=["psnow.exe", "playstationnow.exe"],
        exe_patterns=[r"playstation", r"ps now"],
        ports=GAME_PORTS.get("playstation", []),
    ),
    GameRule(
        name="Xbox",
        platform=GamePlatform.XBOX,
        process_names=["xboxapp.exe", "xboxgames.exe", "gamingservices.exe"],
        exe_patterns=[r"xbox", r"microsoft\\gaming"],
        ports=GAME_PORTS.get("xbox", []),
    ),
    GameRule(
        name="Nintendo",
        platform=GamePlatform.NINTENDO,
        process_names=[],
        exe_patterns=[r"nintendo", r"yuzu", r"ryujinx"],
        ports=GAME_PORTS.get("nintendo", []),
    ),
]


class ProcessMonitor:
    """进程监控器"""

    def __init__(self, scan_interval: float = 5.0):
        self._scan_interval = scan_interval
        self._game_rules: List[GameRule] = DEFAULT_GAME_RULES.copy()
        self._custom_rules: List[GameRule] = []
        self._detected_games: Dict[int, GameProcess] = {}
        self._running = False
        self._scan_task: Optional[asyncio.Task] = None
        self._callbacks: List[callable] = []

    @property
    def detected_games(self) -> Dict[int, GameProcess]:
        return self._detected_games.copy()

    @property
    def game_count(self) -> int:
        return len(self._detected_games)

    def add_callback(self, callback: callable):
        """添加回调函数"""
        self._callbacks.append(callback)

    def add_custom_rule(self, rule: GameRule):
        """添加自定义规则"""
        self._custom_rules.append(rule)

    def remove_custom_rule(self, name: str) -> bool:
        """移除自定义规则"""
        for i, rule in enumerate(self._custom_rules):
            if rule.name == name:
                del self._custom_rules[i]
                return True
        return False

    def get_all_rules(self) -> List[GameRule]:
        """获取所有规则"""
        return self._game_rules + self._custom_rules

    async def start(self):
        """启动监控"""
        self._running = True
        self._scan_task = asyncio.create_task(self._scan_loop())
        logger.info("Process monitor started")

    async def stop(self):
        """停止监控"""
        self._running = False
        if self._scan_task:
            self._scan_task.cancel()
            try:
                await self._scan_task
            except asyncio.CancelledError:
                pass
        logger.info("Process monitor stopped")

    async def _scan_loop(self):
        """扫描循环"""
        while self._running:
            try:
                await self._scan_processes()
                await asyncio.sleep(self._scan_interval)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Process scan error: {e}")
                await asyncio.sleep(self._scan_interval)

    async def _scan_processes(self):
        """扫描进程"""
        current_pids = set()
        new_games = []
        removed_pids = []

        for proc in psutil.process_iter(['pid', 'name', 'exe', 'create_time', 'cpu_percent', 'memory_percent']):
            try:
                pid = proc.info['pid']
                current_pids.add(pid)

                if pid in self._detected_games:
                    game = self._detected_games[pid]
                    game.cpu_percent = proc.info.get('cpu_percent', 0) or 0
                    game.memory_percent = proc.info.get('memory_percent', 0) or 0
                    continue

                name = proc.info.get('name', '')
                exe_path = proc.info.get('exe', '') or ''

                game_process = self._identify_game(pid, name, exe_path)
                if game_process:
                    game_process.create_time = proc.info.get('create_time', 0) or 0
                    game_process.cpu_percent = proc.info.get('cpu_percent', 0) or 0
                    game_process.memory_percent = proc.info.get('memory_percent', 0) or 0
                    self._detected_games[pid] = game_process
                    new_games.append(game_process)
                    logger.info(f"Detected game: {game_process.name} (PID: {pid})")

            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

        for pid in list(self._detected_games.keys()):
            if pid not in current_pids:
                removed_pids.append(pid)
                del self._detected_games[pid]

        if new_games or removed_pids:
            await self._notify_callbacks(new_games, removed_pids)

    def _identify_game(self, pid: int, name: str, exe_path: str) -> Optional[GameProcess]:
        """识别游戏进程"""
        all_rules = self.get_all_rules()

        for rule in all_rules:
            if not rule.enabled:
                continue

            if rule.matches_process(name, exe_path):
                return GameProcess(
                    pid=pid,
                    name=name,
                    exe_path=exe_path,
                    platform=rule.platform,
                    game_name=rule.name,
                    ports=rule.get_all_ports(),
                )

        return None

    async def _notify_callbacks(self, new_games: List[GameProcess], removed_pids: List[int]):
        """通知回调"""
        for callback in self._callbacks:
            try:
                if asyncio.iscoroutinefunction(callback):
                    await callback(new_games, removed_pids)
                else:
                    callback(new_games, removed_pids)
            except Exception as e:
                logger.error(f"Callback error: {e}")

    def scan_once(self) -> Dict[int, GameProcess]:
        """单次扫描"""
        for proc in psutil.process_iter(['pid', 'name', 'exe', 'create_time', 'cpu_percent', 'memory_percent']):
            try:
                pid = proc.info['pid']
                name = proc.info.get('name', '')
                exe_path = proc.info.get('exe', '') or ''

                game_process = self._identify_game(pid, name, exe_path)
                if game_process:
                    game_process.create_time = proc.info.get('create_time', 0) or 0
                    game_process.cpu_percent = proc.info.get('cpu_percent', 0) or 0
                    game_process.memory_percent = proc.info.get('memory_percent', 0) or 0
                    self._detected_games[pid] = game_process

            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

        return self._detected_games

    def get_process_connections(self, pid: int) -> List[Tuple[str, int, str]]:
        """获取进程的网络连接"""
        connections = []
        try:
            proc = psutil.Process(pid)
            for conn in proc.connections():
                if conn.status == 'ESTABLISHED' and conn.raddr:
                    ip = conn.raddr.ip
                    port = conn.raddr.port
                    proto = 'TCP' if conn.type == socket.SOCK_STREAM else 'UDP'
                    connections.append((ip, port, proto))
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
        return connections

    def update_game_connections(self, pid: int) -> bool:
        """更新游戏连接"""
        if pid not in self._detected_games:
            return False

        game = self._detected_games[pid]
        connections = self.get_process_connections(pid)
        game.connections = [(ip, port) for ip, port, _ in connections]

        for ip, port, _ in connections:
            game.ports.add(port)

        return True


class TrafficDirector:
    """流量定向器"""

    def __init__(self):
        self._process_monitor = ProcessMonitor()
        self._traffic_rules: Dict[int, Dict[str, Any]] = {}
        self._default_ports: Set[int] = set(DEFAULT_GAME_PORTS)
        self._enabled = False

    @property
    def process_monitor(self) -> ProcessMonitor:
        return self._process_monitor

    @property
    def is_enabled(self) -> bool:
        return self._enabled

    async def start(self):
        """启动流量定向"""
        await self._process_monitor.start()
        self._process_monitor.add_callback(self._on_game_detected)
        self._enabled = True
        logger.info("Traffic director started")

    async def stop(self):
        """停止流量定向"""
        await self._process_monitor.stop()
        self._enabled = False
        logger.info("Traffic director stopped")

    async def _on_game_detected(self, new_games: List[GameProcess], removed_pids: List[int]):
        """游戏检测回调"""
        for game in new_games:
            self._traffic_rules[game.pid] = {
                "platform": game.platform,
                "ports": game.ports,
                "connections": game.connections,
                "accelerated": False,
            }
            logger.info(f"Added traffic rule for {game.game_name} (PID: {game.pid})")

        for pid in removed_pids:
            if pid in self._traffic_rules:
                del self._traffic_rules[pid]
                logger.info(f"Removed traffic rule for PID: {pid}")

    def should_accelerate(self, dest_ip: str, dest_port: int) -> bool:
        """检查是否需要加速"""
        if not self._enabled:
            return False

        if dest_port in self._default_ports:
            return True

        for rule in self._traffic_rules.values():
            if dest_port in rule.get("ports", set()):
                return True

        return False

    def get_acceleration_ports(self) -> Set[int]:
        """获取需要加速的端口"""
        ports = self._default_ports.copy()
        for rule in self._traffic_rules.values():
            ports.update(rule.get("ports", set()))
        return ports

    def get_traffic_rules(self) -> Dict[int, Dict[str, Any]]:
        """获取流量规则"""
        return self._traffic_rules.copy()

    def add_custom_port(self, port: int):
        """添加自定义端口"""
        self._default_ports.add(port)

    def remove_custom_port(self, port: int):
        """移除自定义端口"""
        self._default_ports.discard(port)

    def get_game_info(self, pid: int) -> Optional[GameProcess]:
        """获取游戏信息"""
        return self._process_monitor.detected_games.get(pid)


import socket
