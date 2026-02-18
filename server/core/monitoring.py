"""
Monitoring and Logging System
监控与日志系统
"""

import os
import time
import logging
from logging import handlers
import asyncio
import json
from typing import Optional, Dict, Any, List, Callable      
from dataclasses import dataclass, field
from datetime import datetime 
from collections import deque 
from threading import Lock    
import psutil

from shared.constants import LOG_FORMAT, LOG_LEVEL


@dataclass
class MetricPoint:
    """指标数据点"""
    name: str
    value: float
    timestamp: float = field(default_factory=time.time)
    labels: Dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "value": self.value,
            "timestamp": self.timestamp,
            "labels": self.labels,
        }


@dataclass
class SystemMetrics:
    """系统指标"""
    cpu_percent: float = 0.0
    memory_percent: float = 0.0
    memory_used: int = 0
    memory_total: int = 0
    disk_percent: float = 0.0
    disk_used: int = 0
    disk_total: int = 0
    network_bytes_sent: int = 0
    network_bytes_recv: int = 0
    network_packets_sent: int = 0
    network_packets_recv: int = 0
    load_average: tuple = (0.0, 0.0, 0.0)
    process_count: int = 0
    uptime: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "cpu_percent": self.cpu_percent,
            "memory_percent": self.memory_percent,
            "memory_used": self.memory_used,
            "memory_total": self.memory_total,
            "disk_percent": self.disk_percent,
            "disk_used": self.disk_used,
            "disk_total": self.disk_total,
            "network_bytes_sent": self.network_bytes_sent,
            "network_bytes_recv": self.network_bytes_recv,
            "network_packets_sent": self.network_packets_sent,
            "network_packets_recv": self.network_packets_recv,
            "load_average": self.load_average,
            "process_count": self.process_count,
            "uptime": self.uptime,
        }


@dataclass
class ServerMetrics:
    """服务器指标"""
    total_connections: int = 0
    active_connections: int = 0
    total_users: int = 0
    active_users: int = 0
    bytes_in: int = 0
    bytes_out: int = 0
    packets_in: int = 0
    packets_out: int = 0
    errors: int = 0
    avg_latency_ms: float = 0.0
    max_latency_ms: float = 0.0
    min_latency_ms: float = float('inf')

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_connections": self.total_connections,
            "active_connections": self.active_connections,
            "total_users": self.total_users,
            "active_users": self.active_users,
            "bytes_in": self.bytes_in,
            "bytes_out": self.bytes_out,
            "packets_in": self.packets_in,
            "packets_out": self.packets_out,
            "errors": self.errors,
            "avg_latency_ms": self.avg_latency_ms,
            "max_latency_ms": self.max_latency_ms,
            "min_latency_ms": self.min_latency_ms if self.min_latency_ms != float('inf') else 0,
        }


class MetricsCollector:
    """指标收集器"""

    def __init__(self, history_size: int = 1000):
        self._history_size = history_size
        self._metrics: Dict[str, deque] = {}
        self._lock = Lock()
        self._start_time = time.time()
        self._last_network_io = psutil.net_io_counters()
        self._server_metrics = ServerMetrics()

    def record(self, name: str, value: float, labels: Optional[Dict[str, str]] = None):
        """记录指标"""
        point = MetricPoint(name=name, value=value, labels=labels or {})
        
        with self._lock:
            if name not in self._metrics:
                self._metrics[name] = deque(maxlen=self._history_size)
            self._metrics[name].append(point)

    def increment(self, name: str, value: float = 1.0, labels: Optional[Dict[str, str]] = None):
        """增加计数器"""
        self.record(name, value, labels)

    def get_metrics(self, name: str, limit: int = 100) -> List[MetricPoint]:
        """获取指标历史"""
        with self._lock:
            if name not in self._metrics:
                return []
            points = list(self._metrics[name])[-limit:]
            return points

    def get_latest(self, name: str) -> Optional[MetricPoint]:
        """获取最新指标"""
        with self._lock:
            if name not in self._metrics or not self._metrics[name]:
                return None
            return self._metrics[name][-1]

    def get_all_metrics(self) -> Dict[str, List[MetricPoint]]:
        """获取所有指标"""
        with self._lock:
            return {name: list(points) for name, points in self._metrics.items()}

    def collect_system_metrics(self) -> SystemMetrics:
        """收集系统指标"""
        cpu_percent = psutil.cpu_percent(interval=0.1)
        memory = psutil.virtual_memory()
        disk = psutil.disk_usage('/')
        network = psutil.net_io_counters()
        
        try:
            load_avg = os.getloadavg()
        except (OSError, AttributeError):
            load_avg = (0.0, 0.0, 0.0)

        uptime = time.time() - self._start_time

        metrics = SystemMetrics(
            cpu_percent=cpu_percent,
            memory_percent=memory.percent,
            memory_used=memory.used,
            memory_total=memory.total,
            disk_percent=disk.percent,
            disk_used=disk.used,
            disk_total=disk.total,
            network_bytes_sent=network.bytes_sent,
            network_bytes_recv=network.bytes_recv,
            network_packets_sent=network.packets_sent,
            network_packets_recv=network.packets_recv,
            load_average=load_avg,
            process_count=len(psutil.pids()),
            uptime=uptime,
        )

        self.record("system.cpu_percent", cpu_percent)
        self.record("system.memory_percent", memory.percent)
        self.record("system.disk_percent", disk.percent)

        return metrics

    @property
    def server_metrics(self) -> ServerMetrics:
        return self._server_metrics

    def update_server_metrics(
        self,
        total_connections: Optional[int] = None,
        active_connections: Optional[int] = None,
        total_users: Optional[int] = None,
        active_users: Optional[int] = None,
        bytes_in: Optional[int] = None,
        bytes_out: Optional[int] = None,
        packets_in: Optional[int] = None,
        packets_out: Optional[int] = None,
        errors: Optional[int] = None,
        latency_ms: Optional[float] = None,
    ):
        """更新服务器指标"""
        if total_connections is not None:
            self._server_metrics.total_connections = total_connections
        if active_connections is not None:
            self._server_metrics.active_connections = active_connections
        if total_users is not None:
            self._server_metrics.total_users = total_users
        if active_users is not None:
            self._server_metrics.active_users = active_users
        if bytes_in is not None:
            self._server_metrics.bytes_in += bytes_in
        if bytes_out is not None:
            self._server_metrics.bytes_out += bytes_out
        if packets_in is not None:
            self._server_metrics.packets_in += packets_in
        if packets_out is not None:
            self._server_metrics.packets_out += packets_out
        if errors is not None:
            self._server_metrics.errors += errors
        if latency_ms is not None:
            self._server_metrics.avg_latency_ms = (
                (self._server_metrics.avg_latency_ms + latency_ms) / 2
            )
            self._server_metrics.max_latency_ms = max(
                self._server_metrics.max_latency_ms, latency_ms
            )
            if self._server_metrics.min_latency_ms == float('inf'):
                self._server_metrics.min_latency_ms = latency_ms
            else:
                self._server_metrics.min_latency_ms = min(
                    self._server_metrics.min_latency_ms, latency_ms
                )

        self.record("server.connections", self._server_metrics.active_connections)
        self.record("server.bytes_in", self._server_metrics.bytes_in)
        self.record("server.bytes_out", self._server_metrics.bytes_out)


class Logger:
    """日志管理器"""

    _instance = None
    _initialized = False

    def __new__(cls, *args, **kwargs):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(
        self,
        name: str = "GameAccelerator",
        log_dir: str = "logs",
        log_level: str = LOG_LEVEL,
        max_bytes: int = 10 * 1024 * 1024,
        backup_count: int = 5
    ):
        if Logger._initialized:
            return

        self._name = name
        self._log_dir = log_dir
        self._log_level = getattr(logging, log_level.upper(), logging.INFO)
        self._max_bytes = max_bytes
        self._backup_count = backup_count
        self._loggers: Dict[str, logging.Logger] = {}

        os.makedirs(log_dir, exist_ok=True)
        self._setup_root_logger()
        Logger._initialized = True

    def _setup_root_logger(self):
        """配置根日志器"""
        root_logger = logging.getLogger()
        root_logger.setLevel(self._log_level)

        console_handler = logging.StreamHandler()
        console_handler.setLevel(self._log_level)
        console_formatter = logging.Formatter(LOG_FORMAT)
        console_handler.setFormatter(console_formatter)
        root_logger.addHandler(console_handler)

        file_handler = handlers.RotatingFileHandler(
            os.path.join(self._log_dir, "server.log"),
            maxBytes=self._max_bytes,
            backupCount=self._backup_count,
            encoding="utf-8"
        )
        file_handler.setLevel(self._log_level)
        file_formatter = logging.Formatter(LOG_FORMAT)
        file_handler.setFormatter(file_formatter)
        root_logger.addHandler(file_handler)

        error_handler = handlers.RotatingFileHandler(
            os.path.join(self._log_dir, "error.log"),
            maxBytes=self._max_bytes,
            backupCount=self._backup_count,
            encoding="utf-8"
        )
        error_handler.setLevel(logging.ERROR)
        error_handler.setFormatter(file_formatter)
        root_logger.addHandler(error_handler)

    def get_logger(self, name: str) -> logging.Logger:
        """获取日志器"""
        if name not in self._loggers:
            self._loggers[name] = logging.getLogger(name)
        return self._loggers[name]


class AuditLogger:
    """审计日志记录器"""

    def __init__(self, log_dir: str = "logs/audit"):
        self._log_dir = log_dir
        os.makedirs(log_dir, exist_ok=True)
        self._lock = asyncio.Lock()

    async def log(
        self,
        action: str,
        user_id: str = "",
        details: Optional[Dict[str, Any]] = None,
        ip_address: str = "",
        success: bool = True
    ):
        """记录审计日志"""
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "action": action,
            "user_id": user_id,
            "ip_address": ip_address,
            "success": success,
            "details": details or {},
        }

        async with self._lock:
            log_file = os.path.join(
                self._log_dir,
                f"audit_{datetime.now().strftime('%Y%m%d')}.json"
            )
            with open(log_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(log_entry) + "\n")

    async def log_login(self, user_id: str, ip_address: str, success: bool):
        """记录登录"""
        await self.log("login", user_id, {}, ip_address, success)

    async def log_logout(self, user_id: str, ip_address: str):
        """记录登出"""
        await self.log("logout", user_id, {}, ip_address)

    async def log_connection(
        self,
        user_id: str,
        node_id: str,
        action: str,
        ip_address: str
    ):
        """记录连接"""
        await self.log(
            action,
            user_id,
            {"node_id": node_id},
            ip_address
        )


class PerformanceMonitor:
    """性能监控器"""

    def __init__(self, metrics_collector: MetricsCollector):
        self._metrics = metrics_collector
        self._latencies: deque = deque(maxlen=1000)
        self._lock = Lock()

    def record_latency(self, latency_ms: float):
        """记录延迟"""
        with self._lock:
            self._latencies.append(latency_ms)
        self._metrics.record("performance.latency", latency_ms)

    def get_latency_stats(self) -> Dict[str, float]:
        """获取延迟统计"""
        with self._lock:
            if not self._latencies:
                return {"avg": 0, "min": 0, "max": 0, "p50": 0, "p95": 0, "p99": 0}
            
            sorted_latencies = sorted(self._latencies)
            n = len(sorted_latencies)
            
            return {
                "avg": sum(sorted_latencies) / n,
                "min": sorted_latencies[0],
                "max": sorted_latencies[-1],
                "p50": sorted_latencies[int(n * 0.5)],
                "p95": sorted_latencies[int(n * 0.95)],
                "p99": sorted_latencies[int(n * 0.99)],
            }

    def record_throughput(self, bytes_per_second: float):
        """记录吞吐量"""
        self._metrics.record("performance.throughput", bytes_per_second)


class HealthMonitor:
    """健康监控器"""

    def __init__(self, metrics_collector: MetricsCollector):
        self._metrics = metrics_collector
        self._checks: Dict[str, Callable] = {}
        self._status: Dict[str, bool] = {}

    def register_check(self, name: str, check_func: Callable[[], bool]):
        """注册健康检查"""
        self._checks[name] = check_func

    async def run_checks(self) -> Dict[str, bool]:
        """运行所有健康检查"""
        for name, check_func in self._checks.items():
            try:
                if asyncio.iscoroutinefunction(check_func):
                    self._status[name] = await check_func()
                else:
                    self._status[name] = check_func()
            except Exception as e:
                logging.error(f"Health check {name} failed: {e}")
                self._status[name] = False

        return self._status

    def is_healthy(self) -> bool:
        """检查是否健康"""
        return all(self._status.values()) if self._status else True

    def get_status(self) -> Dict[str, Any]:
        """获取状态"""
        return {
            "healthy": self.is_healthy(),
            "checks": self._status,
        }


class MonitoringService:
    """监控服务"""

    def __init__(self, log_dir: str = "logs"):
        self._metrics_collector = MetricsCollector()
        self._logger = Logger(log_dir=log_dir)
        self._audit_logger = AuditLogger(log_dir=os.path.join(log_dir, "audit"))
        self._performance_monitor = PerformanceMonitor(self._metrics_collector)
        self._health_monitor = HealthMonitor(self._metrics_collector)
        self._running = False
        self._collect_interval = 10

    @property
    def metrics(self) -> MetricsCollector:
        return self._metrics_collector

    @property
    def performance(self) -> PerformanceMonitor:
        return self._performance_monitor

    @property
    def health(self) -> HealthMonitor:
        return self._health_monitor

    @property
    def audit(self) -> AuditLogger:
        return self._audit_logger

    def get_logger(self, name: str) -> logging.Logger:
        return self._logger.get_logger(name)

    async def start(self):
        """启动监控服务"""
        self._running = True
        asyncio.create_task(self._collect_loop())
        logging.info("Monitoring service started")

    async def stop(self):
        """停止监控服务"""
        self._running = False
        logging.info("Monitoring service stopped")

    async def _collect_loop(self):
        """收集循环"""
        while self._running:
            try:
                self._metrics_collector.collect_system_metrics()
                await self._health_monitor.run_checks()
                await asyncio.sleep(self._collect_interval)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logging.error(f"Metrics collection error: {e}")
                await asyncio.sleep(self._collect_interval)

    def get_full_status(self) -> Dict[str, Any]:
        """获取完整状态"""
        return {
            "system": self._metrics_collector.collect_system_metrics().to_dict(),
            "server": self._metrics_collector.server_metrics.to_dict(),
            "performance": self._performance_monitor.get_latency_stats(),
            "health": self._health_monitor.get_status(),
        }
