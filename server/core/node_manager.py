"""
Load Balancer and Node Management Module
负载均衡与节点管理模块
"""

import asyncio
import time
import socket
import secrets
import logging
from typing import Optional, Dict, List, Any, Callable
from dataclasses import dataclass, field
from datetime import datetime
from enum import IntEnum
import json

from shared.protocol import NodeInfo

logger = logging.getLogger(__name__)


class NodeStatus(IntEnum):
    OFFLINE = 0
    ONLINE = 1
    BUSY = 2
    MAINTENANCE = 3


class LoadBalanceStrategy(IntEnum):
    ROUND_ROBIN = 1
    LEAST_CONNECTIONS = 2
    LEAST_LATENCY = 3
    WEIGHTED = 4
    RANDOM = 5


@dataclass
class ServerNode:
    """服务器节点"""
    node_id: str
    name: str
    region: str
    host: str
    port: int
    api_port: int = 8080
    status: NodeStatus = NodeStatus.OFFLINE
    weight: int = 1
    max_connections: int = 1000
    current_connections: int = 0
    load: float = 0.0
    latency: int = 0
    last_check: float = 0
    last_success: float = 0
    success_count: int = 0
    fail_count: int = 0
    total_bytes_in: int = 0
    total_bytes_out: int = 0
    created_at: datetime = field(default_factory=datetime.now)
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def is_available(self) -> bool:
        return self.status == NodeStatus.ONLINE and self.current_connections < self.max_connections

    @property
    def load_percentage(self) -> float:
        if self.max_connections == 0:
            return 100.0
        return (self.current_connections / self.max_connections) * 100

    def to_dict(self) -> Dict[str, Any]:
        return {
            "node_id": self.node_id,
            "name": self.name,
            "region": self.region,
            "host": self.host,
            "port": self.port,
            "api_port": self.api_port,
            "status": self.status.value,
            "weight": self.weight,
            "max_connections": self.max_connections,
            "current_connections": self.current_connections,
            "load": self.load,
            "latency": self.latency,
            "last_check": self.last_check,
            "is_available": self.is_available,
        }

    def to_node_info(self) -> NodeInfo:
        return NodeInfo(
            node_id=self.node_id,
            name=self.name,
            region=self.region,
            host=self.host,
            port=self.port,
            load=self.load,
            latency=self.latency,
            max_connections=self.max_connections,
            current_connections=self.current_connections,
            is_available=self.is_available,
        )


class NodeHealthChecker:
    """节点健康检查器"""

    def __init__(self, check_interval: int = 30, timeout: int = 5):
        self._check_interval = check_interval
        self._timeout = timeout
        self._running = False
        self._tasks: Dict[str, asyncio.Task] = {}

    async def start_checking(self, node: ServerNode, on_status_change: Callable):
        """开始健康检查"""
        if node.node_id in self._tasks:
            return

        self._running = True
        self._tasks[node.node_id] = asyncio.create_task(
            self._check_loop(node, on_status_change)
        )

    async def stop_checking(self, node_id: str):
        """停止健康检查"""
        task = self._tasks.pop(node_id, None)
        if task:
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass

    async def stop_all(self):
        """停止所有健康检查"""
        self._running = False
        for node_id in list(self._tasks.keys()):
            await self.stop_checking(node_id)

    async def check_node(self, node: ServerNode) -> bool:
        """检查节点健康状态"""
        try:
            start_time = time.time()
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(node.host, node.port),
                timeout=self._timeout
            )
            
            latency = int((time.time() - start_time) * 1000)
            node.latency = latency
            node.last_success = time.time()
            node.success_count += 1
            node.last_check = time.time()

            writer.close()
            await writer.wait_closed()

            return True
        except Exception as e:
            logger.debug(f"Health check failed for node {node.node_id}: {e}")
            node.fail_count += 1
            node.last_check = time.time()
            return False

    async def _check_loop(self, node: ServerNode, on_status_change: Callable):
        """健康检查循环"""
        while self._running:
            try:
                is_healthy = await self.check_node(node)
                new_status = NodeStatus.ONLINE if is_healthy else NodeStatus.OFFLINE

                if node.status != new_status:
                    old_status = node.status
                    node.status = new_status
                    await on_status_change(node, old_status, new_status)

                await asyncio.sleep(self._check_interval)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Health check loop error for node {node.node_id}: {e}")
                await asyncio.sleep(self._check_interval)


class LoadBalancer:
    """负载均衡器"""

    def __init__(self, strategy: LoadBalanceStrategy = LoadBalanceStrategy.LEAST_LATENCY):
        self._strategy = strategy
        self._nodes: Dict[str, ServerNode] = {}
        self._round_robin_index = 0
        self._lock = asyncio.Lock()

    @property
    def node_count(self) -> int:
        return len(self._nodes)

    @property
    def available_count(self) -> int:
        return sum(1 for n in self._nodes.values() if n.is_available)

    async def add_node(self, node: ServerNode) -> bool:
        """添加节点"""
        async with self._lock:
            if node.node_id in self._nodes:
                return False
            self._nodes[node.node_id] = node
            return True

    async def remove_node(self, node_id: str) -> Optional[ServerNode]:
        """移除节点"""
        async with self._lock:
            return self._nodes.pop(node_id, None)

    async def get_node(self, node_id: str) -> Optional[ServerNode]:
        """获取节点"""
        return self._nodes.get(node_id)

    async def get_all_nodes(self) -> List[ServerNode]:
        """获取所有节点"""
        return list(self._nodes.values())

    async def get_available_nodes(self) -> List[ServerNode]:
        """获取可用节点"""
        return [n for n in self._nodes.values() if n.is_available]

    async def get_best_node(self, region: Optional[str] = None) -> Optional[ServerNode]:
        """根据策略获取最佳节点"""
        async with self._lock:
            nodes = [n for n in self._nodes.values() if n.is_available]
            
            if region:
                nodes = [n for n in nodes if n.region == region]

            if not nodes:
                return None

            if self._strategy == LoadBalanceStrategy.ROUND_ROBIN:
                return self._round_robin(nodes)
            elif self._strategy == LoadBalanceStrategy.LEAST_CONNECTIONS:
                return self._least_connections(nodes)
            elif self._strategy == LoadBalanceStrategy.LEAST_LATENCY:
                return self._least_latency(nodes)
            elif self._strategy == LoadBalanceStrategy.WEIGHTED:
                return self._weighted(nodes)
            elif self._strategy == LoadBalanceStrategy.RANDOM:
                return self._random(nodes)
            else:
                return nodes[0]

    def _round_robin(self, nodes: List[ServerNode]) -> ServerNode:
        """轮询策略"""
        node = nodes[self._round_robin_index % len(nodes)]
        self._round_robin_index += 1
        return node

    def _least_connections(self, nodes: List[ServerNode]) -> ServerNode:
        """最少连接策略"""
        return min(nodes, key=lambda n: n.current_connections)

    def _least_latency(self, nodes: List[ServerNode]) -> ServerNode:
        """最低延迟策略"""
        return min(nodes, key=lambda n: n.latency if n.latency > 0 else float('inf'))

    def _weighted(self, nodes: List[ServerNode]) -> ServerNode:
        """加权策略"""
        import random
        total_weight = sum(n.weight for n in nodes)
        r = random.randint(1, total_weight)
        current = 0
        for node in nodes:
            current += node.weight
            if r <= current:
                return node
        return nodes[0]

    def _random(self, nodes: List[ServerNode]) -> ServerNode:
        """随机策略"""
        import random
        return random.choice(nodes)

    async def increment_connections(self, node_id: str) -> bool:
        """增加节点连接数"""
        async with self._lock:
            node = self._nodes.get(node_id)
            if node is None:
                return False
            if node.current_connections >= node.max_connections:
                return False
            node.current_connections += 1
            node.load = node.load_percentage
            return True

    async def decrement_connections(self, node_id: str) -> bool:
        """减少节点连接数"""
        async with self._lock:
            node = self._nodes.get(node_id)
            if node is None:
                return False
            if node.current_connections > 0:
                node.current_connections -= 1
            node.load = node.load_percentage
            return True

    async def update_node_stats(
        self,
        node_id: str,
        bytes_in: int = 0,
        bytes_out: int = 0
    ):
        """更新节点统计"""
        async with self._lock:
            node = self._nodes.get(node_id)
            if node:
                node.total_bytes_in += bytes_in
                node.total_bytes_out += bytes_out


class NodeManager:
    """节点管理器"""

    def __init__(
        self,
        strategy: LoadBalanceStrategy = LoadBalanceStrategy.LEAST_LATENCY,
        health_check_interval: int = 30
    ):
        self._load_balancer = LoadBalancer(strategy)
        self._health_checker = NodeHealthChecker(health_check_interval)
        self._status_callbacks: List[Callable] = []

    @property
    def load_balancer(self) -> LoadBalancer:
        return self._load_balancer

    async def initialize(self):
        """初始化节点管理器"""
        pass

    async def shutdown(self):
        """关闭节点管理器"""
        await self._health_checker.stop_all()

    def add_status_callback(self, callback: Callable):
        """添加状态变化回调"""
        self._status_callbacks.append(callback)

    async def register_node(
        self,
        name: str,
        region: str,
        host: str,
        port: int,
        api_port: int = 8080,
        max_connections: int = 1000,
        weight: int = 1,
        metadata: Optional[Dict[str, Any]] = None
    ) -> ServerNode:
        """注册新节点"""
        node = ServerNode(
            node_id=secrets.token_urlsafe(8),
            name=name,
            region=region,
            host=host,
            port=port,
            api_port=api_port,
            max_connections=max_connections,
            weight=weight,
            metadata=metadata or {}
        )

        await self._load_balancer.add_node(node)
        await self._health_checker.start_checking(node, self._on_status_change)

        logger.info(f"Registered node: {name} ({host}:{port})")
        return node

    async def unregister_node(self, node_id: str) -> bool:
        """注销节点"""
        await self._health_checker.stop_checking(node_id)
        node = await self._load_balancer.remove_node(node_id)
        if node:
            logger.info(f"Unregistered node: {node.name}")
            return True
        return False

    async def get_node(self, node_id: str) -> Optional[ServerNode]:
        """获取节点"""
        return await self._load_balancer.get_node(node_id)

    async def get_best_node(self, region: Optional[str] = None) -> Optional[ServerNode]:
        """获取最佳节点"""
        return await self._load_balancer.get_best_node(region)

    async def get_all_nodes(self) -> List[ServerNode]:
        """获取所有节点"""
        return await self._load_balancer.get_all_nodes()

    async def get_available_nodes(self) -> List[ServerNode]:
        """获取可用节点"""
        return await self._load_balancer.get_available_nodes()

    async def get_node_list_for_client(self) -> List[NodeInfo]:
        """获取客户端节点列表"""
        nodes = await self._load_balancer.get_all_nodes()
        return [n.to_node_info() for n in nodes]

    async def _on_status_change(
        self,
        node: ServerNode,
        old_status: NodeStatus,
        new_status: NodeStatus
    ):
        """节点状态变化处理"""
        logger.info(
            f"Node {node.name} status changed: {old_status.name} -> {new_status.name}"
        )
        for callback in self._status_callbacks:
            try:
                await callback(node, old_status, new_status)
            except Exception as e:
                logger.error(f"Status callback error: {e}")

    async def check_node_now(self, node_id: str) -> bool:
        """立即检查节点"""
        node = await self._load_balancer.get_node(node_id)
        if node is None:
            return False
        return await self._health_checker.check_node(node)

    async def update_node_config(
        self,
        node_id: str,
        **kwargs
    ) -> bool:
        """更新节点配置"""
        node = await self._load_balancer.get_node(node_id)
        if node is None:
            return False

        for key, value in kwargs.items():
            if hasattr(node, key):
                setattr(node, key, value)

        return True

    async def get_stats(self) -> Dict[str, Any]:
        """获取统计信息"""
        nodes = await self._load_balancer.get_all_nodes()
        total_connections = sum(n.current_connections for n in nodes)
        total_capacity = sum(n.max_connections for n in nodes)
        available = sum(1 for n in nodes if n.is_available)

        return {
            "total_nodes": len(nodes),
            "available_nodes": available,
            "total_connections": total_connections,
            "total_capacity": total_capacity,
            "load_percentage": (total_connections / total_capacity * 100) if total_capacity > 0 else 0,
            "nodes": [n.to_dict() for n in nodes],
        }
