"""
Traffic Interception and Forwarding Module
流量拦截与转发模块
"""

import asyncio
import socket
import struct
import logging
import time
from typing import Optional, Dict, List, Set, Any, Callable, Tuple
from dataclasses import dataclass, field
from enum import IntEnum
from collections import defaultdict
import threading

from shared.constants import TCP_BUFFER_SIZE, UDP_BUFFER_SIZE

logger = logging.getLogger(__name__)


class ProxyType(IntEnum):
    SOCKS5 = 5
    HTTP = 1
    TRANSPARENT = 2


@dataclass
class ProxyConnection:
    """代理连接"""
    conn_id: str
    client_addr: tuple
    target_addr: tuple
    protocol: str = "TCP"
    bytes_in: int = 0
    bytes_out: int = 0
    created_at: float = field(default_factory=time.time)
    is_active: bool = True

    def to_dict(self) -> Dict[str, Any]:
        return {
            "conn_id": self.conn_id,
            "client_addr": self.client_addr,
            "target_addr": self.target_addr,
            "protocol": self.protocol,
            "bytes_in": self.bytes_in,
            "bytes_out": self.bytes_out,
            "created_at": self.created_at,
            "is_active": self.is_active,
        }


@dataclass
class ProxyStats:
    """代理统计"""
    total_connections: int = 0
    active_connections: int = 0
    total_bytes_in: int = 0
    total_bytes_out: int = 0
    connections_per_port: Dict[int, int] = field(default_factory=lambda: defaultdict(int))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_connections": self.total_connections,
            "active_connections": self.active_connections,
            "total_bytes_in": self.total_bytes_in,
            "total_bytes_out": self.total_bytes_out,
            "connections_per_port": dict(self.connections_per_port),
        }


class SOCKS5Server:
    """SOCKS5代理服务器"""

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 1080,
        upstream_host: str = "127.0.0.1",
        upstream_port: int = 8388,
        network_client: Optional[Any] = None
    ):
        self._host = host
        self._port = port
        self._upstream_host = upstream_host
        self._upstream_port = upstream_port
        self._network_client = network_client
        self._server: Optional[asyncio.Server] = None
        self._connections: Dict[str, ProxyConnection] = {}
        self._stats = ProxyStats()
        self._running = False
        self._accelerated_ports: Set[int] = set()
        self._lock = asyncio.Lock()

    @property
    def stats(self) -> ProxyStats:
        return self._stats

    @property
    def is_running(self) -> bool:
        return self._running

    def set_accelerated_ports(self, ports: Set[int]):
        """设置需要加速的端口"""
        self._accelerated_ports = ports

    async def start(self):
        """启动代理服务器"""
        self._server = await asyncio.start_server(
            self._handle_client,
            self._host,
            self._port
        )
        self._running = True
        logger.info(f"SOCKS5 proxy started on {self._host}:{self._port}")

    async def stop(self):
        """停止代理服务器"""
        self._running = False
        if self._server:
            self._server.close()
            await self._server.wait_closed()

        for conn in list(self._connections.values()):
            conn.is_active = False

        self._connections.clear()
        logger.info("SOCKS5 proxy stopped")

    async def _handle_client(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter
    ):
        """处理客户端连接"""
        client_addr = writer.get_extra_info('peername')
        conn_id = f"{client_addr[0]}:{client_addr[1]}_{time.time()}"

        try:
            if not await self._handle_greeting(reader, writer):
                return

            target_addr = await self._handle_request(reader, writer)
            if not target_addr:
                return

            conn = ProxyConnection(
                conn_id=conn_id,
                client_addr=client_addr,
                target_addr=target_addr
            )

            async with self._lock:
                self._connections[conn_id] = conn
                self._stats.total_connections += 1
                self._stats.active_connections += 1
                self._stats.connections_per_port[target_addr[1]] += 1

            await self._relay(reader, writer, target_addr, conn)

        except Exception as e:
            logger.debug(f"Client handling error: {e}")
        finally:
            async with self._lock:
                if conn_id in self._connections:
                    self._connections[conn_id].is_active = False
                    del self._connections[conn_id]
                    self._stats.active_connections -= 1

            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    async def _handle_greeting(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter
    ) -> bool:
        """处理SOCKS5握手"""
        data = await reader.read(2)
        if len(data) < 2:
            return False

        version, nmethods = struct.unpack("!BB", data)
        if version != 5:
            return False

        methods = await reader.read(nmethods)
        if 0 in methods:
            writer.write(struct.pack("!BB", 5, 0))
        else:
            writer.write(struct.pack("!BB", 5, 255))
            return False

        await writer.drain()
        return True

    async def _handle_request(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter
    ) -> Optional[tuple]:
        """处理SOCKS5请求"""
        data = await reader.read(4)
        if len(data) < 4:
            return None

        version, cmd, _, atyp = struct.unpack("!BBBB", data)
        if version != 5 or cmd != 1:
            writer.write(struct.pack("!BB", 5, 7, 0, 1) + b"\x00\x00\x00\x00\x00\x00")
            await writer.drain()
            return None

        if atyp == 1:
            addr = await reader.read(4)
            target_host = socket.inet_ntoa(addr)
        elif atyp == 3:
            addr_len = await reader.read(1)
            addr = await reader.read(ord(addr_len))
            target_host = addr.decode()
        elif atyp == 4:
            addr = await reader.read(16)
            target_host = socket.inet_ntop(socket.AF_INET6, addr)
        else:
            return None

        port_data = await reader.read(2)
        target_port = struct.unpack("!H", port_data)[0]

        bind_addr = "0.0.0.0"
        bind_port = 0

        response = struct.pack("!BB", 5, 0, 0, 1)
        response += socket.inet_aton(bind_addr)
        response += struct.pack("!H", bind_port)
        writer.write(response)
        await writer.drain()

        return (target_host, target_port)

    async def _relay(
        self,
        client_reader: asyncio.StreamReader,
        client_writer: asyncio.StreamWriter,
        target_addr: tuple,
        conn: ProxyConnection
    ):
        """转发数据"""
        target_host, target_port = target_addr

        use_accelerator = target_port in self._accelerated_ports

        try:
            if use_accelerator and self._network_client and self._network_client.is_connected:
                target_reader, target_writer = None, None
            elif use_accelerator:
                target_reader, target_writer = await asyncio.open_connection(
                    self._upstream_host,
                    self._upstream_port
                )
            else:
                target_reader, target_writer = await asyncio.open_connection(
                    target_host,
                    target_port
                )
        except Exception as e:
            logger.debug(f"Failed to connect to target: {e}")
            return

        async def forward(
            reader: asyncio.StreamReader,
            writer: asyncio.StreamWriter,
            direction: str
        ):
            try:
                while self._running:
                    data = await reader.read(TCP_BUFFER_SIZE)
                    if not data:
                        break

                    if use_accelerator and self._network_client and self._network_client.is_connected:
                        if direction == "out":
                            await self._network_client.send_data(data, encrypt=False)
                        else:
                            pass
                    else:
                        writer.write(data)
                        await writer.drain()

                    if direction == "out":
                        conn.bytes_out += len(data)
                        self._stats.total_bytes_out += len(data)
                    else:
                        conn.bytes_in += len(data)
                        self._stats.total_bytes_in += len(data)

            except Exception:
                pass
            finally:
                try:
                    writer.close()
                    await writer.wait_closed()
                except Exception:
                    pass

        if use_accelerator and self._network_client and self._network_client.is_connected:
            async def forward_from_network():
                while self._running:
                    try:
                        await asyncio.sleep(0.1)
                    except Exception:
                        break
            
            await asyncio.gather(
                forward(client_reader, client_writer, "out"),
                forward_from_network(),
                return_exceptions=True
            )
        else:
            await asyncio.gather(
                forward(client_reader, target_writer, "out"),
                forward(target_reader, client_writer, "in"),
                return_exceptions=True
            )

    def get_connections(self) -> List[ProxyConnection]:
        """获取所有连接"""
        return list(self._connections.values())


class LocalPortForwarder:
    """本地端口转发器"""

    def __init__(self):
        self._forwards: Dict[int, Dict[str, Any]] = {}
        self._servers: Dict[int, asyncio.Server] = {}
        self._running = False

    @property
    def active_forwards(self) -> Dict[int, Dict[str, Any]]:
        return self._forwards.copy()

    async def add_forward(
        self,
        local_port: int,
        remote_host: str,
        remote_port: int,
        accelerator_host: str = "127.0.0.1",
        accelerator_port: int = 8388,
        use_accelerator: bool = True
    ) -> bool:
        """添加端口转发"""
        if local_port in self._forwards:
            return False

        self._forwards[local_port] = {
            "remote_host": remote_host,
            "remote_port": remote_port,
            "accelerator_host": accelerator_host,
            "accelerator_port": accelerator_port,
            "use_accelerator": use_accelerator,
            "connections": 0,
            "bytes_in": 0,
            "bytes_out": 0,
        }

        server = await asyncio.start_server(
            lambda r, w, p=local_port: self._handle_forward(r, w, p),
            "127.0.0.1",
            local_port
        )
        self._servers[local_port] = server
        self._running = True

        logger.info(f"Port forward added: {local_port} -> {remote_host}:{remote_port}")
        return True

    async def remove_forward(self, local_port: int) -> bool:
        """移除端口转发"""
        if local_port not in self._forwards:
            return False

        server = self._servers.pop(local_port, None)
        if server:
            server.close()
            await server.wait_closed()

        del self._forwards[local_port]
        logger.info(f"Port forward removed: {local_port}")
        return True

    async def _handle_forward(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        local_port: int
    ):
        """处理转发连接"""
        forward_info = self._forwards.get(local_port)
        if not forward_info:
            writer.close()
            return

        forward_info["connections"] += 1

        try:
            if forward_info["use_accelerator"]:
                target_host = forward_info["accelerator_host"]
                target_port = forward_info["accelerator_port"]
            else:
                target_host = forward_info["remote_host"]
                target_port = forward_info["remote_port"]

            target_reader, target_writer = await asyncio.open_connection(
                target_host, target_port
            )

            async def pipe(src, dst, direction: str):
                try:
                    while True:
                        data = await src.read(TCP_BUFFER_SIZE)
                        if not data:
                            break
                        dst.write(data)
                        await dst.drain()

                        if direction == "out":
                            forward_info["bytes_out"] += len(data)
                        else:
                            forward_info["bytes_in"] += len(data)
                except Exception:
                    pass
                finally:
                    try:
                        dst.close()
                        await dst.wait_closed()
                    except Exception:
                        pass

            await asyncio.gather(
                pipe(reader, target_writer, "out"),
                pipe(target_reader, writer, "in"),
                return_exceptions=True
            )

        except Exception as e:
            logger.debug(f"Forward error: {e}")
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    async def stop_all(self):
        """停止所有转发"""
        for port in list(self._servers.keys()):
            await self.remove_forward(port)
        self._running = False


class UDPProxy:
    """UDP代理"""

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 1081,
        upstream_host: str = "127.0.0.1",
        upstream_port: int = 8388
    ):
        self._host = host
        self._port = port
        self._upstream_host = upstream_host
        self._upstream_port = upstream_port
        self._socket: Optional[socket.socket] = None
        self._running = False
        self._mappings: Dict[tuple, tuple] = {}
        self._stats = ProxyStats()

    @property
    def stats(self) -> ProxyStats:
        return self._stats

    async def start(self):
        """启动UDP代理"""
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._socket.bind((self._host, self._port))
        self._socket.setblocking(False)
        self._running = True

        asyncio.create_task(self._receive_loop())
        logger.info(f"UDP proxy started on {self._host}:{self._port}")

    async def stop(self):
        """停止UDP代理"""
        self._running = False
        if self._socket:
            self._socket.close()
            self._socket = None
        self._mappings.clear()
        logger.info("UDP proxy stopped")

    async def _receive_loop(self):
        """接收循环"""
        loop = asyncio.get_event_loop()

        while self._running:
            try:
                data, addr = await loop.sock_recvfrom(self._socket, UDP_BUFFER_SIZE)
                asyncio.create_task(self._handle_datagram(data, addr))
            except Exception as e:
                if self._running:
                    logger.debug(f"UDP receive error: {e}")

    async def _handle_datagram(self, data: bytes, client_addr: tuple):
        """处理数据报"""
        target_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        target_socket.setblocking(False)

        try:
            loop = asyncio.get_event_loop()
            await loop.sock_sendto(
                target_socket,
                data,
                (self._upstream_host, self._upstream_port)
            )

            response, _ = await loop.sock_recvfrom(target_socket, UDP_BUFFER_SIZE)
            await loop.sock_sendto(self._socket, response, client_addr)

            self._stats.total_bytes_in += len(data)
            self._stats.total_bytes_out += len(response)

        except Exception as e:
            logger.debug(f"UDP forward error: {e}")
        finally:
            target_socket.close()


class TrafficInterceptor:
    """流量拦截器"""

    def __init__(self, network_client: Optional[Any] = None):
        self._socks5_proxy: Optional[SOCKS5Server] = None
        self._udp_proxy: Optional[UDPProxy] = None
        self._port_forwarder: Optional[LocalPortForwarder] = None
        self._accelerated_ports: Set[int] = set()
        self._running = False
        self._network_client = network_client

    @property
    def socks5_stats(self) -> Optional[ProxyStats]:
        return self._socks5_proxy.stats if self._socks5_proxy else None

    @property
    def udp_stats(self) -> Optional[ProxyStats]:
        return self._udp_proxy.stats if self._udp_proxy else None

    @property
    def port_forwards(self) -> Dict[int, Dict[str, Any]]:
        return self._port_forwarder.active_forwards if self._port_forwarder else {}

    async def start(
        self,
        socks5_port: int = 1080,
        udp_port: int = 1081,
        upstream_host: str = "127.0.0.1",
        upstream_port: int = 8388
    ):
        """启动流量拦截"""
        self._socks5_proxy = SOCKS5Server(
            port=socks5_port,
            upstream_host=upstream_host,
            upstream_port=upstream_port,
            network_client=self._network_client
        )
        self._socks5_proxy.set_accelerated_ports(self._accelerated_ports)
        await self._socks5_proxy.start()

        self._udp_proxy = UDPProxy(
            port=udp_port,
            upstream_host=upstream_host,
            upstream_port=upstream_port
        )
        await self._udp_proxy.start()

        self._port_forwarder = LocalPortForwarder()

        self._running = True
        logger.info("Traffic interceptor started")

    async def stop(self):
        """停止流量拦截"""
        self._running = False

        if self._socks5_proxy:
            await self._socks5_proxy.stop()
            self._socks5_proxy = None

        if self._udp_proxy:
            await self._udp_proxy.stop()
            self._udp_proxy = None

        if self._port_forwarder:
            await self._port_forwarder.stop_all()
            self._port_forwarder = None

        logger.info("Traffic interceptor stopped")

    def set_accelerated_ports(self, ports: Set[int]):
        """设置加速端口"""
        self._accelerated_ports = ports
        if self._socks5_proxy:
            self._socks5_proxy.set_accelerated_ports(ports)

    def add_accelerated_port(self, port: int):
        """添加加速端口"""
        self._accelerated_ports.add(port)
        if self._socks5_proxy:
            self._socks5_proxy.set_accelerated_ports(self._accelerated_ports)

    def remove_accelerated_port(self, port: int):
        """移除加速端口"""
        self._accelerated_ports.discard(port)
        if self._socks5_proxy:
            self._socks5_proxy.set_accelerated_ports(self._accelerated_ports)

    async def add_port_forward(
        self,
        local_port: int,
        remote_host: str,
        remote_port: int,
        use_accelerator: bool = True
    ) -> bool:
        """添加端口转发"""
        if not self._port_forwarder:
            return False

        accelerator_host = "127.0.0.1"
        accelerator_port = 8388

        if self._socks5_proxy:
            accelerator_port = self._socks5_proxy._upstream_port

        return await self._port_forwarder.add_forward(
            local_port,
            remote_host,
            remote_port,
            accelerator_host,
            accelerator_port,
            use_accelerator
        )

    async def remove_port_forward(self, local_port: int) -> bool:
        """移除端口转发"""
        if not self._port_forwarder:
            return False
        return await self._port_forwarder.remove_forward(local_port)

    def get_stats(self) -> Dict[str, Any]:
        """获取统计信息"""
        return {
            "socks5": self.socks5_stats.to_dict() if self.socks5_stats else {},
            "udp": self.udp_stats.to_dict() if self.udp_stats else {},
            "port_forwards": self.port_forwards,
            "accelerated_ports": list(self._accelerated_ports),
        }
