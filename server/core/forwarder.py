"""
High Performance TCP/UDP Data Forwarding Module
高性能TCP/UDP数据转发模块
"""

import asyncio
import socket
import time
import struct
from typing import Optional, Dict, Any, Callable, Set
from dataclasses import dataclass, field
from enum import IntEnum
from collections import deque
import logging

from shared.constants import TCP_BUFFER_SIZE, UDP_BUFFER_SIZE, CONNECTION_TIMEOUT
from shared.protocol import Packet, PacketHeader, MessageType, PacketFlags
from shared.crypto import SecureChannel, CryptoManager

logger = logging.getLogger(__name__)


class ConnectionState(IntEnum):
    DISCONNECTED = 0
    CONNECTING = 1
    AUTHENTICATING = 2
    CONNECTED = 3
    DISCONNECTING = 4


@dataclass
class ConnectionStats:
    """连接统计信息"""
    bytes_sent: int = 0
    bytes_received: int = 0
    packets_sent: int = 0
    packets_received: int = 0
    connect_time: float = 0
    last_activity: float = 0
    latency_ms: float = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "bytes_sent": self.bytes_sent,
            "bytes_received": self.bytes_received,
            "packets_sent": self.packets_sent,
            "packets_received": self.packets_received,
            "connect_time": self.connect_time,
            "last_activity": self.last_activity,
            "latency_ms": self.latency_ms,
        }


@dataclass
class ClientConnection:
    """客户端连接"""
    conn_id: str
    user_id: str
    remote_addr: tuple
    state: ConnectionState = ConnectionState.DISCONNECTED
    secure_channel: Optional[SecureChannel] = None
    tcp_reader: Optional[asyncio.StreamReader] = None
    tcp_writer: Optional[asyncio.StreamWriter] = None
    udp_socket: Optional[socket.socket] = None
    stats: ConnectionStats = field(default_factory=ConnectionStats)
    target_connections: Dict[str, "TargetConnection"] = field(default_factory=dict)
    created_at: float = field(default_factory=time.time)
    sequence: int = 0
    pending_acks: Dict[int, asyncio.Event] = field(default_factory=dict)

    def update_activity(self):
        """更新活动时间"""
        self.stats.last_activity = time.time()


@dataclass
class TargetConnection:
    """目标服务器连接"""
    target_id: str
    target_host: str
    target_port: int
    protocol: str = "tcp"
    reader: Optional[asyncio.StreamReader] = None
    writer: Optional[asyncio.StreamWriter] = None
    udp_socket: Optional[socket.socket] = None
    stats: ConnectionStats = field(default_factory=ConnectionStats)
    is_active: bool = False


class TCPForwarder:
    """TCP数据转发器"""

    def __init__(
        self,
        buffer_size: int = TCP_BUFFER_SIZE,
        timeout: int = CONNECTION_TIMEOUT
    ):
        self._buffer_size = buffer_size
        self._timeout = timeout
        self._active = False

    async def forward(
        self,
        source_reader: asyncio.StreamReader,
        source_writer: asyncio.StreamWriter,
        target_host: str,
        target_port: int,
        on_data: Optional[Callable[[bytes, str], bytes]] = None,
        stats: Optional[ConnectionStats] = None
    ) -> None:
        """
        转发TCP数据
        
        Args:
            source_reader: 源读取器
            source_writer: 源写入器
            target_host: 目标主机
            target_port: 目标端口
            on_data: 数据处理回调
            stats: 统计信息
        """
        try:
            target_reader, target_writer = await asyncio.wait_for(
                asyncio.open_connection(target_host, target_port),
                timeout=self._timeout
            )
        except Exception as e:
            logger.error(f"Failed to connect to target {target_host}:{target_port}: {e}")
            return

        async def forward_data(
            reader: asyncio.StreamReader,
            writer: asyncio.StreamWriter,
            direction: str
        ):
            try:
                while self._active:
                    data = await reader.read(self._buffer_size)
                    if not data:
                        break

                    if on_data:
                        data = on_data(data, direction)

                    writer.write(data)
                    await writer.drain()

                    if stats:
                        if direction == "out":
                            stats.bytes_sent += len(data)
                            stats.packets_sent += 1
                        else:
                            stats.bytes_received += len(data)
                            stats.packets_received += 1
            except Exception as e:
                logger.debug(f"Forward error ({direction}): {e}")
            finally:
                try:
                    writer.close()
                    await writer.wait_closed()
                except Exception:
                    pass

        self._active = True
        await asyncio.gather(
            forward_data(source_reader, target_writer, "out"),
            forward_data(target_reader, source_writer, "in"),
            return_exceptions=True
        )
        self._active = False

    def stop(self):
        """停止转发"""
        self._active = False


class UDPForwarder:
    """UDP数据转发器"""

    def __init__(
        self,
        buffer_size: int = UDP_BUFFER_SIZE,
        timeout: int = CONNECTION_TIMEOUT
    ):
        self._buffer_size = buffer_size
        self._timeout = timeout
        self._active = False
        self._mappings: Dict[tuple, tuple] = {}
        self._sockets: Dict[tuple, socket.socket] = {}

    async def start_forward(
        self,
        local_socket: socket.socket,
        target_host: str,
        target_port: int,
        on_data: Optional[Callable[[bytes, tuple], bytes]] = None,
        stats: Optional[ConnectionStats] = None
    ) -> None:
        """
        开始UDP转发
        
        Args:
            local_socket: 本地UDP套接字
            target_host: 目标主机
            target_port: 目标端口
            on_data: 数据处理回调
            stats: 统计信息
        """
        self._active = True
        loop = asyncio.get_event_loop()

        target_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        target_socket.setblocking(False)

        async def receive_from_client():
            while self._active:
                try:
                    data, addr = await loop.sock_recvfrom(local_socket, self._buffer_size)
                    if on_data:
                        data = on_data(data, addr)

                    await loop.sock_sendto(
                        target_socket, data, (target_host, target_port)
                    )
                    self._mappings[(target_host, target_port)] = addr

                    if stats:
                        stats.bytes_sent += len(data)
                        stats.packets_sent += 1
                except Exception as e:
                    if self._active:
                        logger.debug(f"UDP receive error: {e}")

        async def receive_from_target():
            while self._active:
                try:
                    data, addr = await loop.sock_recvfrom(target_socket, self._buffer_size)
                    client_addr = self._mappings.get(addr)
                    if client_addr:
                        if on_data:
                            data = on_data(data, addr)

                        await loop.sock_sendto(local_socket, data, client_addr)

                        if stats:
                            stats.bytes_received += len(data)
                            stats.packets_received += 1
                except Exception as e:
                    if self._active:
                        logger.debug(f"UDP receive from target error: {e}")

        await asyncio.gather(
            receive_from_client(),
            receive_from_target(),
            return_exceptions=True
        )

        target_socket.close()

    def stop(self):
        """停止转发"""
        self._active = False
        for sock in self._sockets.values():
            try:
                sock.close()
            except Exception:
                pass
        self._sockets.clear()
        self._mappings.clear()


class ConnectionManager:
    """连接管理器"""

    def __init__(self, max_connections: int = 2000):
        self._max_connections = max_connections
        self._connections: Dict[str, ClientConnection] = {}
        self._user_connections: Dict[str, Set[str]] = {}
        self._lock = asyncio.Lock()

    @property
    def connection_count(self) -> int:
        return len(self._connections)

    @property
    def is_full(self) -> bool:
        return len(self._connections) >= self._max_connections

    async def add_connection(self, conn: ClientConnection) -> bool:
        """添加连接"""
        async with self._lock:
            if self.is_full:
                return False

            self._connections[conn.conn_id] = conn

            if conn.user_id not in self._user_connections:
                self._user_connections[conn.user_id] = set()
            self._user_connections[conn.user_id].add(conn.conn_id)

            return True

    async def remove_connection(self, conn_id: str) -> Optional[ClientConnection]:
        """移除连接"""
        async with self._lock:
            conn = self._connections.pop(conn_id, None)
            if conn:
                if conn.user_id in self._user_connections:
                    self._user_connections[conn.user_id].discard(conn_id)
                    if not self._user_connections[conn.user_id]:
                        del self._user_connections[conn.user_id]
            return conn

    async def get_connection(self, conn_id: str) -> Optional[ClientConnection]:
        """获取连接"""
        return self._connections.get(conn_id)

    async def get_user_connections(self, user_id: str) -> Set[str]:
        """获取用户的所有连接"""
        return self._user_connections.get(user_id, set()).copy()

    async def get_all_connections(self) -> Dict[str, ClientConnection]:
        """获取所有连接"""
        return self._connections.copy()

    async def cleanup_inactive(self, timeout: int = CONNECTION_TIMEOUT) -> int:
        """清理不活跃的连接"""
        cleaned = 0
        now = time.time()
        async with self._lock:
            to_remove = []
            for conn_id, conn in self._connections.items():
                if now - conn.stats.last_activity > timeout:
                    to_remove.append(conn_id)

            for conn_id in to_remove:
                await self.remove_connection(conn_id)
                cleaned += 1

        return cleaned


class PacketProcessor:
    """数据包处理器"""

    def __init__(self, crypto: Optional[CryptoManager] = None):
        self._crypto = crypto
        self._sequence = 0

    def create_packet(
        self,
        msg_type: MessageType,
        payload: bytes = b"",
        flags: int = 0,
        encrypt: bool = True
    ) -> bytes:
        """创建数据包"""
        if encrypt and self._crypto:
            payload = self._crypto.encrypt(payload)
            flags |= PacketFlags.ENCRYPTED

        packet = Packet.create(
            msg_type=msg_type,
            payload=payload,
            flags=flags,
            sequence=self._sequence,
            timestamp=int(time.time())
        )
        self._sequence += 1
        return packet.pack()

    def parse_packet(self, data: bytes) -> Optional[Packet]:
        """解析数据包"""
        return Packet.unpack(data)

    def decrypt_payload(self, packet: Packet) -> bytes:
        """解密数据包负载"""
        if packet.header.flags & PacketFlags.ENCRYPTED and self._crypto:
            return self._crypto.decrypt(packet.payload)
        return packet.payload


class ProxyServer:
    """代理服务器基类"""

    def __init__(
        self,
        host: str = "0.0.0.0",
        port: int = 8388,
        max_connections: int = 2000
    ):
        self._host = host
        self._port = port
        self._connection_manager = ConnectionManager(max_connections)
        self._tcp_forwarder = TCPForwarder()
        self._udp_forwarder = UDPForwarder()
        self._running = False
        self._server: Optional[asyncio.Server] = None
        self._udp_socket: Optional[socket.socket] = None

    @property
    def is_running(self) -> bool:
        return self._running

    @property
    def connection_count(self) -> int:
        return self._connection_manager.connection_count

    async def start(self):
        """启动服务器"""
        self._running = True

        self._server = await asyncio.start_server(
            self._handle_tcp_client,
            self._host,
            self._port
        )

        self._udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._udp_socket.bind((self._host, self._port))
        self._udp_socket.setblocking(False)

        asyncio.create_task(self._handle_udp_clients())

        logger.info(f"Proxy server started on {self._host}:{self._port}")

        async with self._server:
            await self._server.serve_forever()

    async def stop(self):
        """停止服务器"""
        self._running = False
        self._tcp_forwarder.stop()
        self._udp_forwarder.stop()

        if self._server:
            self._server.close()
            await self._server.wait_closed()

        if self._udp_socket:
            self._udp_socket.close()

        logger.info("Proxy server stopped")

    async def _handle_tcp_client(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter
    ):
        """处理TCP客户端连接"""
        addr = writer.get_extra_info('peername')
        conn_id = f"tcp_{addr[0]}_{addr[1]}_{time.time()}"

        print(f"New TCP connection from {addr}")

        conn = ClientConnection(
            conn_id=conn_id,
            user_id="",
            remote_addr=addr,
            tcp_reader=reader,
            tcp_writer=writer,
            state=ConnectionState.CONNECTING
        )
        conn.stats.connect_time = time.time()
        conn.stats.last_activity = time.time()

        print(f"Created client connection: {conn_id}")
        
        added = await self._connection_manager.add_connection(conn)
        print(f"Added connection to manager: {added}")

        try:
            print(f"Starting to process TCP connection: {conn_id}")
            await self._process_tcp_connection(conn)
            print(f"Finished processing TCP connection: {conn_id}")
        except Exception as e:
            print(f"TCP connection error: {e}")
        finally:
            print(f"Removing connection: {conn_id}")
            await self._connection_manager.remove_connection(conn_id)
            try:
                writer.close()
                await writer.wait_closed()
                print(f"Closed connection: {conn_id}")
            except Exception as e:
                print(f"Error closing connection: {e}")

    async def _process_tcp_connection(self, conn: ClientConnection):
        """处理TCP连接"""
        raise NotImplementedError("Subclasses must implement _process_tcp_connection")

    async def _handle_udp_clients(self):
        """处理UDP客户端"""
        loop = asyncio.get_event_loop()
        while self._running:
            try:
                data, addr = await loop.sock_recvfrom(
                    self._udp_socket, UDP_BUFFER_SIZE
                )
                asyncio.create_task(self._process_udp_datagram(data, addr))
            except Exception as e:
                if self._running:
                    logger.debug(f"UDP receive error: {e}")

    async def _process_udp_datagram(self, data: bytes, addr: tuple):
        """处理UDP数据报"""
        raise NotImplementedError("Subclasses must implement _process_udp_datagram")
