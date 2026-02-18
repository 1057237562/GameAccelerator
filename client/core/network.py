"""
Client Network Connection Module
客户端网络连接模块
"""

import asyncio
import socket
import time
import logging
from typing import Optional, Dict, Any, Callable, List
from dataclasses import dataclass, field
from enum import IntEnum
from datetime import datetime
import json

from shared.constants import TCP_BUFFER_SIZE, UDP_BUFFER_SIZE, HEARTBEAT_INTERVAL
from shared.protocol import (
    Packet, PacketHeader, MessageType, ErrorCode, PacketFlags,
    AuthRequest, AuthResponse, NodeInfo, ConnectRequest, ConnectResponse
)
from shared.crypto import SecureChannel, CryptoManager, HandshakeCrypto

logger = logging.getLogger(__name__)


class ConnectionState(IntEnum):
    DISCONNECTED = 0
    CONNECTING = 1
    AUTHENTICATING = 2
    CONNECTED = 3
    RECONNECTING = 4
    ERROR = 5


@dataclass
class ConnectionConfig:
    """连接配置"""
    server_host: str = "127.0.0.1"
    server_port: int = 8388
    username: str = ""
    password: str = ""
    device_id: str = ""
    auto_reconnect: bool = True
    max_reconnect_attempts: int = 5
    reconnect_delay: float = 1.0
    heartbeat_interval: int = HEARTBEAT_INTERVAL
    timeout: int = 30


@dataclass
class ConnectionStats:
    """连接统计"""
    bytes_sent: int = 0
    bytes_received: int = 0
    packets_sent: int = 0
    packets_received: int = 0
    connect_time: float = 0
    last_activity: float = 0
    latency_ms: float = 0
    reconnect_count: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "bytes_sent": self.bytes_sent,
            "bytes_received": self.bytes_received,
            "packets_sent": self.packets_sent,
            "packets_received": self.packets_received,
            "connect_time": self.connect_time,
            "last_activity": self.last_activity,
            "latency_ms": self.latency_ms,
            "reconnect_count": self.reconnect_count,
        }


class NetworkClient:
    """网络客户端"""

    def __init__(self, config: ConnectionConfig):
        self._config = config
        self._state = ConnectionState.DISCONNECTED
        self._reader: Optional[asyncio.StreamReader] = None
        self._writer: Optional[asyncio.StreamWriter] = None
        self._secure_channel: Optional[SecureChannel] = None
        self._handshake_crypto = HandshakeCrypto()
        self._session_key: Optional[bytes] = None
        self._token: Optional[str] = None
        self._refresh_token: Optional[str] = None
        self._stats = ConnectionStats()
        self._sequence = 0
        self._heartbeat_task: Optional[asyncio.Task] = None
        self._receive_task: Optional[asyncio.Task] = None
        self._reconnect_attempts = 0
        self._state_callbacks: List[Callable] = []
        self._data_callbacks: List[Callable] = []
        self._running = False
        self._lock = asyncio.Lock()

    @property
    def state(self) -> ConnectionState:
        return self._state

    @property
    def is_connected(self) -> bool:
        return self._state == ConnectionState.CONNECTED

    @property
    def stats(self) -> ConnectionStats:
        return self._stats

    @property
    def token(self) -> Optional[str]:
        return self._token

    def add_state_callback(self, callback: Callable):
        """添加状态变化回调"""
        self._state_callbacks.append(callback)

    def add_data_callback(self, callback: Callable):
        """添加数据回调"""
        self._data_callbacks.append(callback)

    async def connect(self) -> bool:
        """连接服务器"""
        if self._state == ConnectionState.CONNECTED:
            return True

        self._set_state(ConnectionState.CONNECTING)

        try:
            self._reader, self._writer = await asyncio.wait_for(
                asyncio.open_connection(
                    self._config.server_host,
                    self._config.server_port
                ),
                timeout=self._config.timeout
            )

            if not await self._perform_handshake():
                await self._disconnect()
                return False

            if not await self._authenticate():
                await self._disconnect()
                return False

            self._stats.connect_time = time.time()
            self._stats.last_activity = time.time()
            self._running = True

            self._heartbeat_task = asyncio.create_task(self._heartbeat_loop())
            self._receive_task = asyncio.create_task(self._receive_loop())

            self._set_state(ConnectionState.CONNECTED)
            self._reconnect_attempts = 0

            logger.info(f"Connected to {self._config.server_host}:{self._config.server_port}")
            return True

        except asyncio.TimeoutError:
            logger.error("Connection timeout")
            self._set_state(ConnectionState.ERROR)
            return False
        except Exception as e:
            logger.error(f"Connection failed: {e}")
            self._set_state(ConnectionState.ERROR)
            return False

    async def disconnect(self):
        """断开连接"""
        await self._disconnect()

    async def _disconnect(self):
        """内部断开连接"""
        self._running = False

        if self._heartbeat_task:
            self._heartbeat_task.cancel()
            try:
                await self._heartbeat_task
            except asyncio.CancelledError:
                pass
            self._heartbeat_task = None

        if self._receive_task:
            self._receive_task.cancel()
            try:
                await self._receive_task
            except asyncio.CancelledError:
                pass
            self._receive_task = None

        if self._writer:
            try:
                self._writer.close()
                await self._writer.wait_closed()
            except Exception:
                pass
            self._writer = None
            self._reader = None

        self._secure_channel = None
        self._set_state(ConnectionState.DISCONNECTED)

    async def _perform_handshake(self) -> bool:
        """执行握手"""
        try:
            handshake_packet = Packet.create(
                msg_type=MessageType.HANDSHAKE,
                payload=b"",
                sequence=0
            )
            self._writer.write(handshake_packet.pack())
            await self._writer.drain()

            response_data = await asyncio.wait_for(
                self._reader.read(1024),
                timeout=self._config.timeout
            )

            response = Packet.unpack(response_data)
            if response is None or response.header.msg_type != MessageType.HANDSHAKE_ACK:
                logger.error("Invalid handshake response")
                return False

            challenge = response.payload
            self._session_key = CryptoManager.generate_key()
            self._secure_channel = SecureChannel()
            self._secure_channel.establish(self._session_key)

            return True

        except Exception as e:
            logger.error(f"Handshake failed: {e}")
            return False

    async def _authenticate(self) -> bool:
        """执行认证"""
        self._set_state(ConnectionState.AUTHENTICATING)

        auth_request = AuthRequest(
            username=self._config.username,
            password=self._config.password,
            client_version="1.0.0",
            device_id=self._config.device_id
        )

        auth_packet = Packet.create(
            msg_type=MessageType.AUTH_REQUEST,
            payload=auth_request.to_bytes(),
            sequence=0
        )

        self._writer.write(auth_packet.pack())
        await self._writer.drain()

        try:
            response_data = await asyncio.wait_for(
                self._reader.read(1024),
                timeout=self._config.timeout
            )

            response = Packet.unpack(response_data)
            if response is None or response.header.msg_type != MessageType.AUTH_RESPONSE:
                logger.error("Invalid auth response")
                return False

            auth_response = AuthResponse.from_bytes(response.payload)
            if not auth_response.success:
                logger.error(f"Authentication failed: {auth_response.message}")
                return False

            self._token = auth_response.token
            self._refresh_token = auth_response.refresh_token

            return True

        except Exception as e:
            logger.error(f"Authentication failed: {e}")
            return False

    async def _heartbeat_loop(self):
        """心跳循环"""
        while self._running:
            try:
                await asyncio.sleep(self._config.heartbeat_interval)

                if not self._running or self._state != ConnectionState.CONNECTED:
                    break

                heartbeat_packet = Packet.create(
                    msg_type=MessageType.HEARTBEAT,
                    payload=b"",
                    sequence=self._sequence
                )
                self._sequence += 1

                self._writer.write(heartbeat_packet.pack())
                await self._writer.drain()

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.debug(f"Heartbeat error: {e}")
                if self._config.auto_reconnect:
                    await self._reconnect()
                break

    async def _receive_loop(self):
        """接收循环"""
        while self._running:
            try:
                data = await self._reader.read(TCP_BUFFER_SIZE)
                if not data:
                    logger.debug("Connection closed by server")
                    if self._config.auto_reconnect:
                        await self._reconnect()
                    break

                packet = Packet.unpack(data)
                if packet:
                    await self._handle_packet(packet)

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.debug(f"Receive error: {e}")
                if self._config.auto_reconnect and self._running:
                    await self._reconnect()
                break

    async def _handle_packet(self, packet: Packet):
        """处理数据包"""
        self._stats.last_activity = time.time()
        self._stats.packets_received += 1

        if packet.header.msg_type == MessageType.HEARTBEAT_ACK:
            latency = (time.time() - packet.header.timestamp) * 1000
            self._stats.latency_ms = latency

        elif packet.header.msg_type == MessageType.DATA:
            payload = packet.payload
            if packet.header.flags & PacketFlags.ENCRYPTED and self._secure_channel:
                try:
                    payload = self._secure_channel.receive(payload)
                except Exception:
                    return

            self._stats.bytes_received += len(packet.pack())

            for callback in self._data_callbacks:
                try:
                    await callback(payload, packet.header)
                except Exception as e:
                    logger.error(f"Data callback error: {e}")

        elif packet.header.msg_type == MessageType.NODE_LIST_RESPONSE:
            nodes_data = json.loads(packet.payload.decode('utf-8'))
            for callback in self._data_callbacks:
                try:
                    await callback({"type": "node_list", "nodes": nodes_data}, packet.header)
                except Exception as e:
                    logger.error(f"Node list callback error: {e}")

        elif packet.header.msg_type == MessageType.ERROR:
            error_code = ErrorCode(packet.header.flags)
            logger.error(f"Server error: {error_code}")

    async def send_data(self, data: bytes, encrypt: bool = True) -> bool:
        """发送数据"""
        if not self.is_connected or self._writer is None:
            return False

        try:
            payload = data
            flags = 0

            if encrypt and self._secure_channel:
                payload = self._secure_channel.send(data)
                flags |= PacketFlags.ENCRYPTED

            packet = Packet.create(
                msg_type=MessageType.DATA,
                payload=payload,
                flags=flags,
                sequence=self._sequence
            )
            self._sequence += 1

            packed_data = packet.pack()
            self._writer.write(packed_data)
            await self._writer.drain()

            self._stats.bytes_sent += len(packed_data)
            self._stats.packets_sent += 1

            return True

        except Exception as e:
            logger.error(f"Send error: {e}")
            return False

    async def request_node_list(self) -> Optional[List[NodeInfo]]:
        """请求节点列表"""
        if not self.is_connected or self._writer is None:
            return None

        try:
            packet = Packet.create(
                msg_type=MessageType.NODE_LIST_REQUEST,
                payload=b"",
                sequence=self._sequence
            )
            self._sequence += 1

            self._writer.write(packet.pack())
            await self._writer.drain()

            return None

        except Exception as e:
            logger.error(f"Request node list error: {e}")
            return None

    async def connect_to_target(self, target_host: str, target_port: int) -> bool:
        """
        连接到目标服务器
        通过加速器服务器建立到目标的连接
        """
        if not self.is_connected or self._writer is None:
            logger.error("[Client] Not connected to accelerator server")
            return False

        try:
            connect_request = ConnectRequest(
                target_host=target_host,
                target_port=target_port
            )
            
            packet = Packet.create(
                msg_type=MessageType.CONNECT,
                payload=connect_request.to_bytes(),
                sequence=self._sequence
            )
            self._sequence += 1

            self._writer.write(packet.pack())
            await self._writer.drain()
            
            logger.info(f"[Client] Sent CONNECT request for {target_host}:{target_port}")

            # 等待响应
            response_data = await asyncio.wait_for(
                self._reader.read(1024),
                timeout=self._config.timeout
            )

            response = Packet.unpack(response_data)
            if response is None:
                logger.error("[Client] Invalid CONNECT response")
                return False

            if response.header.msg_type == MessageType.CONNECT_ACK:
                connect_response = ConnectResponse.from_bytes(response.payload)
                if connect_response.success:
                    logger.info(f"[Client] Connected to {target_host}:{target_port} via accelerator")
                    return True
                else:
                    logger.error(f"[Client] Connect failed: {connect_response.message}")
                    return False
            elif response.header.msg_type == MessageType.CONNECT_FAILED:
                connect_response = ConnectResponse.from_bytes(response.payload)
                logger.error(f"[Client] Connect failed: {connect_response.message}")
                return False
            else:
                logger.error(f"[Client] Unexpected response type: {response.header.msg_type}")
                return False

        except asyncio.TimeoutError:
            logger.error("[Client] Connect timeout")
            return False
        except Exception as e:
            logger.error(f"[Client] Connect to target error: {e}")
            return False

    async def _reconnect(self):
        """重连"""
        if self._reconnect_attempts >= self._config.max_reconnect_attempts:
            logger.error("Max reconnect attempts reached")
            self._set_state(ConnectionState.ERROR)
            return

        self._set_state(ConnectionState.RECONNECTING)
        self._reconnect_attempts += 1
        self._stats.reconnect_count += 1

        delay = self._config.reconnect_delay * (2 ** (self._reconnect_attempts - 1))
        logger.info(f"Reconnecting in {delay}s (attempt {self._reconnect_attempts})")

        await asyncio.sleep(delay)

        await self._disconnect()

        if await self.connect():
            logger.info("Reconnected successfully")
        else:
            if self._config.auto_reconnect:
                await self._reconnect()

    def _set_state(self, state: ConnectionState):
        """设置状态"""
        old_state = self._state
        self._state = state

        for callback in self._state_callbacks:
            try:
                callback(old_state, state)
            except Exception as e:
                logger.error(f"State callback error: {e}")

    async def test_connection(self) -> Dict[str, Any]:
        """测试连接"""
        result = {
            "success": False,
            "latency_ms": 0,
            "error": None
        }

        try:
            start_time = time.time()
            
            test_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            test_socket.settimeout(5)
            test_socket.connect((self._config.server_host, self._config.server_port))
            test_socket.close()

            result["latency_ms"] = (time.time() - start_time) * 1000
            result["success"] = True

        except Exception as e:
            result["error"] = str(e)

        return result


class UDPClient:
    """UDP客户端"""

    def __init__(self, server_host: str, server_port: int):
        self._server_host = server_host
        self._server_port = server_port
        self._socket: Optional[socket.socket] = None
        self._running = False

    async def start(self):
        """启动UDP客户端"""
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._socket.setblocking(False)
        self._running = True

    async def stop(self):
        """停止UDP客户端"""
        self._running = False
        if self._socket:
            self._socket.close()
            self._socket = None

    async def send(self, data: bytes) -> bool:
        """发送UDP数据"""
        if not self._socket:
            return False

        try:
            loop = asyncio.get_event_loop()
            await loop.sock_sendto(
                self._socket,
                data,
                (self._server_host, self._server_port)
            )
            return True
        except Exception as e:
            logger.error(f"UDP send error: {e}")
            return False

    async def receive(self, buffer_size: int = UDP_BUFFER_SIZE) -> Optional[bytes]:
        """接收UDP数据"""
        if not self._socket:
            return None

        try:
            loop = asyncio.get_event_loop()
            data, addr = await loop.sock_recvfrom(self._socket, buffer_size)
            return data
        except Exception as e:
            logger.error(f"UDP receive error: {e}")
            return None
