"""
Game Accelerator Server Main Module
游戏加速器服务端主程序
"""

import asyncio
import signal
import os
import sys
import logging
from typing import Optional
from datetime import datetime

from server.core.auth import AuthManager, UserRole
from server.core.forwarder import (
    ProxyServer, ConnectionManager, ClientConnection, ConnectionState
)
from server.core.node_manager import NodeManager, LoadBalanceStrategy
from server.core.monitoring import MonitoringService
from shared.constants import DEFAULT_SERVER_HOST, DEFAULT_SERVER_PORT, DEFAULT_API_PORT
from shared.protocol import (
    Packet, PacketHeader, MessageType, ErrorCode, PacketFlags,
    AuthRequest, AuthResponse
)
from shared.crypto import SecureChannel, HandshakeCrypto, CryptoManager


logger = logging.getLogger(__name__)


class GameAcceleratorServer(ProxyServer):
    """游戏加速器服务器"""

    def __init__(
        self,
        host: str = DEFAULT_SERVER_HOST,
        port: int = DEFAULT_SERVER_PORT,
        api_port: int = DEFAULT_API_PORT,
        max_connections: int = 2000,
        jwt_secret: Optional[str] = None,
        db_path: str = "data/users.db"
    ):
        super().__init__(host, port, max_connections)
        
        self._api_port = api_port
        self._auth_manager = AuthManager(db_path, jwt_secret)
        self._node_manager = NodeManager(LoadBalanceStrategy.LEAST_LATENCY)
        self._monitoring = MonitoringService()
        self._handshake_crypto = HandshakeCrypto()
        self._sessions: dict = {}
        self._api_server: Optional[asyncio.Server] = None

    async def start(self):
        """启动服务器"""
        await self._auth_manager.initialize()
        await self._node_manager.initialize()
        await self._monitoring.start()

        self._api_server = await asyncio.start_server(
            self._handle_api_client,
            self._host,
            self._api_port
        )

        logger.info(f"API server started on {self._host}:{self._api_port}")

        await self._load_default_nodes()

        await super().start()

    async def stop(self):
        """停止服务器"""
        await super().stop()

        if self._api_server:
            self._api_server.close()
            await self._api_server.wait_closed()

        await self._node_manager.shutdown()
        await self._auth_manager.close()
        await self._monitoring.stop()

        logger.info("Server stopped")

    async def _load_default_nodes(self):
        """加载默认节点"""
        default_nodes = [
            {
                "name": "华东节点-1",
                "region": "east_china",
                "host": "127.0.0.1",
                "port": 8389,
                "max_connections": 500,
            },
            {
                "name": "华南节点-1",
                "region": "south_china",
                "host": "127.0.0.1",
                "port": 8390,
                "max_connections": 500,
            },
            {
                "name": "华北节点-1",
                "region": "north_china",
                "host": "127.0.0.1",
                "port": 8391,
                "max_connections": 500,
            },
        ]

        for node_config in default_nodes:
            await self._node_manager.register_node(**node_config)

    async def _handle_api_client(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter
    ):
        """处理API客户端连接"""
        addr = writer.get_extra_info('peername')
        logger.debug(f"API client connected: {addr}")

        try:
            while self._running:
                data = await reader.readline()
                if not data:
                    break

                try:
                    import json
                    request = json.loads(data.decode('utf-8'))
                    response = await self._handle_api_request(request)
                    writer.write((json.dumps(response) + "\n").encode('utf-8'))
                    await writer.drain()
                except json.JSONDecodeError:
                    writer.write(b'{"error": "Invalid JSON"}\n')
                    await writer.drain()
        except Exception as e:
            logger.debug(f"API client error: {e}")
        finally:
            writer.close()
            await writer.wait_closed()
            logger.debug(f"API client disconnected: {addr}")

    async def _handle_api_request(self, request: dict) -> dict:
        """处理API请求"""
        action = request.get("action", "")
        
        if action == "get_nodes":
            nodes = await self._node_manager.get_node_list_for_client()
            return {
                "success": True,
                "nodes": [n.__dict__ for n in nodes]
            }
        
        elif action == "get_stats":
            return {
                "success": True,
                "stats": self._monitoring.get_full_status()
            }
        
        elif action == "register_user":
            username = request.get("username")
            email = request.get("email")
            password = request.get("password")
            if not all([username, email, password]):
                return {"success": False, "error": "Missing fields"}
            
            user = await self._auth_manager.register_user(username, email, password)
            if user:
                return {"success": True, "user_id": user.user_id}
            return {"success": False, "error": "Registration failed"}
        
        elif action == "create_admin":
            username = request.get("username")
            email = request.get("email")
            password = request.get("password")
            if not all([username, email, password]):
                return {"success": False, "error": "Missing fields"}
            
            user = await self._auth_manager.register_user(
                username, email, password, UserRole.ADMIN
            )
            if user:
                return {"success": True, "user_id": user.user_id}
            return {"success": False, "error": "Admin creation failed"}
        
        else:
            return {"success": False, "error": "Unknown action"}

    async def _process_tcp_connection(self, conn: ClientConnection):
        """处理TCP连接"""
        try:
            while True:
                packet_data = await asyncio.wait_for(
                    conn.tcp_reader.read(8192),
                    timeout=90
                )
                if not packet_data:
                    break

                packet = Packet.unpack(packet_data)
                if packet is None:
                    logger.warning(f"Invalid packet from {conn.remote_addr}")
                    continue

                if packet.header.msg_type == MessageType.HANDSHAKE:
                    await self._handle_handshake(conn, packet)
                elif packet.header.msg_type == MessageType.AUTH_REQUEST:
                    await self._handle_auth(conn, packet)
                elif packet.header.msg_type == MessageType.DATA:
                    await self._handle_data(conn, packet)
                elif packet.header.msg_type == MessageType.HEARTBEAT:
                    await self._handle_heartbeat(conn, packet)
                elif packet.header.msg_type == MessageType.DISCONNECT:
                    await self._handle_disconnect(conn, packet)
                    break
                elif packet.header.msg_type == MessageType.NODE_LIST_REQUEST:
                    await self._handle_node_list_request(conn, packet)

        except asyncio.TimeoutError:
            logger.debug(f"Connection timeout: {conn.conn_id}")
        except Exception as e:
            logger.error(f"Connection error: {e}")

    async def _handle_handshake(self, conn: ClientConnection, packet: Packet):
        """处理握手"""
        conn.state = ConnectionState.CONNECTING

        challenge = self._handshake_crypto.generate_challenge()
        self._sessions[conn.conn_id] = {
            "challenge": challenge,
            "state": "handshake"
        }

        response_packet = Packet.create(
            msg_type=MessageType.HANDSHAKE_ACK,
            payload=challenge,
            sequence=0
        )
        conn.tcp_writer.write(response_packet.pack())
        await conn.tcp_writer.drain()

    async def _handle_auth(self, conn: ClientConnection, packet: Packet):
        """处理认证"""
        try:
            auth_request = AuthRequest.from_bytes(packet.payload)
            
            token = await self._auth_manager.authenticate(
                auth_request.username,
                auth_request.password,
                auth_request.device_id,
                conn.remote_addr[0]
            )

            if token is None:
                response = AuthResponse(
                    success=False,
                    error_code=ErrorCode.AUTH_FAILED,
                    token="",
                    refresh_token="",
                    expires_in=0,
                    message="Authentication failed"
                )
            else:
                user = await self._auth_manager.get_user(token.user_id)
                if user and user.can_connect():
                    conn.user_id = token.user_id
                    conn.state = ConnectionState.CONNECTED
                    
                    session_key = CryptoManager.generate_key()
                    conn.secure_channel = SecureChannel()
                    conn.secure_channel.establish(session_key)

                    await self._auth_manager.increment_connections(token.user_id)

                    response = AuthResponse(
                        success=True,
                        error_code=ErrorCode.SUCCESS,
                        token=token.access_token,
                        refresh_token=token.refresh_token,
                        expires_in=int((token.expires_at - datetime.now()).total_seconds()),
                        message="Authentication successful"
                    )

                    self._monitoring.metrics.update_server_metrics(
                        active_connections=self._connection_manager.connection_count
                    )

                    await self._monitoring.audit.log_login(
                        token.user_id, conn.remote_addr[0], True
                    )
                else:
                    response = AuthResponse(
                        success=False,
                        error_code=ErrorCode.CONNECTION_REFUSED,
                        token="",
                        refresh_token="",
                        expires_in=0,
                        message="Connection limit reached or user inactive"
                    )

            response_packet = Packet.create(
                msg_type=MessageType.AUTH_RESPONSE,
                payload=response.to_bytes(),
                sequence=0
            )
            conn.tcp_writer.write(response_packet.pack())
            await conn.tcp_writer.drain()

        except Exception as e:
            logger.error(f"Auth error: {e}")

    async def _handle_data(self, conn: ClientConnection, packet: Packet):
        """处理数据"""
        if conn.state != ConnectionState.CONNECTED:
            return

        conn.update_activity()

        if packet.header.flags & PacketFlags.ENCRYPTED and conn.secure_channel:
            try:
                payload = conn.secure_channel.receive(packet.payload)
            except Exception:
                return
        else:
            payload = packet.payload

        target_host = "127.0.0.1"
        target_port = 80

        self._monitoring.metrics.update_server_metrics(
            bytes_in=len(payload),
            packets_in=1
        )

    async def _handle_heartbeat(self, conn: ClientConnection, packet: Packet):
        """处理心跳"""
        conn.update_activity()
        
        response_packet = Packet.create(
            msg_type=MessageType.HEARTBEAT_ACK,
            payload=b"",
            sequence=packet.header.sequence
        )
        conn.tcp_writer.write(response_packet.pack())
        await conn.tcp_writer.drain()

    async def _handle_disconnect(self, conn: ClientConnection, packet: Packet):
        """处理断开连接"""
        await self._cleanup_connection(conn)

    async def _handle_node_list_request(self, conn: ClientConnection, packet: Packet):
        """处理节点列表请求"""
        nodes = await self._node_manager.get_node_list_for_client()
        
        import json
        payload = json.dumps([n.__dict__ for n in nodes]).encode('utf-8')
        
        response_packet = Packet.create(
            msg_type=MessageType.NODE_LIST_RESPONSE,
            payload=payload,
            sequence=packet.header.sequence
        )
        conn.tcp_writer.write(response_packet.pack())
        await conn.tcp_writer.drain()

    async def _process_udp_datagram(self, data: bytes, addr: tuple):
        """处理UDP数据报"""
        pass

    async def _cleanup_connection(self, conn: ClientConnection):
        """清理连接"""
        if conn.user_id:
            await self._auth_manager.decrement_connections(conn.user_id)
            await self._monitoring.audit.log_logout(
                conn.user_id, conn.remote_addr[0]
            )

        if conn.conn_id in self._sessions:
            del self._sessions[conn.conn_id]

        self._monitoring.metrics.update_server_metrics(
            active_connections=self._connection_manager.connection_count - 1
        )


async def main():
    """主函数"""
    import argparse
    from dotenv import load_dotenv

    load_dotenv()

    parser = argparse.ArgumentParser(description="Game Accelerator Server")
    parser.add_argument("--host", default=os.getenv("SERVER_HOST", DEFAULT_SERVER_HOST))
    parser.add_argument("--port", type=int, default=int(os.getenv("SERVER_PORT", DEFAULT_SERVER_PORT)))
    parser.add_argument("--api-port", type=int, default=int(os.getenv("API_PORT", DEFAULT_API_PORT)))
    parser.add_argument("--max-connections", type=int, default=int(os.getenv("MAX_CONNECTIONS", 2000)))
    parser.add_argument("--jwt-secret", default=os.getenv("JWT_SECRET"))
    parser.add_argument("--db-path", default=os.getenv("DB_PATH", "data/users.db"))

    args = parser.parse_args()

    os.makedirs(os.path.dirname(args.db_path), exist_ok=True)

    server = GameAcceleratorServer(
        host=args.host,
        port=args.port,
        api_port=args.api_port,
        max_connections=args.max_connections,
        jwt_secret=args.jwt_secret,
        db_path=args.db_path
    )

    loop = asyncio.get_event_loop()

    def signal_handler():
        logger.info("Received shutdown signal")
        asyncio.create_task(server.stop())

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, signal_handler)
        except NotImplementedError:
            pass

    try:
        await server.start()
    except KeyboardInterrupt:
        logger.info("Server interrupted")
    finally:
        await server.stop()


if __name__ == "__main__":
    asyncio.run(main())
