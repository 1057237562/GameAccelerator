"""
Test Suite for Game Accelerator
游戏加速器测试套件
"""

import pytest
import asyncio
import os
import sys
import time
import tempfile
from unittest.mock import Mock, AsyncMock, patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from shared.crypto import CryptoManager, SecureChannel, HandshakeCrypto, EncryptionError
from shared.protocol import (
    Packet, PacketHeader, MessageType, ErrorCode, PacketFlags,
    AuthRequest, AuthResponse, NodeInfo
)
from server.core.auth import (
    AuthManager, User, UserRole, UserStatus, PasswordManager, JWTManager
)
from server.core.node_manager import NodeManager, LoadBalanceStrategy, ServerNode, NodeStatus


class TestCrypto:
    """加密模块测试"""

    def test_generate_key(self):
        """测试密钥生成"""
        key = CryptoManager.generate_key()
        assert len(key) == 32

    def test_encrypt_decrypt(self):
        """测试加密解密"""
        crypto = CryptoManager()
        plaintext = b"Hello, World!"
        ciphertext = crypto.encrypt(plaintext)
        decrypted = crypto.decrypt(ciphertext)
        assert decrypted == plaintext

    def test_encrypt_with_associated_data(self):
        """测试带关联数据的加密"""
        crypto = CryptoManager()
        plaintext = b"Test data"
        associated_data = b"additional info"
        ciphertext = crypto.encrypt(plaintext, associated_data)
        decrypted = crypto.decrypt(ciphertext, associated_data)
        assert decrypted == plaintext

    def test_decrypt_with_wrong_key(self):
        """测试错误密钥解密"""
        crypto1 = CryptoManager()
        crypto2 = CryptoManager()
        plaintext = b"Secret message"
        ciphertext = crypto1.encrypt(plaintext)
        
        with pytest.raises(EncryptionError):
            crypto2.decrypt(ciphertext)

    def test_derive_key_from_password(self):
        """测试从密码派生密钥"""
        password = "my_password"
        key1, salt = CryptoManager.derive_key(password)
        key2, _ = CryptoManager.derive_key(password, salt)
        assert key1 == key2

    def test_secure_channel(self):
        """测试安全通道"""
        channel = SecureChannel()
        session_key = CryptoManager.generate_key()
        channel.establish(session_key)
        
        assert channel.is_established
        
        data = b"Secure message"
        encrypted = channel.send(data)
        decrypted = channel.receive(encrypted)
        assert decrypted == data

    def test_handshake_challenge(self):
        """测试握手挑战"""
        challenge = HandshakeCrypto.generate_challenge()
        assert len(challenge) == HandshakeCrypto.CHALLENGE_SIZE

        key = CryptoManager.generate_key()
        response = HandshakeCrypto.create_challenge_response(challenge, key)
        assert HandshakeCrypto.verify_challenge_response(challenge, response, key)


class TestProtocol:
    """协议模块测试"""

    def test_packet_header_pack_unpack(self):
        """测试数据包头打包解包"""
        header = PacketHeader(
            msg_type=MessageType.DATA,
            flags=PacketFlags.ENCRYPTED,
            payload_len=100,
            sequence=1,
            timestamp=int(time.time())
        )
        
        packed = header.pack()
        assert len(packed) == PacketHeader.HEADER_SIZE
        
        unpacked = PacketHeader.unpack(packed)
        assert unpacked is not None
        assert unpacked.msg_type == MessageType.DATA
        assert unpacked.flags == PacketFlags.ENCRYPTED
        assert unpacked.payload_len == 100

    def test_packet_create_unpack(self):
        """测试数据包创建解包"""
        payload = b"Test payload data"
        packet = Packet.create(
            msg_type=MessageType.DATA,
            payload=payload,
            flags=PacketFlags.NONE,
            sequence=1
        )
        
        packed = packet.pack()
        unpacked = Packet.unpack(packed)
        
        assert unpacked is not None
        assert unpacked.header.msg_type == MessageType.DATA
        assert unpacked.payload == payload

    def test_auth_request_serialization(self):
        """测试认证请求序列化"""
        request = AuthRequest(
            username="testuser",
            password="testpass",
            client_version="1.0.0",
            device_id="device123"
        )
        
        data = request.to_bytes()
        restored = AuthRequest.from_bytes(data)
        
        assert restored.username == request.username
        assert restored.password == request.password
        assert restored.client_version == request.client_version
        assert restored.device_id == request.device_id

    def test_auth_response_serialization(self):
        """测试认证响应序列化"""
        response = AuthResponse(
            success=True,
            error_code=ErrorCode.SUCCESS,
            token="test_token",
            refresh_token="refresh_token",
            expires_in=3600,
            message="Success"
        )
        
        data = response.to_bytes()
        restored = AuthResponse.from_bytes(data)
        
        assert restored.success == response.success
        assert restored.error_code == response.error_code
        assert restored.token == response.token


class TestAuth:
    """认证模块测试"""

    @pytest.fixture
    def temp_db(self):
        """临时数据库"""
        with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as f:
            db_path = f.name
        yield db_path
        try:
            os.unlink(db_path)
        except:
            pass

    @pytest.mark.asyncio
    async def test_password_manager(self):
        """测试密码管理器"""
        pm = PasswordManager()
        password = "test_password"
        hashed = pm.hash_password(password)
        
        assert hashed != password
        assert pm.verify_password(password, hashed)
        assert not pm.verify_password("wrong_password", hashed)

    def test_jwt_manager(self):
        """测试JWT管理器"""
        jwt_mgr = JWTManager("test_secret")
        
        token = jwt_mgr.create_access_token("user123")
        assert token is not None
        
        user_id = jwt_mgr.verify_token(token, "access")
        assert user_id == "user123"

    @pytest.mark.asyncio
    async def test_user_registration(self, temp_db):
        """测试用户注册"""
        auth_mgr = AuthManager(temp_db)
        await auth_mgr.initialize()
        
        user = await auth_mgr.register_user(
            username="testuser",
            email="test@example.com",
            password="password123"
        )
        
        assert user is not None
        assert user.username == "testuser"
        assert user.email == "test@example.com"
        assert user.role == UserRole.USER
        
        await auth_mgr.close()

    @pytest.mark.asyncio
    async def test_user_authentication(self, temp_db):
        """测试用户认证"""
        auth_mgr = AuthManager(temp_db)
        await auth_mgr.initialize()
        
        await auth_mgr.register_user("testuser", "test@example.com", "password123")
        
        token = await auth_mgr.authenticate("testuser", "password123")
        
        assert token is not None
        assert token.access_token is not None
        assert token.refresh_token is not None
        
        user = await auth_mgr.verify_access_token(token.access_token)
        assert user is not None
        assert user.username == "testuser"
        
        await auth_mgr.close()

    @pytest.mark.asyncio
    async def test_wrong_password(self, temp_db):
        """测试错误密码"""
        auth_mgr = AuthManager(temp_db)
        await auth_mgr.initialize()
        
        await auth_mgr.register_user("testuser", "test@example.com", "password123")
        
        token = await auth_mgr.authenticate("testuser", "wrongpassword")
        assert token is None
        
        await auth_mgr.close()


class TestNodeManager:
    """节点管理器测试"""

    @pytest.fixture
    def node_manager(self):
        return NodeManager(LoadBalanceStrategy.LEAST_LATENCY)

    @pytest.mark.asyncio
    async def test_register_node(self, node_manager):
        """测试注册节点"""
        await node_manager.initialize()
        
        node = await node_manager.register_node(
            name="Test Node",
            region="east_china",
            host="192.168.1.1",
            port=8388
        )
        
        assert node is not None
        assert node.name == "Test Node"
        assert node.region == "east_china"
        
        await node_manager.shutdown()

    @pytest.mark.asyncio
    async def test_get_best_node(self, node_manager):
        """测试获取最佳节点"""
        await node_manager.initialize()
        
        await node_manager.register_node("Node1", "east", "192.168.1.1", 8388)
        await node_manager.register_node("Node2", "east", "192.168.1.2", 8388)
        
        nodes = await node_manager.get_all_nodes()
        assert len(nodes) == 2
        
        best = await node_manager.get_best_node()
        assert best is not None
        
        await node_manager.shutdown()

    @pytest.mark.asyncio
    async def test_connection_tracking(self, node_manager):
        """测试连接跟踪"""
        await node_manager.initialize()
        
        node = await node_manager.register_node("Test", "east", "192.168.1.1", 8388)
        
        success = await node_manager.load_balancer.increment_connections(node.node_id)
        assert success
        
        node = await node_manager.load_balancer.get_node(node.node_id)
        assert node.current_connections == 1
        
        await node_manager.load_balancer.decrement_connections(node.node_id)
        node = await node_manager.load_balancer.get_node(node.node_id)
        assert node.current_connections == 0
        
        await node_manager.shutdown()


class TestPerformance:
    """性能测试"""

    def test_encryption_performance(self):
        """测试加密性能"""
        crypto = CryptoManager()
        data = b"x" * 1024
        
        start = time.time()
        iterations = 1000
        
        for _ in range(iterations):
            encrypted = crypto.encrypt(data)
            crypto.decrypt(encrypted)
        
        elapsed = time.time() - start
        ops_per_sec = iterations / elapsed
        
        print(f"\nEncryption/Decryption: {ops_per_sec:.2f} ops/sec")
        assert ops_per_sec > 100

    def test_packet_packing_performance(self):
        """测试数据包打包性能"""
        payload = b"x" * 1024
        
        start = time.time()
        iterations = 10000
        
        for i in range(iterations):
            packet = Packet.create(
                msg_type=MessageType.DATA,
                payload=payload,
                sequence=i
            )
            packed = packet.pack()
            Packet.unpack(packed)
        
        elapsed = time.time() - start
        ops_per_sec = iterations / elapsed
        
        print(f"\nPacket Packing/Unpacking: {ops_per_sec:.2f} ops/sec")
        assert ops_per_sec > 1000


def run_tests():
    """运行测试"""
    pytest.main([__file__, "-v", "-s"])


if __name__ == "__main__":
    run_tests()
