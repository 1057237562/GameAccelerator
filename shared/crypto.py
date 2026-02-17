"""
Encryption Module
AES-256-GCM加密模块
提供安全的数据加密和解密功能
"""

import os
import hashlib
import secrets
import hmac
from typing import Tuple, Optional
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

from shared.constants import ENCRYPTION_KEY_SIZE, AES_BLOCK_SIZE


class EncryptionError(Exception):
    """加密相关错误"""
    pass


class CryptoManager:
    """
    加密管理器
    使用AES-256-GCM进行数据加密
    """

    NONCE_SIZE = 12
    TAG_SIZE = 16
    KEY_SIZE = ENCRYPTION_KEY_SIZE
    SALT_SIZE = 32

    def __init__(self, key: Optional[bytes] = None):
        """
        初始化加密管理器
        
        Args:
            key: 加密密钥，如果不提供则自动生成
        """
        if key is None:
            self._key = secrets.token_bytes(self.KEY_SIZE)
        else:
            if len(key) != self.KEY_SIZE:
                raise EncryptionError(f"Key must be {self.KEY_SIZE} bytes")
            self._key = key
        self._aesgcm = AESGCM(self._key)

    @property
    def key(self) -> bytes:
        """获取加密密钥"""
        return self._key

    @staticmethod
    def generate_key() -> bytes:
        """生成随机加密密钥"""
        return secrets.token_bytes(CryptoManager.KEY_SIZE)

    @staticmethod
    def derive_key(password: str, salt: Optional[bytes] = None) -> Tuple[bytes, bytes]:
        """
        从密码派生加密密钥
        
        Args:
            password: 用户密码
            salt: 盐值，如果不提供则自动生成
            
        Returns:
            (key, salt) 元组
        """
        if salt is None:
            salt = secrets.token_bytes(CryptoManager.SALT_SIZE)
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=CryptoManager.KEY_SIZE,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = kdf.derive(password.encode('utf-8'))
        return key, salt

    def encrypt(self, plaintext: bytes, associated_data: Optional[bytes] = None) -> bytes:
        """
        加密数据
        
        Args:
            plaintext: 明文数据
            associated_data: 关联数据（用于认证但不加密）
            
        Returns:
            加密后的数据（nonce + ciphertext + tag）
        """
        nonce = secrets.token_bytes(self.NONCE_SIZE)
        ciphertext = self._aesgcm.encrypt(nonce, plaintext, associated_data)
        return nonce + ciphertext

    def decrypt(self, ciphertext: bytes, associated_data: Optional[bytes] = None) -> bytes:
        """
        解密数据
        
        Args:
            ciphertext: 加密数据（nonce + ciphertext + tag）
            associated_data: 关联数据
            
        Returns:
            解密后的明文
            
        Raises:
            EncryptionError: 解密失败
        """
        if len(ciphertext) < self.NONCE_SIZE + self.TAG_SIZE:
            raise EncryptionError("Ciphertext too short")
        
        nonce = ciphertext[:self.NONCE_SIZE]
        ct = ciphertext[self.NONCE_SIZE:]
        
        try:
            plaintext = self._aesgcm.decrypt(nonce, ct, associated_data)
            return plaintext
        except Exception as e:
            raise EncryptionError(f"Decryption failed: {e}")

    def encrypt_packet(self, data: bytes, sequence: int = 0) -> bytes:
        """
        加密网络数据包
        
        Args:
            data: 原始数据
            sequence: 序列号（用于防重放）
            
        Returns:
            加密后的数据包
        """
        associated_data = sequence.to_bytes(8, 'big')
        return self.encrypt(data, associated_data)

    def decrypt_packet(self, data: bytes, sequence: int = 0) -> bytes:
        """
        解密网络数据包
        
        Args:
            data: 加密数据包
            sequence: 序列号
            
        Returns:
            解密后的原始数据
        """
        associated_data = sequence.to_bytes(8, 'big')
        return self.decrypt(data, associated_data)


class HandshakeCrypto:
    """
    握手加密模块
    用于客户端和服务端之间的初始密钥交换
    """

    CHALLENGE_SIZE = 32

    @staticmethod
    def generate_challenge() -> bytes:
        """生成挑战码"""
        return secrets.token_bytes(HandshakeCrypto.CHALLENGE_SIZE)

    @staticmethod
    def create_session_key(client_key: bytes, server_key: bytes, challenge: bytes) -> bytes:
        """
        创建会话密钥
        
        Args:
            client_key: 客户端密钥
            server_key: 服务端密钥
            challenge: 挑战码
            
        Returns:
            会话密钥
        """
        combined = client_key + server_key + challenge
        return hashlib.sha256(combined).digest()

    @staticmethod
    def verify_challenge_response(challenge: bytes, response: bytes, key: bytes) -> bool:
        """
        验证挑战响应
        
        Args:
            challenge: 原始挑战码
            response: 响应数据
            key: 密钥
            
        Returns:
            验证是否成功
        """
        expected = hmac.new(key, challenge, hashlib.sha256).digest()
        return hmac.compare_digest(expected, response)

    @staticmethod
    def create_challenge_response(challenge: bytes, key: bytes) -> bytes:
        """
        创建挑战响应
        
        Args:
            challenge: 挑战码
            key: 密钥
            
        Returns:
            响应数据
        """
        return hmac.new(key, challenge, hashlib.sha256).digest()


class SecureChannel:
    """
    安全通道
    管理加密通信的完整流程
    """

    def __init__(self):
        self._crypto: Optional[CryptoManager] = None
        self._sequence = 0
        self._is_established = False

    @property
    def is_established(self) -> bool:
        """通道是否已建立"""
        return self._is_established

    def establish(self, session_key: bytes):
        """
        建立安全通道
        
        Args:
            session_key: 会话密钥
        """
        self._crypto = CryptoManager(session_key)
        self._sequence = 0
        self._is_established = True

    def close(self):
        """关闭安全通道"""
        self._crypto = None
        self._sequence = 0
        self._is_established = False

    def send(self, data: bytes) -> bytes:
        """
        发送加密数据
        
        Args:
            data: 原始数据
            
        Returns:
            加密数据
        """
        if not self._is_established or self._crypto is None:
            raise EncryptionError("Secure channel not established")
        
        encrypted = self._crypto.encrypt_packet(data, self._sequence)
        self._sequence += 1
        return encrypted

    def receive(self, data: bytes) -> bytes:
        """
        接收并解密数据
        
        Args:
            data: 加密数据
            
        Returns:
            原始数据
        """
        if not self._is_established or self._crypto is None:
            raise EncryptionError("Secure channel not established")
        
        decrypted = self._crypto.decrypt_packet(data, self._sequence)
        self._sequence += 1
        return decrypted

    def reset_sequence(self):
        """重置序列号"""
        self._sequence = 0
