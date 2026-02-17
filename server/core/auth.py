"""
User Authentication and Authorization Module
用户认证与授权模块
"""

import os
import time
import secrets
import hashlib
import asyncio
import aiosqlite
from typing import Optional, Dict, Any, List
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import IntEnum
import jwt
from passlib.context import CryptContext

from shared.constants import AUTH_TOKEN_EXPIRE, REFRESH_TOKEN_EXPIRE


class UserRole(IntEnum):
    GUEST = 0
    USER = 1
    VIP = 2
    ADMIN = 3


class UserStatus(IntEnum):
    INACTIVE = 0
    ACTIVE = 1
    SUSPENDED = 2
    BANNED = 3


@dataclass
class User:
    """用户数据模型"""
    user_id: str
    username: str
    email: str
    password_hash: str
    role: UserRole = UserRole.USER
    status: UserStatus = UserStatus.ACTIVE
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)
    expires_at: Optional[datetime] = None
    max_connections: int = 2
    current_connections: int = 0
    bandwidth_limit: int = 0
    traffic_used: int = 0
    traffic_limit: int = 0
    metadata: Dict[str, Any] = field(default_factory=dict)

    def is_active(self) -> bool:
        """检查用户是否活跃"""
        if self.status != UserStatus.ACTIVE:
            return False
        if self.expires_at and datetime.now() > self.expires_at:
            return False
        return True

    def can_connect(self) -> bool:
        """检查用户是否可以建立新连接"""
        if not self.is_active():
            return False
        if self.max_connections > 0 and self.current_connections >= self.max_connections:
            return False
        return True

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "user_id": self.user_id,
            "username": self.username,
            "email": self.email,
            "role": self.role.value,
            "status": self.status.value,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "max_connections": self.max_connections,
            "current_connections": self.current_connections,
            "bandwidth_limit": self.bandwidth_limit,
            "traffic_used": self.traffic_used,
            "traffic_limit": self.traffic_limit,
        }


@dataclass
class Token:
    """令牌数据模型"""
    token_id: str
    user_id: str
    access_token: str
    refresh_token: str
    expires_at: datetime
    refresh_expires_at: datetime
    created_at: datetime = field(default_factory=datetime.now)
    device_id: str = ""
    ip_address: str = ""
    is_revoked: bool = False

    def is_expired(self) -> bool:
        """检查令牌是否过期"""
        return datetime.now() > self.expires_at

    def is_refresh_expired(self) -> bool:
        """检查刷新令牌是否过期"""
        return datetime.now() > self.refresh_expires_at


class PasswordManager:
    """密码管理器"""

    def __init__(self):
        self._pwd_context = CryptContext(
            schemes=["bcrypt"],
            deprecated="auto",
            bcrypt__rounds=12
        )

    def hash_password(self, password: str) -> str:
        """哈希密码"""
        return self._pwd_context.hash(password)

    def verify_password(self, password: str, password_hash: str) -> bool:
        """验证密码"""
        try:
            return self._pwd_context.verify(password, password_hash)
        except Exception:
            return False


class JWTManager:
    """JWT令牌管理器"""

    def __init__(self, secret_key: Optional[str] = None):
        self._secret_key = secret_key or secrets.token_urlsafe(32)
        self._algorithm = "HS256"

    @property
    def secret_key(self) -> str:
        return self._secret_key

    def create_access_token(
        self,
        user_id: str,
        expires_in: int = AUTH_TOKEN_EXPIRE,
        additional_claims: Optional[Dict[str, Any]] = None
    ) -> str:
        """创建访问令牌"""
        now = datetime.utcnow()
        payload = {
            "sub": user_id,
            "type": "access",
            "iat": now,
            "exp": now + timedelta(seconds=expires_in),
            "jti": secrets.token_urlsafe(16),
        }
        if additional_claims:
            payload.update(additional_claims)
        return jwt.encode(payload, self._secret_key, algorithm=self._algorithm)

    def create_refresh_token(
        self,
        user_id: str,
        expires_in: int = REFRESH_TOKEN_EXPIRE
    ) -> str:
        """创建刷新令牌"""
        now = datetime.utcnow()
        payload = {
            "sub": user_id,
            "type": "refresh",
            "iat": now,
            "exp": now + timedelta(seconds=expires_in),
            "jti": secrets.token_urlsafe(16),
        }
        return jwt.encode(payload, self._secret_key, algorithm=self._algorithm)

    def decode_token(self, token: str) -> Optional[Dict[str, Any]]:
        """解码令牌"""
        try:
            payload = jwt.decode(token, self._secret_key, algorithms=[self._algorithm])
            return payload
        except jwt.ExpiredSignatureError:
            return None
        except jwt.InvalidTokenError:
            return None

    def verify_token(self, token: str, expected_type: str = "access") -> Optional[str]:
        """
        验证令牌
        
        Args:
            token: JWT令牌
            expected_type: 期望的令牌类型
            
        Returns:
            用户ID或None
        """
        payload = self.decode_token(token)
        if payload is None:
            return None
        if payload.get("type") != expected_type:
            return None
        return payload.get("sub")


class UserDatabase:
    """用户数据库管理"""

    def __init__(self, db_path: str = "data/users.db"):
        self._db_path = db_path
        self._db: Optional[aiosqlite.Connection] = None
        self._lock = asyncio.Lock()

    async def initialize(self):
        """初始化数据库"""
        os.makedirs(os.path.dirname(self._db_path), exist_ok=True)
        self._db = await aiosqlite.connect(self._db_path)
        await self._create_tables()

    async def close(self):
        """关闭数据库连接"""
        if self._db:
            await self._db.close()

    async def _create_tables(self):
        """创建数据表"""
        await self._db.executescript("""
            CREATE TABLE IF NOT EXISTS users (
                user_id TEXT PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role INTEGER DEFAULT 1,
                status INTEGER DEFAULT 1,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                expires_at TEXT,
                max_connections INTEGER DEFAULT 2,
                current_connections INTEGER DEFAULT 0,
                bandwidth_limit INTEGER DEFAULT 0,
                traffic_used INTEGER DEFAULT 0,
                traffic_limit INTEGER DEFAULT 0,
                metadata TEXT
            );

            CREATE TABLE IF NOT EXISTS tokens (
                token_id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                access_token TEXT NOT NULL,
                refresh_token TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                refresh_expires_at TEXT NOT NULL,
                created_at TEXT NOT NULL,
                device_id TEXT,
                ip_address TEXT,
                is_revoked INTEGER DEFAULT 0,
                FOREIGN KEY (user_id) REFERENCES users(user_id)
            );

            CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
            CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
            CREATE INDEX IF NOT EXISTS idx_tokens_user_id ON tokens(user_id);
            CREATE INDEX IF NOT EXISTS idx_tokens_access_token ON tokens(access_token);
        """)
        await self._db.commit()

    async def create_user(self, user: User) -> bool:
        """创建用户"""
        async with self._lock:
            try:
                await self._db.execute(
                    """
                    INSERT INTO users (
                        user_id, username, email, password_hash, role, status,
                        created_at, updated_at, expires_at, max_connections,
                        current_connections, bandwidth_limit, traffic_used,
                        traffic_limit, metadata
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        user.user_id, user.username, user.email, user.password_hash,
                        user.role.value, user.status.value, user.created_at.isoformat(),
                        user.updated_at.isoformat(),
                        user.expires_at.isoformat() if user.expires_at else None,
                        user.max_connections, user.current_connections, user.bandwidth_limit,
                        user.traffic_used, user.traffic_limit,
                        str(user.metadata) if user.metadata else None
                    )
                )
                await self._db.commit()
                return True
            except aiosqlite.IntegrityError:
                return False

    async def get_user_by_id(self, user_id: str) -> Optional[User]:
        """通过ID获取用户"""
        async with self._lock:
            cursor = await self._db.execute(
                "SELECT * FROM users WHERE user_id = ?", (user_id,)
            )
            row = await cursor.fetchone()
            if row is None:
                return None
            return self._row_to_user(row)

    async def get_user_by_username(self, username: str) -> Optional[User]:
        """通过用户名获取用户"""
        async with self._lock:
            cursor = await self._db.execute(
                "SELECT * FROM users WHERE username = ?", (username,)
            )
            row = await cursor.fetchone()
            if row is None:
                return None
            return self._row_to_user(row)

    async def get_user_by_email(self, email: str) -> Optional[User]:
        """通过邮箱获取用户"""
        async with self._lock:
            cursor = await self._db.execute(
                "SELECT * FROM users WHERE email = ?", (email,)
            )
            row = await cursor.fetchone()
            if row is None:
                return None
            return self._row_to_user(row)

    async def update_user(self, user: User) -> bool:
        """更新用户"""
        async with self._lock:
            user.updated_at = datetime.now()
            try:
                await self._db.execute(
                    """
                    UPDATE users SET
                        username = ?, email = ?, password_hash = ?, role = ?,
                        status = ?, updated_at = ?, expires_at = ?,
                        max_connections = ?, current_connections = ?,
                        bandwidth_limit = ?, traffic_used = ?, traffic_limit = ?,
                        metadata = ?
                    WHERE user_id = ?
                    """,
                    (
                        user.username, user.email, user.password_hash, user.role.value,
                        user.status.value, user.updated_at.isoformat(),
                        user.expires_at.isoformat() if user.expires_at else None,
                        user.max_connections, user.current_connections, user.bandwidth_limit,
                        user.traffic_used, user.traffic_limit,
                        str(user.metadata) if user.metadata else None, user.user_id
                    )
                )
                await self._db.commit()
                return True
            except Exception:
                return False

    async def delete_user(self, user_id: str) -> bool:
        """删除用户"""
        async with self._lock:
            try:
                await self._db.execute("DELETE FROM tokens WHERE user_id = ?", (user_id,))
                await self._db.execute("DELETE FROM users WHERE user_id = ?", (user_id,))
                await self._db.commit()
                return True
            except Exception:
                return False

    async def list_users(self, limit: int = 100, offset: int = 0) -> List[User]:
        """列出用户"""
        async with self._lock:
            cursor = await self._db.execute(
                "SELECT * FROM users LIMIT ? OFFSET ?", (limit, offset)
            )
            rows = await cursor.fetchall()
            return [self._row_to_user(row) for row in rows]

    async def save_token(self, token: Token) -> bool:
        """保存令牌"""
        async with self._lock:
            try:
                await self._db.execute(
                    """
                    INSERT INTO tokens (
                        token_id, user_id, access_token, refresh_token,
                        expires_at, refresh_expires_at, created_at,
                        device_id, ip_address, is_revoked
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        token.token_id, token.user_id, token.access_token,
                        token.refresh_token, token.expires_at.isoformat(),
                        token.refresh_expires_at.isoformat(),
                        token.created_at.isoformat(), token.device_id,
                        token.ip_address, int(token.is_revoked)
                    )
                )
                await self._db.commit()
                return True
            except Exception:
                return False

    async def get_token_by_access_token(self, access_token: str) -> Optional[Token]:
        """通过访问令牌获取令牌记录"""
        async with self._lock:
            cursor = await self._db.execute(
                "SELECT * FROM tokens WHERE access_token = ?", (access_token,)
            )
            row = await cursor.fetchone()
            if row is None:
                return None
            return self._row_to_token(row)

    async def revoke_token(self, token_id: str) -> bool:
        """撤销令牌"""
        async with self._lock:
            try:
                await self._db.execute(
                    "UPDATE tokens SET is_revoked = 1 WHERE token_id = ?", (token_id,)
                )
                await self._db.commit()
                return True
            except Exception:
                return False

    async def revoke_user_tokens(self, user_id: str) -> bool:
        """撤销用户所有令牌"""
        async with self._lock:
            try:
                await self._db.execute(
                    "UPDATE tokens SET is_revoked = 1 WHERE user_id = ?", (user_id,)
                )
                await self._db.commit()
                return True
            except Exception:
                return False

    async def cleanup_expired_tokens(self) -> int:
        """清理过期令牌"""
        async with self._lock:
            cursor = await self._db.execute(
                "DELETE FROM tokens WHERE refresh_expires_at < ?",
                (datetime.now().isoformat(),)
            )
            await self._db.commit()
            return cursor.rowcount

    def _row_to_user(self, row) -> User:
        """将数据库行转换为用户对象"""
        return User(
            user_id=row[0],
            username=row[1],
            email=row[2],
            password_hash=row[3],
            role=UserRole(row[4]),
            status=UserStatus(row[5]),
            created_at=datetime.fromisoformat(row[6]),
            updated_at=datetime.fromisoformat(row[7]),
            expires_at=datetime.fromisoformat(row[8]) if row[8] else None,
            max_connections=row[9],
            current_connections=row[10],
            bandwidth_limit=row[11],
            traffic_used=row[12],
            traffic_limit=row[13],
            metadata=eval(row[14]) if row[14] else {}
        )

    def _row_to_token(self, row) -> Token:
        """将数据库行转换为令牌对象"""
        return Token(
            token_id=row[0],
            user_id=row[1],
            access_token=row[2],
            refresh_token=row[3],
            expires_at=datetime.fromisoformat(row[4]),
            refresh_expires_at=datetime.fromisoformat(row[5]),
            created_at=datetime.fromisoformat(row[6]),
            device_id=row[7] or "",
            ip_address=row[8] or "",
            is_revoked=bool(row[9])
        )


class AuthManager:
    """认证管理器"""

    def __init__(self, db_path: str = "data/users.db", jwt_secret: Optional[str] = None):
        self._db = UserDatabase(db_path)
        self._password_manager = PasswordManager()
        self._jwt_manager = JWTManager(jwt_secret)
        self._initialized = False

    @property
    def jwt_secret(self) -> str:
        return self._jwt_manager.secret_key

    async def initialize(self):
        """初始化认证管理器"""
        if not self._initialized:
            await self._db.initialize()
            self._initialized = True

    async def close(self):
        """关闭认证管理器"""
        await self._db.close()
        self._initialized = False

    async def register_user(
        self,
        username: str,
        email: str,
        password: str,
        role: UserRole = UserRole.USER
    ) -> Optional[User]:
        """注册新用户"""
        if await self._db.get_user_by_username(username):
            return None
        if await self._db.get_user_by_email(email):
            return None

        user = User(
            user_id=secrets.token_urlsafe(16),
            username=username,
            email=email,
            password_hash=self._password_manager.hash_password(password),
            role=role
        )

        if await self._db.create_user(user):
            return user
        return None

    async def authenticate(
        self,
        username: str,
        password: str,
        device_id: str = "",
        ip_address: str = ""
    ) -> Optional[Token]:
        """用户认证"""
        user = await self._db.get_user_by_username(username)
        if user is None:
            return None

        if not self._password_manager.verify_password(password, user.password_hash):
            return None

        if not user.is_active():
            return None

        access_token = self._jwt_manager.create_access_token(user.user_id)
        refresh_token = self._jwt_manager.create_refresh_token(user.user_id)

        token = Token(
            token_id=secrets.token_urlsafe(16),
            user_id=user.user_id,
            access_token=access_token,
            refresh_token=refresh_token,
            expires_at=datetime.now() + timedelta(seconds=AUTH_TOKEN_EXPIRE),
            refresh_expires_at=datetime.now() + timedelta(seconds=REFRESH_TOKEN_EXPIRE),
            device_id=device_id,
            ip_address=ip_address
        )

        if await self._db.save_token(token):
            return token
        return None

    async def verify_access_token(self, access_token: str) -> Optional[User]:
        """验证访问令牌"""
        token_record = await self._db.get_token_by_access_token(access_token)
        if token_record is None or token_record.is_revoked or token_record.is_expired():
            return None

        user_id = self._jwt_manager.verify_token(access_token, "access")
        if user_id is None:
            return None

        return await self._db.get_user_by_id(user_id)

    async def refresh_access_token(self, refresh_token: str) -> Optional[Token]:
        """刷新访问令牌"""
        user_id = self._jwt_manager.verify_token(refresh_token, "refresh")
        if user_id is None:
            return None

        user = await self._db.get_user_by_id(user_id)
        if user is None or not user.is_active():
            return None

        new_access_token = self._jwt_manager.create_access_token(user.user_id)
        new_refresh_token = self._jwt_manager.create_refresh_token(user.user_id)

        token = Token(
            token_id=secrets.token_urlsafe(16),
            user_id=user.user_id,
            access_token=new_access_token,
            refresh_token=new_refresh_token,
            expires_at=datetime.now() + timedelta(seconds=AUTH_TOKEN_EXPIRE),
            refresh_expires_at=datetime.now() + timedelta(seconds=REFRESH_TOKEN_EXPIRE)
        )

        if await self._db.save_token(token):
            return token
        return None

    async def logout(self, access_token: str) -> bool:
        """用户登出"""
        token_record = await self._db.get_token_by_access_token(access_token)
        if token_record is None:
            return False
        return await self._db.revoke_token(token_record.token_id)

    async def get_user(self, user_id: str) -> Optional[User]:
        """获取用户"""
        return await self._db.get_user_by_id(user_id)

    async def update_user(self, user: User) -> bool:
        """更新用户"""
        return await self._db.update_user(user)

    async def delete_user(self, user_id: str) -> bool:
        """删除用户"""
        return await self._db.delete_user(user_id)

    async def increment_connections(self, user_id: str) -> bool:
        """增加连接数"""
        user = await self._db.get_user_by_id(user_id)
        if user is None:
            return False
        user.current_connections += 1
        return await self._db.update_user(user)

    async def decrement_connections(self, user_id: str) -> bool:
        """减少连接数"""
        user = await self._db.get_user_by_id(user_id)
        if user is None:
            return False
        if user.current_connections > 0:
            user.current_connections -= 1
        return await self._db.update_user(user)

    async def add_traffic(self, user_id: str, bytes_count: int) -> bool:
        """增加流量统计"""
        user = await self._db.get_user_by_id(user_id)
        if user is None:
            return False
        user.traffic_used += bytes_count
        return await self._db.update_user(user)
