"""
Protocol Definitions
协议定义
"""

import struct
from enum import IntEnum
from dataclasses import dataclass
from typing import Optional


class MessageType(IntEnum):
    HANDSHAKE = 0x01
    HANDSHAKE_ACK = 0x02
    AUTH_REQUEST = 0x03
    AUTH_RESPONSE = 0x04
    HEARTBEAT = 0x05
    HEARTBEAT_ACK = 0x06
    DATA = 0x07
    DATA_ACK = 0x08
    DISCONNECT = 0x09
    ERROR = 0x0A
    NODE_LIST_REQUEST = 0x0B
    NODE_LIST_RESPONSE = 0x0C
    SPEED_TEST = 0x0D
    SPEED_TEST_RESULT = 0x0E


class ErrorCode(IntEnum):
    SUCCESS = 0
    UNKNOWN_ERROR = 1
    AUTH_FAILED = 2
    TOKEN_EXPIRED = 3
    INVALID_PACKET = 4
    CONNECTION_REFUSED = 5
    SERVER_OVERLOAD = 6
    RATE_LIMITED = 7
    ENCRYPTION_ERROR = 8


@dataclass
class PacketHeader:
    magic: int = 0x4E41
    version: int = 0x01
    msg_type: MessageType = MessageType.DATA
    flags: int = 0
    payload_len: int = 0
    sequence: int = 0
    timestamp: int = 0

    HEADER_SIZE = 16
    HEADER_FORMAT = "!HBBIIII"

    def pack(self) -> bytes:
        return struct.pack(
            self.HEADER_FORMAT,
            self.magic,
            self.version,
            self.msg_type,
            self.flags,
            self.payload_len,
            self.sequence,
            self.timestamp,
        )

    @classmethod
    def unpack(cls, data: bytes) -> Optional["PacketHeader"]:
        if len(data) < cls.HEADER_SIZE:
            return None
        try:
            magic, version, msg_type, flags, payload_len, sequence, timestamp = struct.unpack(
                cls.HEADER_FORMAT, data[: cls.HEADER_SIZE]
            )
            if magic != cls(magic).magic:
                return None
            return cls(
                magic=magic,
                version=version,
                msg_type=MessageType(msg_type),
                flags=flags,
                payload_len=payload_len,
                sequence=sequence,
                timestamp=timestamp,
            )
        except (struct.error, ValueError):
            return None


class PacketFlags(IntEnum):
    NONE = 0
    ENCRYPTED = 1 << 0
    COMPRESSED = 1 << 1
    ACK_REQUIRED = 1 << 2
    PRIORITY = 1 << 3
    FRAGMENT = 1 << 4
    LAST_FRAGMENT = 1 << 5


@dataclass
class Packet:
    header: PacketHeader
    payload: bytes = b""

    def pack(self) -> bytes:
        self.header.payload_len = len(self.payload)
        return self.header.pack() + self.payload

    @classmethod
    def create(
        cls,
        msg_type: MessageType,
        payload: bytes = b"",
        flags: int = 0,
        sequence: int = 0,
        timestamp: int = 0,
    ) -> "Packet":
        header = PacketHeader(
            msg_type=msg_type,
            flags=flags,
            payload_len=len(payload),
            sequence=sequence,
            timestamp=timestamp,
        )
        return cls(header=header, payload=payload)

    @classmethod
    def unpack(cls, data: bytes) -> Optional["Packet"]:
        header = PacketHeader.unpack(data)
        if header is None:
            return None
        payload = data[PacketHeader.HEADER_SIZE : PacketHeader.HEADER_SIZE + header.payload_len]
        if len(payload) != header.payload_len:
            return None
        return cls(header=header, payload=payload)


@dataclass
class AuthRequest:
    username: str
    password: str
    client_version: str
    device_id: str

    def to_bytes(self) -> bytes:
        data = f"{self.username}:{self.password}:{self.client_version}:{self.device_id}"
        return data.encode("utf-8")

    @classmethod
    def from_bytes(cls, data: bytes) -> "AuthRequest":
        parts = data.decode("utf-8").split(":")
        if len(parts) != 4:
            raise ValueError("Invalid auth request format")
        return cls(
            username=parts[0],
            password=parts[1],
            client_version=parts[2],
            device_id=parts[3],
        )


@dataclass
class AuthResponse:
    success: bool
    error_code: ErrorCode
    token: str
    refresh_token: str
    expires_in: int
    message: str

    def to_bytes(self) -> bytes:
        data = f"{int(self.success)}:{int(self.error_code)}:{self.token}:{self.refresh_token}:{self.expires_in}:{self.message}"
        return data.encode("utf-8")

    @classmethod
    def from_bytes(cls, data: bytes) -> "AuthResponse":
        parts = data.decode("utf-8").split(":")
        if len(parts) != 6:
            raise ValueError("Invalid auth response format")
        return cls(
            success=bool(int(parts[0])),
            error_code=ErrorCode(int(parts[1])),
            token=parts[2],
            refresh_token=parts[3],
            expires_in=int(parts[4]),
            message=parts[5],
        )


@dataclass
class NodeInfo:
    node_id: str
    name: str
    region: str
    host: str
    port: int
    load: float
    latency: int
    max_connections: int
    current_connections: int
    is_available: bool

    def to_dict(self) -> dict:
        return {
            "node_id": self.node_id,
            "name": self.name,
            "region": self.region,
            "host": self.host,
            "port": self.port,
            "load": self.load,
            "latency": self.latency,
            "max_connections": self.max_connections,
            "current_connections": self.current_connections,
            "is_available": self.is_available,
        }
