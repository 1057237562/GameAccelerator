"""
Shared Constants and Configuration
共享常量和配置
"""

import os
from typing import Dict, Any

DEFAULT_SERVER_HOST = "0.0.0.0"
DEFAULT_SERVER_PORT = 8388
DEFAULT_API_PORT = 8080

TCP_BUFFER_SIZE = 8192
UDP_BUFFER_SIZE = 65507

MAX_CONNECTIONS = 2000
CONNECTION_TIMEOUT = 300
HEARTBEAT_INTERVAL = 30

ENCRYPTION_KEY_SIZE = 32
AES_BLOCK_SIZE = 16

AUTH_TOKEN_EXPIRE = 3600
REFRESH_TOKEN_EXPIRE = 86400

LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
LOG_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"

DEFAULT_CONFIG: Dict[str, Any] = {
    "server": {
        "host": DEFAULT_SERVER_HOST,
        "port": DEFAULT_SERVER_PORT,
        "api_port": DEFAULT_API_PORT,
        "max_connections": MAX_CONNECTIONS,
        "timeout": CONNECTION_TIMEOUT,
    },
    "encryption": {
        "algorithm": "AES-256-GCM",
        "key_size": ENCRYPTION_KEY_SIZE,
    },
    "performance": {
        "tcp_buffer_size": TCP_BUFFER_SIZE,
        "udp_buffer_size": UDP_BUFFER_SIZE,
        "heartbeat_interval": HEARTBEAT_INTERVAL,
    },
    "auth": {
        "token_expire": AUTH_TOKEN_EXPIRE,
        "refresh_token_expire": REFRESH_TOKEN_EXPIRE,
    },
}

GAME_PORTS: Dict[str, list] = {
    "steam": [27015, 27016, 27017, 27018, 27019, 27020],
    "battlenet": [1119, 1120, 3724, 4000, 6112, 6113, 6114],
    "origin": [9960, 9961, 9962, 9963, 42127],
    "epic": [5222, 5223, 5224, 5225, 5226, 5227, 5228, 5229],
    "riot": [2099, 5222, 5223, 5224, 5225, 5226, 5227, 5228, 5229, 8393, 8394],
    "ubisoft": [13000, 13005, 13200, 14000, 14001],
    "playstation": [1935, 3478, 3479, 3480, 9293, 9295, 9296, 9297],
    "xbox": [3074, 3075, 3076, 3077, 3078, 3079, 3080],
    "nintendo": [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 49152, 49153, 49154],
}

DEFAULT_GAME_PORTS = []
for ports in GAME_PORTS.values():
    DEFAULT_GAME_PORTS.extend(ports)
DEFAULT_GAME_PORTS = list(set(DEFAULT_GAME_PORTS))
