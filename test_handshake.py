"""
Test handshake connection
测试握手连接
"""

import asyncio
import logging
from client.core.network import NetworkClient, ConnectionConfig
from shared.protocol import MessageType

# 设置日志
logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)

async def test_handshake():
    """测试握手连接"""
    print("Testing handshake connection...")
    
    # 创建连接配置
    config = ConnectionConfig(
        server_host="129.226.194.192",
        server_port=8388,
        username="test",
        password="test",
        device_id="test-device"
    )
    
    # 创建网络客户端
    client = NetworkClient(config)
    
    try:
        # 尝试连接
        success = await client.connect()
        if success:
            print("Handshake successful!")
        else:
            print("Handshake failed!")
    except Exception as e:
        print(f"Error: {e}")
    finally:
        # 断开连接
        await client.disconnect()

if __name__ == "__main__":
    asyncio.run(test_handshake())
