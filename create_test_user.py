"""
Create a test user for authentication testing
创建测试用户用于认证测试
"""

import asyncio
from server.core.auth import AuthManager, UserRole

async def create_test_user():
    """创建测试用户"""
    auth_manager = AuthManager()
    await auth_manager.initialize()
    
    # 创建测试用户
    user = await auth_manager.register_user(
        username="test",
        email="test@example.com",
        password="test",
        role=UserRole.USER
    )
    
    if user:
        print(f"Test user created successfully: {user.username}")
    else:
        print("Failed to create test user")
    
    await auth_manager.close()

if __name__ == "__main__":
    asyncio.run(create_test_user())
