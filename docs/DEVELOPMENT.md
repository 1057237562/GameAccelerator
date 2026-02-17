# 游戏加速器系统开发文档

## 项目概述

本项目是一个完整的游戏加速器系统，包含服务端和客户端两个核心组件。系统采用Python 3.8+开发，支持TCP/UDP协议的高性能数据转发，具备流量加密、多用户管理、负载均衡等功能。

## 技术架构

### 系统架构图

```
┌─────────────────────────────────────────────────────────────┐
│                        客户端 (Client)                        │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐  │
│  │   GUI界面   │  │  网络模块   │  │  流量拦截与转发     │  │
│  │  (PyQt5)    │  │  (asyncio)  │  │  (SOCKS5/UDP代理)   │  │
│  └─────────────┘  └─────────────┘  └─────────────────────┘  │
│  ┌─────────────┐  ┌─────────────┐                           │
│  │ 进程监控    │  │  加密通信   │                           │
│  │ (psutil)    │  │  (AES-256)  │                           │
│  └─────────────┘  └─────────────┘                           │
└─────────────────────────────────────────────────────────────┘
                              │
                              │ 加密隧道 (TCP/UDP)
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                       服务端 (Server)                         │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐  │
│  │  代理服务   │  │  认证模块   │  │  负载均衡           │  │
│  │  (asyncio)  │  │  (JWT)      │  │  (多节点管理)       │  │
│  └─────────────┘  └─────────────┘  └─────────────────────┘  │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐  │
│  │ 数据转发    │  │  加密模块   │  │  监控与日志         │  │
│  │ (TCP/UDP)   │  │  (AES-256)  │  │  (Prometheus)       │  │
│  └─────────────┘  └─────────────┘  └─────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

### 目录结构

```
NAC/
├── client/                     # 客户端代码
│   ├── core/                   # 核心模块
│   │   ├── network.py          # 网络连接模块
│   │   ├── process_monitor.py  # 进程监控模块
│   │   └── traffic.py          # 流量拦截模块
│   ├── ui/                     # 用户界面
│   │   └── main_window.py      # 主窗口
│   ├── utils/                  # 工具模块
│   ├── main.py                 # 客户端入口
│   └── .env.example            # 配置示例
├── server/                     # 服务端代码
│   ├── core/                   # 核心模块
│   │   ├── auth.py             # 认证授权模块
│   │   ├── forwarder.py        # 数据转发模块
│   │   ├── node_manager.py     # 节点管理模块
│   │   └── monitoring.py       # 监控日志模块
│   ├── handlers/               # 处理器模块
│   ├── utils/                  # 工具模块
│   ├── main.py                 # 服务端入口
│   └── .env.example            # 配置示例
├── shared/                     # 共享模块
│   ├── constants.py            # 常量定义
│   ├── protocol.py             # 协议定义
│   └── crypto.py               # 加密模块
├── tests/                      # 测试代码
│   └── test_all.py             # 测试套件
├── requirements.txt            # 依赖列表
├── start_server.bat/sh         # 服务端启动脚本
└── start_client.bat/sh         # 客户端启动脚本
```

## 核心模块说明

### 1. 加密模块 (shared/crypto.py)

使用AES-256-GCM算法进行数据加密，提供以下功能：

- **CryptoManager**: 核心加密管理器
  - `encrypt()`: 加密数据
  - `decrypt()`: 解密数据
  - `generate_key()`: 生成随机密钥
  - `derive_key()`: 从密码派生密钥

- **SecureChannel**: 安全通道
  - 管理加密通信的完整流程
  - 支持序列号防重放攻击

- **HandshakeCrypto**: 握手加密
  - 用于客户端和服务端之间的初始密钥交换

### 2. 协议模块 (shared/protocol.py)

定义了客户端和服务端之间的通信协议：

```python
# 数据包结构
┌────────────────────────────────────────┐
│            Packet Header (16B)          │
├────────────────────────────────────────┤
│ Magic (2B) │ Version (1B) │ Type (1B)  │
├────────────────────────────────────────┤
│ Flags (4B) │ Payload Len (4B)          │
├────────────────────────────────────────┤
│ Sequence (4B) │ Timestamp (4B)         │
├────────────────────────────────────────┤
│            Payload (Variable)           │
└────────────────────────────────────────┘
```

消息类型：
- HANDSHAKE: 握手请求
- AUTH_REQUEST/RESPONSE: 认证请求/响应
- DATA: 数据传输
- HEARTBEAT: 心跳检测
- NODE_LIST_REQUEST/RESPONSE: 节点列表

### 3. 认证模块 (server/core/auth.py)

提供完整的用户认证和授权功能：

- **User**: 用户数据模型
- **Token**: 令牌数据模型
- **PasswordManager**: 密码管理（bcrypt哈希）
- **JWTManager**: JWT令牌管理
- **UserDatabase**: 用户数据库操作
- **AuthManager**: 认证管理器

### 4. 数据转发模块 (server/core/forwarder.py)

高性能TCP/UDP数据转发：

- **TCPForwarder**: TCP数据转发器
- **UDPForwarder**: UDP数据转发器
- **ConnectionManager**: 连接管理器
- **PacketProcessor**: 数据包处理器
- **ProxyServer**: 代理服务器基类

### 5. 节点管理模块 (server/core/node_manager.py)

多节点负载均衡管理：

- **ServerNode**: 服务器节点模型
- **NodeHealthChecker**: 节点健康检查
- **LoadBalancer**: 负载均衡器
  - 轮询 (Round Robin)
  - 最少连接 (Least Connections)
  - 最低延迟 (Least Latency)
  - 加权 (Weighted)
  - 随机 (Random)
- **NodeManager**: 节点管理器

### 6. 监控模块 (server/core/monitoring.py)

系统监控和日志记录：

- **MetricsCollector**: 指标收集器
- **Logger**: 日志管理器
- **AuditLogger**: 审计日志
- **PerformanceMonitor**: 性能监控
- **HealthMonitor**: 健康监控
- **MonitoringService**: 监控服务

### 7. 客户端网络模块 (client/core/network.py)

客户端网络连接管理：

- **NetworkClient**: 网络客户端
  - 连接管理
  - 认证处理
  - 数据收发
  - 自动重连
- **UDPClient**: UDP客户端

### 8. 进程监控模块 (client/core/process_monitor.py)

游戏进程识别和流量定向：

- **GameProcess**: 游戏进程模型
- **GameRule**: 游戏识别规则
- **ProcessMonitor**: 进程监控器
- **TrafficDirector**: 流量定向器

### 9. 流量拦截模块 (client/core/traffic.py)

本地流量拦截和转发：

- **SOCKS5Server**: SOCKS5代理服务器
- **LocalPortForwarder**: 本地端口转发
- **UDPProxy**: UDP代理
- **TrafficInterceptor**: 流量拦截器

## 部署指南

### 环境要求

- Python 3.8+
- 操作系统: Windows 10/11, macOS 10.15+, Linux

### 安装步骤

1. 克隆项目
```bash
git clone <repository_url>
cd NAC
```

2. 创建虚拟环境
```bash
python -m venv venv
source venv/bin/activate  # Linux/macOS
venv\Scripts\activate     # Windows
```

3. 安装依赖
```bash
pip install -r requirements.txt
```

4. 配置服务端
```bash
cp server/.env.example server/.env
# 编辑 server/.env 配置文件
```

5. 配置客户端
```bash
cp client/.env.example client/.env
# 编辑 client/.env 配置文件
```

### 启动服务

**启动服务端:**
```bash
# Windows
start_server.bat

# Linux/macOS
./start_server.sh
```

**启动客户端:**
```bash
# Windows
start_client.bat

# Linux/macOS
./start_client.sh
```

### 创建管理员账户

```bash
# 通过API创建管理员
curl -X POST http://localhost:8080 -d '{"action":"create_admin","username":"admin","email":"admin@example.com","password":"admin123"}'
```

## 性能优化建议

### 服务端优化

1. 使用uvloop替代默认事件循环（Linux/macOS）
```python
import uvloop
asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
```

2. 调整系统限制
```bash
# Linux
ulimit -n 65535
```

3. 使用多进程模式
```python
# 利用多核CPU
workers = multiprocessing.cpu_count()
```

### 客户端优化

1. 减少UI刷新频率
2. 使用异步操作避免阻塞
3. 合理设置缓冲区大小

## 安全建议

1. **密钥管理**
   - 生产环境必须更换默认JWT密钥
   - 定期轮换加密密钥

2. **网络安全**
   - 使用TLS加密传输
   - 配置防火墙规则

3. **访问控制**
   - 实施IP白名单
   - 限制登录尝试次数

## API文档

### 服务端API

| 端点 | 方法 | 描述 |
|------|------|------|
| `/` | POST | API入口 |
| `action=get_nodes` | POST | 获取节点列表 |
| `action=get_stats` | POST | 获取统计信息 |
| `action=register_user` | POST | 注册用户 |
| `action=create_admin` | POST | 创建管理员 |

### 协议API

客户端与服务端通过自定义协议通信：

1. **握手流程**
   - Client → Server: HANDSHAKE
   - Server → Client: HANDSHAKE_ACK (包含挑战码)

2. **认证流程**
   - Client → Server: AUTH_REQUEST
   - Server → Client: AUTH_RESPONSE

3. **数据传输**
   - 双向: DATA (加密)

4. **心跳保活**
   - Client → Server: HEARTBEAT
   - Server → Client: HEARTBEAT_ACK

## 故障排查

### 常见问题

1. **连接失败**
   - 检查防火墙设置
   - 确认服务端已启动
   - 验证网络连通性

2. **认证失败**
   - 检查用户名密码
   - 确认用户状态
   - 查看服务端日志

3. **性能问题**
   - 检查系统资源
   - 调整缓冲区大小
   - 优化网络配置

## 版本历史

- v1.0.0 (2024-01)
  - 初始版本发布
  - 支持TCP/UDP转发
  - 实现基础认证
  - PyQt5图形界面

## 许可证

MIT License
