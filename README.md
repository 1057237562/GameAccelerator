# 游戏加速器系统 (Game Accelerator System)

一个完整的游戏加速器系统，包含服务端和客户端两个核心组件。支持TCP/UDP协议的高性能数据转发，具备流量加密、多用户管理、负载均衡等功能。

## 特性

### 服务端
- 🚀 高性能TCP/UDP数据转发
- 🔐 AES-256-GCM流量加密
- 👥 多用户并发处理（支持1000+用户）
- ⚖️ 负载均衡与节点管理
- 📊 实时监控与日志系统
- 🔑 JWT认证与授权

### 客户端
- 🖥️ 现代化PyQt5图形界面
- 🎮 游戏进程自动识别
- 🔄 SOCKS5/UDP代理支持
- 📡 断线自动重连
- 📈 连接状态实时监控

## 快速开始

### 环境要求
- Python 3.8+
- Windows 10/11, macOS 10.15+, Linux

### 安装

```bash
# 克隆项目
git clone <repository_url>
cd NAC

# 创建虚拟环境
python -m venv venv
source venv/bin/activate  # Linux/macOS
venv\Scripts\activate     # Windows

# 安装依赖
pip install -r requirements.txt
```

### 启动服务端

```bash
# Windows
start_server.bat

# Linux/macOS
./start_server.sh
```

### 启动客户端

```bash
# Windows
start_client.bat

# Linux/macOS
./start_client.sh
```

## 项目结构

```
NAC/
├── client/                 # 客户端代码
│   ├── core/              # 核心模块
│   ├── ui/                # 用户界面
│   └── main.py            # 入口文件
├── server/                 # 服务端代码
│   ├── core/              # 核心模块
│   ├── handlers/          # 处理器
│   └── main.py            # 入口文件
├── shared/                 # 共享模块
│   ├── constants.py       # 常量定义
│   ├── protocol.py        # 协议定义
│   └── crypto.py          # 加密模块
├── tests/                  # 测试代码
├── docs/                   # 文档
└── requirements.txt        # 依赖列表
```

## 配置

### 服务端配置

复制配置模板并修改：

```bash
cp server/.env.example server/.env
```

主要配置项：
- `SERVER_HOST`: 监听地址
- `SERVER_PORT`: 服务端口
- `JWT_SECRET`: JWT密钥（生产环境必须修改）
- `MAX_CONNECTIONS`: 最大连接数

### 客户端配置

```bash
cp client/.env.example client/.env
```

## API使用

### 创建管理员账户

```bash
curl -X POST http://localhost:8080 \
  -H "Content-Type: application/json" \
  -d '{"action":"create_admin","username":"admin","email":"admin@example.com","password":"admin123"}'
```

### 获取节点列表

```bash
curl -X POST http://localhost:8080 \
  -H "Content-Type: application/json" \
  -d '{"action":"get_nodes"}'
```

## 测试

运行测试套件：

```bash
python -m pytest tests/ -v
```

## 性能指标

| 指标 | 目标值 |
|------|--------|
| 并发连接数 | 1000+ |
| 数据转发延迟 | <50ms |
| 客户端CPU占用 | <10% |
| 客户端内存占用 | <100MB |
| 网络丢包率 | <1% |

## 支持的游戏平台

- Steam
- Battle.net
- Epic Games
- Origin
- Riot Games
- Ubisoft Connect
- PlayStation Network
- Xbox Live
- Nintendo Switch

## 技术栈

- **服务端**: asyncio, aiohttp, cryptography, JWT, SQLite
- **客户端**: PyQt5, asyncio, psutil
- **加密**: AES-256-GCM
- **协议**: 自定义二进制协议

## 文档

- [开发文档](docs/DEVELOPMENT.md)
- [用户手册](docs/USER_MANUAL.md)

## 许可证

MIT License

## 贡献

欢迎提交 Issue 和 Pull Request！

## 联系方式

- 项目主页: https://github.com/example/nac
- 问题反馈: https://github.com/example/nac/issues
