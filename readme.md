# VC Jump

[![CI](https://github.com/Veritas-Calculus/vc-jump/actions/workflows/ci.yml/badge.svg)](https://github.com/Veritas-Calculus/vc-jump/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/Veritas-Calculus/vc-jump)](https://goreportcard.com/report/github.com/Veritas-Calculus/vc-jump)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

轻量级 SSH 堡垒机（Bastion Host），使用 Go 语言编写。

## 功能特性

- 🔐 **SSH 跳板机** - 安全的 SSH 代理，支持公钥和密码认证
- 📹 **会话录像** - 完整记录 SSH 操作过程，支持 asciinema 风格回放
- 📊 **Web Dashboard** - 直观的管理界面，用户/主机/密钥管理
- 🔍 **审计日志** - 详细的操作审计和会话历史
- 🚀 **轻量部署** - 单二进制文件，支持离线环境

## 快速开始

### 安装

从 [Releases](https://github.com/Veritas-Calculus/vc-jump/releases) 下载对应平台的二进制文件：

```bash
# Linux AMD64
curl -LO https://github.com/Veritas-Calculus/vc-jump/releases/latest/download/vc-jump_linux_amd64.tar.gz
tar xzf vc-jump_linux_amd64.tar.gz

# macOS ARM64 (Apple Silicon)
curl -LO https://github.com/Veritas-Calculus/vc-jump/releases/latest/download/vc-jump_darwin_arm64.tar.gz
tar xzf vc-jump_darwin_arm64.tar.gz
```

或者从源码构建：

```bash
go install github.com/Veritas-Calculus/vc-jump/cmd/vc-jump@latest
```

### 配置

创建配置文件 `config.yaml`：

```yaml
server:
  listen_address: ":2222"
  host_key_path: "host_key"

storage:
  type: "sqlite"
  db_path: "./data/vc-jump.db"

recording:
  enabled: true
  path: "./recordings"

dashboard:
  enabled: true
  listen_address: ":8081"
  username: "admin"
  password: "admin123"
```

### 运行

```bash
./vc-jump -config config.yaml
```

### 连接

```bash
# SSH 连接到堡垒机
ssh -p 2222 username@bastion-host

# 访问 Dashboard
open http://bastion-host:8081
```

## 架构

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   Client    │────▶│   vc-jump   │────▶│ Target Host │
│  (SSH)      │     │  (Bastion)  │     │   (SSH)     │
└─────────────┘     └─────────────┘     └─────────────┘
                           │
                    ┌──────┴──────┐
                    │             │
               ┌────▼────┐  ┌────▼────┐
               │ SQLite  │  │Recording│
               │   DB    │  │  Files  │
               └─────────┘  └─────────┘
```

## 开发

### 环境准备

```bash
# 安装开发工具
make install-tools

# 运行测试
make test

# 运行 lint 检查
make lint

# 构建所有平台
make build-all
```

### 项目结构

```
.
├── cmd/vc-jump/        # 程序入口
├── internal/
│   ├── auth/           # 认证模块
│   ├── audit/          # 审计模块
│   ├── config/         # 配置管理
│   ├── dashboard/      # Web Dashboard
│   ├── logger/         # 日志模块
│   ├── proxy/          # SSH 代理
│   ├── recording/      # 会话录像
│   ├── selector/       # 主机选择器
│   ├── server/         # SSH 服务器
│   └── storage/        # 数据存储
├── .github/workflows/  # CI/CD 配置
└── Makefile
```

## API

Dashboard 提供 REST API：

| 端点 | 方法 | 描述 |
|------|------|------|
| `/api/login` | POST | 登录获取 token |
| `/api/overview` | GET | 获取概览数据 |
| `/api/hosts` | GET/POST | 主机管理 |
| `/api/users` | GET/POST | 用户管理 |
| `/api/keys` | GET/POST | 密钥管理 |
| `/api/sessions` | GET | 会话历史 |
| `/api/sessions/active` | GET | 活跃会话 |
| `/api/recordings` | GET | 录像列表 |
| `/api/recordings/:id` | GET | 获取录像内容 |

## 安全

- 所有 SSH 连接使用加密传输
- Dashboard 使用 JWT 认证
- 支持公钥认证
- 会话录像加密存储（可选）

## 贡献

欢迎提交 Issue 和 Pull Request！

1. Fork 本仓库
2. 创建特性分支 (`git checkout -b feature/amazing-feature`)
3. 提交更改 (`git commit -m 'feat: add amazing feature'`)
4. 推送到分支 (`git push origin feature/amazing-feature`)
5. 创建 Pull Request

请确保代码通过所有测试和 lint 检查：

```bash
make test
make lint
```

## 许可证

[MIT License](LICENSE)