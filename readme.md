# VC Jump

[![CI](https://github.com/Veritas-Calculus/vc-jump/actions/workflows/ci.yml/badge.svg)](https://github.com/Veritas-Calculus/vc-jump/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/Veritas-Calculus/vc-jump)](https://goreportcard.com/report/github.com/Veritas-Calculus/vc-jump)
[![Security Scan](https://github.com/Veritas-Calculus/vc-jump/actions/workflows/security.yml/badge.svg)](https://github.com/Veritas-Calculus/vc-jump/actions/workflows/security.yml)
[![CodeQL](https://github.com/Veritas-Calculus/vc-jump/actions/workflows/codeql.yml/badge.svg)](https://github.com/Veritas-Calculus/vc-jump/actions/workflows/codeql.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Go Version](https://img.shields.io/github/go-mod/go-version/Veritas-Calculus/vc-jump)](https://go.dev/)

轻量级 SSH 堡垒机（Bastion Host），使用 Go 语言编写。单二进制文件部署，内置 Web 管理界面。

## 功能特性

- **SSH 跳板机** - SSH 代理转发，支持公钥和密码认证，主机选择器交互式选择目标
- **会话录像** - 完整记录 SSH 操作过程，支持本地和 S3 兼容存储，支持实时观看活跃会话
- **Web Dashboard** - 管理界面，涵盖主机、用户、SSH 密钥、文件夹、会话和录像管理
- **RBAC 权限控制** - 基于角色的细粒度访问控制，5 个预置角色、22 项权限，支持按主机分配权限
- **OTP 双因素认证** - 基于 TOTP 的双因素认证，支持 QR 码配置，可全局强制启用
- **审计日志** - 记录登录、连接、操作事件，支持按用户/事件类型/时间范围查询和统计
- **API Key 认证** - 面向自动化和 IaC (Terraform) 场景的长期 API Key，支持 scope 限定和轮替
- **声明式 IAM** - 支持 `PUT` 全量覆盖的角色/权限分配接口，天然适配 Terraform Drift Detection
- **OpenAPI 规范** - 提供 OpenAPI 3.1 规范文件 (`openapi.yaml`)，覆盖全部 API 端点
- **轻量部署** - 单二进制文件，SQLite 存储，支持 Docker 部署

## 快速开始

### 安装

从 [Releases](https://github.com/Veritas-Calculus/vc-jump/releases) 下载对应平台的二进制文件：

```bash
# Linux AMD64
curl -LO https://github.com/Veritas-Calculus/vc-jump/releases/latest/download/vc-jump-linux-amd64
chmod +x vc-jump-linux-amd64

# macOS ARM64 (Apple Silicon)
curl -LO https://github.com/Veritas-Calculus/vc-jump/releases/latest/download/vc-jump-darwin-arm64
chmod +x vc-jump-darwin-arm64
```

或者从源码构建：

```bash
git clone https://github.com/Veritas-Calculus/vc-jump.git
cd vc-jump
make build
```

### 配置

创建配置文件 `config.yaml`（参考 `config.example.yaml`）：

```yaml
server:
  listen_addr: ":2222"
  host_key_path: "./host_key"
  max_connections: 100

storage:
  type: "sqlite"
  db_path: "./data/vc-jump.db"

recording:
  enabled: true
  storage_type: "local"    # "local" 或 "s3"
  local_path: "./recordings"

dashboard:
  enabled: true
  listen_addr: ":8080"
  username: "admin"
  password: "changeme"
  # enable_https: true
  # cert_file: "./cert.pem"
  # key_file: "./key.pem"
  session_timeout: "24h"

audit:
  enabled: true
  storage_type: "local"
  local_path: "./audit"

session:
  idle_timeout: 30m
  max_duration: 8h

otp:
  force_enabled: false     # 全局强制启用 OTP
  issuer: "VC-Jump"        # 认证器 App 中显示的名称

logging:
  level: "info"
  format: "json"
  output: "stdout"
```

完整配置项说明见 `config.example.yaml`，包括 S3 录像存储、HTTPS、OTP 等高级配置。

### 运行

```bash
./vc-jump -config config.yaml
```

查看版本信息：

```bash
./vc-jump -version
```

### Docker 部署

```bash
# 构建镜像
make docker-build

# 或直接使用 Docker
docker build -t vc-jump .
docker run -p 2222:2222 -p 8080:8080 -v ./data:/app/data vc-jump -config /app/config.yaml
```

### 连接

```bash
# SSH 连接到堡垒机，交互式选择目标主机
ssh -p 2222 username@bastion-host

# 访问 Dashboard
open http://bastion-host:8080
```

## 架构

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   Client    │────>│   vc-jump   │────>│ Target Host │
│  (SSH)      │     │  (Bastion)  │     │   (SSH)     │
└─────────────┘     └──────┬──────┘     └─────────────┘
                           │
              ┌────────────┼────────────┐
              │            │            │
         ┌────▼────┐  ┌────▼────┐  ┌────▼────┐
         │ SQLite  │  │Recording│  │  Audit  │
         │   DB    │  │  Store  │  │   Log   │
         └─────────┘  └─────────┘  └─────────┘
```

## Terraform / IaC 集成

VC Jump 的 API 完整支持 Infrastructure as Code 自动化编排：

- **API Key 认证** — 通过 `POST /api/api-keys` 创建长期有效的 API Key（`vcj_` 前缀），用于 Terraform Provider 无交互鉴权。API Key 使用 SHA256 哈希存储，明文仅在创建时显示一次。
- **声明式 IAM** — `PUT /api/users/:id/roles` 和 `PUT /api/users/:id/host-permissions` 支持全量覆盖的声明式状态管理，返回变更 diff（added/removed/updated），天然适配 Terraform 的 Drift Detection。
- **标准 RESTful 路由** — 所有核心资源（Hosts、Users、Folders、Roles）均提供 ID 路由的 `GET/POST/PUT/DELETE` 接口，完美契合 Terraform 的状态管理模型。
- **OpenAPI 3.1 规范** — 提供 `openapi.yaml` 覆盖全部 36+ 端点，可用于自动生成 Terraform Provider 或 SDK。

---

## 开发

### 环境要求

- Go 1.24+
- golangci-lint（可选，用于 lint 检查）

### 常用命令

```bash
make build          # 构建当前平台
make build-all      # 构建所有平台（linux/darwin/windows, amd64/arm64）
make test           # 运行全部测试
make test-short     # 运行快速测试
make coverage       # 生成覆盖率报告
make lint           # 运行 lint 检查
make lint-fix       # 运行 lint 并自动修复
make fmt            # 代码格式化
make security       # 运行安全扫描
make install-tools  # 安装开发工具
make docker-build   # 构建 Docker 镜像
make clean          # 清理构建产物
```

### 项目结构

```
.
├── cmd/vc-jump/           # 程序入口
├── internal/
│   ├── audit/             # 审计日志
│   ├── auth/              # 认证（密码哈希、Token、会话管理）
│   ├── config/            # 配置管理
│   ├── dashboard/         # Web Dashboard 及 REST API
│   ├── integration/       # 集成测试
│   ├── logger/            # 日志模块
│   ├── otp/               # TOTP 双因素认证
│   ├── proxy/             # SSH 代理转发
│   ├── rbac/              # RBAC 角色权限控制
│   ├── recording/         # 会话录像（本地 / S3）
│   ├── selector/          # 主机选择器
│   ├── server/            # SSH 服务器
│   ├── sshkey/            # SSH 密钥生成与管理
│   └── storage/           # 数据存储（SQLite / 文件）
├── .github/workflows/     # CI/CD（测试、Lint、安全扫描、CodeQL、DAST、Docker）
├── openapi.yaml           # OpenAPI 3.1 规范
├── Dockerfile
├── Makefile
└── config.example.yaml
```

## API

Dashboard 提供 REST API，支持以下认证方式：
- **Session Token** — 通过 `POST /api/login` 登录获取，使用 `Authorization: Bearer <token>` 或 `session` Cookie 传递
- **API Key** — 通过 `POST /api/api-keys` 创建，使用 `Authorization: Bearer vcj_<token>` 传递，适合自动化和 IaC 场景

完整的 API 文档详见 [`openapi.yaml`](openapi.yaml)。

### 认证

| 端点 | 方法 | 描述 |
|------|------|------|
| `/api/login` | POST | 登录，返回 session token |
| `/api/logout` | POST | 注销当前会话 |
| `/api/me` | GET | 获取当前用户信息（含角色和权限） |

### 主机管理

| 端点 | 方法 | 描述 |
|------|------|------|
| `/api/hosts` | GET | 获取主机列表 |
| `/api/hosts` | POST | 创建主机 |
| `/api/hosts/:id` | GET/PUT/DELETE | 查看、更新、删除主机 |

### 文件夹管理

| 端点 | 方法 | 描述 |
|------|------|------|
| `/api/folders` | GET | 获取文件夹列表（支持 `?tree=true` 树形结构） |
| `/api/folders` | POST | 创建文件夹 |
| `/api/folders/:id` | GET/PUT/DELETE | 查看、更新、删除文件夹 |

### 用户管理

| 端点 | 方法 | 描述 |
|------|------|------|
| `/api/users` | GET | 获取用户列表 |
| `/api/users` | POST | 创建用户（支持指定角色） |
| `/api/users/:id` | GET/PUT/DELETE | 查看、更新、删除用户 |
| `/api/users/:id/roles` | GET | 获取用户的角色列表 |
| `/api/users/:id/roles` | PUT | 声明式设置用户角色（全量覆盖） |
| `/api/users/:id/host-permissions` | GET | 获取用户的主机权限 |
| `/api/users/:id/host-permissions` | PUT | 声明式设置用户主机权限（全量覆盖） |

### SSH 密钥管理

| 端点 | 方法 | 描述 |
|------|------|------|
| `/api/keys` | GET | 获取密钥列表 |
| `/api/keys` | POST | 生成密钥（ed25519 / rsa-4096 / rsa-2048） |
| `/api/keys/:id` | GET/DELETE | 查看、删除密钥 |

### 会话与录像

| 端点 | 方法 | 描述 |
|------|------|------|
| `/api/sessions` | GET | 会话历史 |
| `/api/sessions/active` | GET | 活跃会话列表 |
| `/api/sessions/live` | GET | 实时录像会话列表 |
| `/api/sessions/watch/:id` | WebSocket | 实时观看活跃会话 |
| `/api/recordings` | GET | 录像文件列表 |
| `/api/recordings` | DELETE | 批量删除录像 |
| `/api/recordings/:filename` | GET/DELETE | 下载或删除单个录像 |

### IAM 权限管理

| 端点 | 方法 | 描述 |
|------|------|------|
| `/api/roles` | GET/POST | 角色列表 / 创建角色 |
| `/api/roles/:id` | GET/PUT/DELETE | 查看、更新、删除角色 |
| `/api/iam/roles` | GET/POST | 角色列表（同 `/api/roles`） |
| `/api/iam/roles/:id` | GET/PUT/DELETE | 角色详情（同 `/api/roles/:id`） |
| `/api/iam/user-roles/:userID` | GET/POST/DELETE | 用户角色分配（⚠️ 已废弃，使用 `/api/users/:id/roles`） |
| `/api/iam/host-permissions` | GET/POST | 主机权限查询与授权 |
| `/api/iam/host-permissions/:id` | DELETE | 撤销主机权限 |
| `/api/iam/permissions` | GET | 权限清单（22 项权限） |

### API Key 管理

| 端点 | 方法 | 描述 |
|------|------|------|
| `/api/api-keys` | GET | 获取当前用户的 API Key 列表 |
| `/api/api-keys` | POST | 创建 API Key（明文仅返回一次） |
| `/api/api-keys/:id` | GET | 获取 API Key 元数据 |
| `/api/api-keys/:id` | DELETE | 删除 API Key |
| `/api/api-keys/:id/rotate` | POST | 轮替 API Key（生成新 token） |

### OTP 双因素认证

| 端点 | 方法 | 描述 |
|------|------|------|
| `/api/otp/status` | GET | 获取当前用户 OTP 状态 |
| `/api/otp/setup` | POST | 生成 TOTP 密钥和 QR 码 |
| `/api/otp/verify` | POST | 验证 OTP 并启用双因素认证 |
| `/api/otp` | DELETE | 关闭 OTP |
| `/api/settings/otp` | GET/PUT | 全局 OTP 设置（管理员） |

### 审计日志

| 端点 | 方法 | 描述 |
|------|------|------|
| `/api/audit` | GET | 查询审计日志（支持按用户/事件/时间过滤） |
| `/api/audit/stats` | GET | 24 小时审计统计 |

### 概览

| 端点 | 方法 | 描述 |
|------|------|------|
| `/api/stats` | GET | 系统概览（主机数、用户数、会话数、密钥数） |

## 安全

- SSH 连接全程加密
- Dashboard 支持 HTTPS（配置 `enable_https`、`cert_file`、`key_file`）
- 基于 Session Token / Cookie / API Key 的多种认证方式，可配置超时时间
- API Key 使用 SHA256 哈希存储，明文仅在创建时显示一次
- API Key 带 `vcj_` 前缀，Gitleaks 自动检测泄漏
- TOTP 双因素认证，支持全局强制启用
- RBAC 细粒度权限控制，按主机分配访问权限（支持 sudo 标记和过期时间）
- 安全响应头：X-Frame-Options、CSP、Cross-Origin 策略
- 录像文件路径遍历防护
- 废弃路由添加 RFC 8594 Deprecation / Sunset / Link header
- CI 集成 govulncheck、gosec、CodeQL、Trivy、Gitleaks、DAST 扫描

## 贡献

欢迎提交 Issue 和 Pull Request。

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