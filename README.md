# ITAsset API — 服务端

基于 **FastAPI + PostgreSQL** 的 IT 资产管理后端，为 Windows 客户端（ITAsset4）和 GLPI 插件（admanager）提供统一 API 服务。

## 功能概览

### 🖥️ 终端资产管理
- 终端自动注册与 HMAC 签名认证（设备级安全）
- 硬件信息采集上报（CPU、内存、磁盘、BIOS 序列号）
- 软件清单采集与查询
- 终端在线状态实时检测（WebSocket 心跳）
- 多终端分组管理

### 🖱️ 远程桌面
- 基于 WebSocket 的实时远程桌面（JPEG 帧流）
- 鼠标键盘输入透传
- Session Token 一次性鉴权，安全隔离

### 📦 软件部署
- 安装包上传与管理（最大 500 MB）
- 支持全部 / 分组 / 单台终端推送
- 静默安装、弹窗确认、安装后重启等参数配置
- 任务进度实时查询，失败原因与安装日志记录
- 软件卸载任务

### 🏢 AD 域同步
- Active Directory 用户、OU、分组数据同步到 GLPI
- 企业微信 / 钉钉 / 飞书 IM 账号绑定
- 用户同步状态 diff 追踪

### 📋 审计与日志
- 可执行文件操作审计（ActionAudit）
- 操作审计日志（AuditLog）
- 客户端上报历史记录

## 技术栈

| 组件 | 版本 |
|---|---|
| Python | 3.11+ |
| FastAPI | 0.110+ |
| SQLAlchemy (async) | 2.x |
| PostgreSQL | 14+ |
| WebSocket | 内置 |

## 快速开始

```bash
# 1. 创建虚拟环境
python3 -m venv venv
source venv/bin/activate

# 2. 安装依赖
pip install -r requirements.txt

# 3. 配置环境变量
cp .env.example .env
# 编辑 .env，填写数据库连接和 token

# 4. 初始化数据库
python3 -m app.core.init_db

# 5. 启动（单 worker，WebSocket 共享状态要求）
uvicorn app.main:app --host 0.0.0.0 --port 8000 --workers 1
```

## 环境变量

| 变量 | 说明 | 示例 |
|---|---|---|
| `DATABASE_URL` | PostgreSQL 连接串 | `postgresql+asyncpg://user:pass@localhost/itasset` |
| `AGENT_INITIAL_TOKEN` | 客户端初始注册令牌 | UUID v4 |
| `SECRET_KEY` | 应用密钥 | 随机 32 字符 |
| `SERVER_URL` | 对外服务地址（Agent 回连用） | `http://your-server:8000` |
| `PACKAGES_DIR` | 安装包存储目录 | `/opt/itasset/packages` |

## API 文档

启动后访问：`http://your-server:8000/docs`

## 目录结构

```
app/
├── api/v1/          # 路由（agent, dashboard, groups, websocket, packages...）
├── core/            # 数据库、依赖、安全模块
├── models/          # SQLAlchemy ORM 模型
└── schemas/         # Pydantic 请求/响应 Schema
```

## 相关项目

- [admanager](https://github.com/Gailun90/admanager) — GLPI 插件（前端管理界面）
- [ITAsset4](https://github.com/Gailun90/ITAsset4) — Windows 客户端 Agent

## License

MIT
