import logging
import time
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from app.core.database import engine, Base
from app.core.config import get_settings
from app.api.v1 import agent, packages, dashboard, websocket, groups

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # 启动时自动建表（⚠️ 生产环境应使用 Alembic 迁移，此处仅用于开发）
    logger.warning("使用 create_all 建表，生产环境请切换到 Alembic 迁移！")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    logger.info("数据库表初始化完成")
    yield
    await engine.dispose()
    logger.info("数据库连接已关闭")


app = FastAPI(
    title="ITAsset API",
    description="IT 资产管理与 AD 域管控系统 — FastAPI 服务端 v1.0.0",
    version="1.0.0",
    lifespan=lifespan,
)

settings = get_settings()

# 🔒 问题 23：API 速率限制（防止 DDoS 和暴力破解）
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["200 per minute"],  # 默认限制：每分钟 200 请求
)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
    # 🔒 修复问题6：添加 X-Initial-Token（之前漏了）
    allow_headers=["Authorization", "Content-Type", "X-Serial", "X-Timestamp", "X-Signature", "X-Initial-Token"],
)


# 🔒 问题 26：请求日志中间件
@app.middleware("http")
async def log_requests(request: Request, call_next):
    """记录所有请求（用于审计和调试）"""
    start_time = time.time()
    
    # 跳过健康检查和静态文件（减少日志量）
    if request.url.path in ["/health", "/docs", "/redoc", "/openapi.json"]:
        return await call_next(request)
    
    # 记录请求
    client_ip = request.client.host if request.client else "unknown"
    logger.info(f"Request: {request.method} {request.url.path} from {client_ip}")
    
    response: Response = await call_next(request)
    
    process_time = (time.time() - start_time) * 1000
    logger.info(f"Response: {response.status_code} ({process_time:.2f}ms)")
    
    return response


# 注册路由
app.include_router(agent.router)
app.include_router(packages.router)
app.include_router(dashboard.router)
app.include_router(websocket.router)
app.include_router(groups.router)


@app.get("/health")
async def health():
    """健康检查（TODO: 应检查数据库、Redis 等依赖）"""
    return {"status": "ok", "version": "1.0.0"}
