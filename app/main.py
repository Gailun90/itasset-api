import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
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
    # 启动时自动建表
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
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
    allow_headers=["Authorization", "Content-Type", "X-Serial", "X-Timestamp", "X-Signature"],
)

# 注册路由
app.include_router(agent.router)
app.include_router(packages.router)
app.include_router(dashboard.router)
app.include_router(websocket.router)
app.include_router(groups.router)


@app.get("/health")
async def health():
    return {"status": "ok", "version": "1.0.0"}
