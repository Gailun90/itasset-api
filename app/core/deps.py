"""
# v4.9: DeviceRegistration.serial → hash_serial, Client.serial → hash_serial fix
依赖注入：Agent 请求认证
两种认证模式：
  1. 注册阶段：Header X-Initial-Token
  2. 正常通信：Header X-Serial + X-Timestamp + X-Signature
     签名 = HmacSHA256("{timestamp}:{serial}", SHA256(DeviceSecret))
     即：客户端先对自己的 DeviceSecret 取 SHA256，用该哈希值做 HMAC key
     服务器直接用存储的 device_secret_hash 验证，无需存原文
"""
import logging
from fastapi import Header, HTTPException, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.core.database import get_db
from app.core.security import verify_initial_token, verify_hmac_signature
from app.models.models import Client, DeviceRegistration

logger = logging.getLogger(__name__)


async def require_initial_token(
    x_initial_token: str = Header(..., alias="X-Initial-Token"),
):
    """注册阶段：验证初始 Token"""
    if not verify_initial_token(x_initial_token):
        raise HTTPException(status_code=401, detail="初始 Token 无效")
    return True


async def require_agent_auth(
    x_serial:    str = Header(..., alias="X-Serial"),
    x_timestamp: str = Header(..., alias="X-Timestamp"),
    x_signature: str = Header(..., alias="X-Signature"),
    db: AsyncSession = Depends(get_db),
) -> Client:
    """
    正常通信认证：
    1. 查找 DeviceRegistration，取 device_secret_hash
    2. 用 device_secret_hash 作为 HMAC key 验签
       （客户端注册收到 DeviceSecret 后，对其取 SHA256 作为签名 key）
    """
    reg_res = await db.execute(
        select(DeviceRegistration).where(DeviceRegistration.hash_serial == x_serial)
    )
    reg = reg_res.scalar_one_or_none()
    if not reg:
        raise HTTPException(status_code=401, detail="终端未注册")

    # device_secret_hash = SHA256(DeviceSecret)，直接用作 HMAC key
    if not verify_hmac_signature(x_serial, x_timestamp, x_signature, reg.device_secret_hash):
        raise HTTPException(status_code=401, detail="签名验证失败")

    # 返回 Client 对象
    client_res = await db.execute(
        select(Client).where(Client.hash_serial == x_serial)
    )
    client = client_res.scalar_one_or_none()
    if not client:
        raise HTTPException(status_code=401, detail="终端记录不存在")

    return client


async def require_glpi_token(
    authorization: str = Header(...),
) -> bool:
    """GLPI 插件调用：Bearer Token 验证"""
    from app.core.config import get_settings
    settings = get_settings()
    scheme, _, token = authorization.partition(" ")
    glpi_tok = settings.GLPI_API_TOKEN or settings.AGENT_INITIAL_TOKEN
    if scheme.lower() != "bearer" or token != glpi_tok:
        raise HTTPException(status_code=401, detail="Token 无效")
    return True
