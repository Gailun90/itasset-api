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
import os
from functools import lru_cache
from fastapi import Header, HTTPException, Depends, Request
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.core.database import get_db
from app.core.config import get_settings
from app.core.security import verify_initial_token, verify_hmac_signature
from app.core.mtls import (
    verify_client_cert, cert_fingerprint, decode_nginx_client_cert,
)
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
    request: Request,
    x_serial:    str = Header(..., alias="X-Serial"),
    x_timestamp: str = Header(..., alias="X-Timestamp"),
    x_signature: str = Header(..., alias="X-Signature"),
    x_ssl_client_verify: str | None = Header(None, alias="X-Ssl-Client-Verify"),
    x_ssl_client_cert:   str | None = Header(None, alias="X-Ssl-Client-Cert"),
    db: AsyncSession = Depends(get_db),
) -> Client:
    """
    正常通信认证（HMAC 第一因子）：
    1. 查找 DeviceRegistration，取 device_secret_hash
    2. 用 device_secret_hash 作为 HMAC key 验签
       （客户端注册收到 DeviceSecret 后，对其取 SHA256 作为签名 key）
    3. 最终形态·一：mTLS 第二因子（传输层互信闸门）
       - MTLS_ENABLED=False（默认/不部署生产前）：require_mtls_agent 直接放行，
         不破坏现有终端行为；
       - MTLS_ENABLED=True：必须携带受信 CA 签发的有效客户端证书，否则 401。
    """
    # 最终形态·一：mTLS 双因子（HMAC 已识别身份，证书证明传输层互信）
    await require_mtls_agent(request, x_ssl_client_verify, x_ssl_client_cert)

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
    """GLPI 插件调用：Bearer Token 验证
    
    🔒 安全修复 v6.1：不再回退到 AGENT_INITIAL_TOKEN
    GLPI_API_TOKEN 必须单独设置，不能与 Agent 初始 Token 相同
    """
    from app.core.config import get_settings
    settings = get_settings()
    
    if not settings.GLPI_API_TOKEN:
        logger.error("GLPI_API_TOKEN 未配置，拒绝所有 GLPI 端点访问")
        raise HTTPException(status_code=500, detail="服务器配置错误：GLPI_API_TOKEN 未设置")
    
    scheme, _, token = authorization.partition(" ")
    # 防御性 strip：.env 曾经是 CRLF 换行导致 GLPI_API_TOKEN 读出来带了一个隐藏的 \r，
    # 跟 PHP 侧粘贴配置时如果也带了不可见字符，会导致两边比较永远不相等，或者
    # 更糟——把这个带 \r 的值原样拼进 Authorization 头，被 h11 当成非法请求直接拒绝
    # （裸 CR 破坏 HTTP 头帧结构），报 "Invalid HTTP request received."。
    # 这里对两边都做 strip，防止任何一边再次因为不可见空白字符出问题。
    if scheme.lower() != "bearer" or token.strip() != settings.GLPI_API_TOKEN.strip():
        raise HTTPException(status_code=401, detail="Token 无效")
    return True


# ── 最终形态·一：mTLS 客户端证书校验（与 HMAC 并存，双因子）────────────────────
@lru_cache(maxsize=1)
def _load_ca_pem(path: str) -> bytes:
    with open(path, "rb") as f:
        return f.read()


async def require_mtls_agent(
    request: Request,
    x_ssl_client_verify: str = Header(None, alias="X-Ssl-Client-Verify"),
    x_ssl_client_cert: str = Header(None, alias="X-Ssl-Client-Cert"),
) -> str | None:
    """mTLS 客户端证书校验（最终形态·一）。

    与 HMAC（require_agent_auth）并存：HMAC 是第二因子，本依赖是传输层互信闸门。
    - MTLS_ENABLED=False（默认）：直接放行，不影响现有行为（不部署生产前的兼容态）。
    - MTLS_ENABLED=True：
        * 从 nginx 透传的 X-Ssl-Client-Verify / X-Ssl-Client-Cert 取客户端证书；
        * 校验是否由受信 CA 签发且未过期；
        * 成功返回证书指纹（小写 sha256 hex），供上层映射到已注册 Agent；
        * 校验失败且 MTLS_CLIENT_CERT_REQUIRED=True → 401。
    """
    settings = get_settings()
    if not getattr(settings, "MTLS_ENABLED", False):
        return None
    ca_path = getattr(settings, "MTLS_CA_CERT_PATH", "") or ""
    if not ca_path or not os.path.isfile(ca_path):
        raise HTTPException(
            status_code=500,
            detail="服务器配置错误：MTLS_CA_CERT_PATH 未设置或文件缺失")

    # 取客户端证书：优先 nginx 透传头；其次 uvicorn 直连 scope.ssl
    cert_pem: bytes | None = None
    if (x_ssl_client_verify and x_ssl_client_verify.strip().upper() == "SUCCESS"
            and x_ssl_client_cert):
        try:
            cert_pem = decode_nginx_client_cert(x_ssl_client_cert)
        except Exception:
            cert_pem = None
    if cert_pem is None:
        scope_ssl = (request.scope.get("ssl") or {})
        direct = scope_ssl.get("client_cert")
        if direct is not None:
            cert_pem = direct if isinstance(direct, bytes) else str(direct).encode("utf-8")

    if cert_pem is None:
        if getattr(settings, "MTLS_CLIENT_CERT_REQUIRED", True):
            raise HTTPException(status_code=401, detail="mTLS：缺少客户端证书")
        return None

    ca_pem = _load_ca_pem(ca_path)
    if not verify_client_cert(cert_pem, ca_pem):
        raise HTTPException(
            status_code=401,
            detail="mTLS：客户端证书校验失败（非受信 CA 或已过期）")
    return cert_fingerprint(cert_pem)
