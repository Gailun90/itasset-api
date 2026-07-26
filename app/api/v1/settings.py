"""
AI 解析设置管理：GET/PUT /api/settings/ai + POST /api/settings/ai/test
鉴权走现有 require_glpi_token（跟其它 GLPI 插件专用接口一致，
真正的"只有部署权限的人能改"由 admanager 那边的 plugin_admanager_deploy 权限门禁负责）
"""
import time
import logging
import httpx
from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from app.core.deps import require_glpi_token, get_db
from app.schemas.schemas import AISettingsOut, AISettingsIn, AITestResult
from app.services.settings_service import (
    get_ai_settings, set_setting, encrypt_value, decrypt_value, get_setting,
)

router = APIRouter(prefix="/api/settings", tags=["settings"])
logger = logging.getLogger(__name__)


@router.get("/ai", response_model=AISettingsOut)
async def read_ai_settings(
    _: bool = Depends(require_glpi_token),
    db: AsyncSession = Depends(get_db),
):
    cfg = await get_ai_settings(db)
    token = cfg["openclaw_token"] or ""
    return AISettingsOut(
        openclaw_url=cfg["openclaw_url"],
        openclaw_model=cfg["openclaw_model"],
        openclaw_timeout=cfg["openclaw_timeout"],
        llm_enabled=cfg["llm_enabled"],
        openclaw_prompt=cfg["openclaw_prompt"],
        token_configured=bool(token),
        token_last4=(token[-4:] if len(token) >= 4 else None),
    )


@router.put("/ai", response_model=AISettingsOut)
async def save_ai_settings(
    body: AISettingsIn,
    _: bool = Depends(require_glpi_token),
    db: AsyncSession = Depends(get_db),
):
    await set_setting(db, "ai.openclaw_url", body.openclaw_url, updated_by="glpi")
    await set_setting(db, "ai.openclaw_model", body.openclaw_model, updated_by="glpi")
    await set_setting(db, "ai.openclaw_timeout", str(body.openclaw_timeout), updated_by="glpi")
    await set_setting(db, "ai.llm_enabled", "true" if body.llm_enabled else "false", updated_by="glpi")
    await set_setting(db, "ai.openclaw_prompt", body.openclaw_prompt or "", updated_by="glpi")

    if body.clear_token:
        await set_setting(db, "ai.openclaw_token", None, updated_by="glpi")
    elif body.openclaw_token:
        # 只有真的传了新 token 才更新；留空代表不改动已保存的 token
        await set_setting(db, "ai.openclaw_token", encrypt_value(body.openclaw_token), updated_by="glpi")

    await db.commit()
    return await read_ai_settings(_, db)


@router.post("/ai/test", response_model=AITestResult)
async def test_ai_connection(
    body: AISettingsIn,
    _: bool = Depends(require_glpi_token),
    db: AsyncSession = Depends(get_db),
):
    """用页面上（可能还没保存）的参数做一次最小化测试请求，不落库"""
    token = body.openclaw_token
    if not token and not body.clear_token:
        # 页面没填新 token，用已保存的（脱敏展示的场景下测试已保存的配置）
        saved = await get_setting(db, "ai.openclaw_token")
        token = decrypt_value(saved) if saved else None

    if not token:
        return AITestResult(ok=False, error="未配置 token，无法测试")

    start = time.monotonic()
    try:
        async with httpx.AsyncClient(timeout=min(body.openclaw_timeout, 30)) as client:
            resp = await client.post(
                f"{body.openclaw_url.rstrip('/')}/chat/completions",
                headers={"Authorization": f"Bearer {token}"},
                json={
                    "model": body.openclaw_model,
                    "messages": [{"role": "user", "content": "ping，请只回复 pong"}],
                    "max_tokens": 10,
                    "stream": False,
                },
            )
        latency = int((time.monotonic() - start) * 1000)
        if resp.status_code != 200:
            return AITestResult(ok=False, latency_ms=latency,
                                 error=f"HTTP {resp.status_code}: {resp.text[:300]}")
        return AITestResult(ok=True, latency_ms=latency)
    except Exception as ex:
        latency = int((time.monotonic() - start) * 1000)
        return AITestResult(ok=False, latency_ms=latency, error=str(ex)[:300])
