"""
# v4.9: session token 安全改进 — 一次性token + Agent端验证 + 断开吊销
# WebSocket endpoints v3: Agent long-connection + Browser remote viewer
v4.8: 支持 binary JPEG 帧（减少 33% 传输量）
- Agent → binary JPEG frame → FastAPI → binary to viewers
- Agent → remote_frame_bin text header → FastAPI → text to viewers (width/height)
- 保留 remote_frame (base64) 兼容旧 Agent
"""
import json
import logging
import asyncio
from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Query, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.core.database import AsyncSessionLocal
from sqlalchemy import update
from app.core.security import verify_hmac_signature
from app.core.deps import require_glpi_token, get_db
from app.core.ws_manager import ws_manager
from app.models.models import Client, DeviceRegistration

router = APIRouter(tags=["websocket"])
logger = logging.getLogger(__name__)

HEARTBEAT_INTERVAL = 60
async def _update_last_seen(serial: str):
    """Update Client.last_seen on WS connect/heartbeat for online detection"""
    try:
        async with AsyncSessionLocal() as db:
            from datetime import datetime, timezone
            await db.execute(
                update(Client).where(Client.hash_serial == serial).values(
                    last_seen=datetime.now(timezone.utc)))
            await db.commit()
    except Exception:
        pass  # best-effort, don't break WS on DB error


# ═══════════════════════════════════════════════════════

# ════════════════════════════════════════════════════════
# Server Info: GET /api/server/info
# ════════════════════════════════════════════════════════

@router.get("/api/server/info")
async def server_info(
    _: bool = Depends(require_glpi_token),
):
    """Return FastAPI SERVER_URL for frontend WebSocket connections"""
    from app.core.config import get_settings
    s = get_settings()
    return {"server_url": s.SERVER_URL, "ws_endpoint": s.WS_ENDPOINT}

# Agent WebSocket: /ws/agent/{serial}
# ═══════════════════════════════════════════════════════

@router.websocket("/ws/agent/{serial}")
async def agent_websocket(
    websocket: WebSocket,
    serial: str,
    timestamp: str = Query(...),
    signature: str = Query(...),
):
    # Auth
    async with AsyncSessionLocal() as db:
        reg_res = await db.execute(
            select(DeviceRegistration).where(
                DeviceRegistration.hash_serial == serial))
        reg = reg_res.scalar_one_or_none()

    if not reg or not verify_hmac_signature(
            serial, timestamp, signature, reg.device_secret_hash):
        await websocket.close(code=4001, reason="auth failed")
        return

    await ws_manager.connect(serial, websocket)
    asyncio.create_task(_update_last_seen(serial))

    try:
        await websocket.send_text(json.dumps({
            "type": "connected",
            "serial": serial,
            "heartbeat_interval": HEARTBEAT_INTERVAL,
        }))

        # ── 重连主动推送：连上就查一次是否有待处理任务，有则立即推送 ──
        # 覆盖"断网重连后要等到下次轮询才能拿到任务"的场景，不用等 client 的轮询周期
        try:
            from sqlalchemy import select as _select
            from app.models.models import Client as _Client, Task as _Task, TaskTarget as _TaskTarget
            async with AsyncSessionLocal() as _db:
                _row = (await _db.execute(
                    _select(_Task.name)
                    .join(_TaskTarget, _TaskTarget.task_id == _Task.id)
                    .join(_Client, _Client.id == _TaskTarget.client_id)
                    .where(_Client.hash_serial == serial, _TaskTarget.status == "pending")
                    .limit(1)
                )).first()
            if _row:
                await ws_manager.send(serial, {"type": "task_push", "task_name": _row[0]})
                logger.info(f"WS重连主动推送: {serial} 有待处理任务 -> {_row[0]}")
        except Exception:
            logger.exception(f"WS重连检查待处理任务失败: {serial}")

        while True:
            try:
                raw = await asyncio.wait_for(
                    websocket.receive(),
                    timeout=HEARTBEAT_INTERVAL + 30,
                )

                # 修复：这里用的是 Starlette 底层 websocket.receive()，返回原始 ASGI
                # 消息字典。客户端真正断开时会收到 {"type": "websocket.disconnect"}，
                # 这种消息既没有 "bytes" 也没有 "text" 字段——此前代码遇到它会直接
                # continue 回到循环顶部再调一次 receive()，但 Starlette 在已经收到
                # disconnect 消息后不允许再次 receive()，会抛
                # "Cannot call receive once a disconnect message has been received."。
                # 结果是：几乎每一次正常断线（客户端更新重启、网络抖动、正常退出）
                # 都会走到这个异常分支，被当成 ERROR 打进日志——3 天内出现了近万次，
                # 但其实绝大多数只是普通的断线，不是真的故障。
                if raw.get("type") == "websocket.disconnect":
                    logger.info(f"WS client disconnect [{serial}]: code={raw.get('code')}")
                    break

                # ★ v4.8: Handle binary messages (raw JPEG frame from agent)
                if "bytes" in raw and raw["bytes"] is not None:
                    # Binary JPEG frame — broadcast as binary to all viewers
                    await ws_manager.broadcast_bytes_to_viewers(
                        serial, raw["bytes"])
                    continue

                # Handle text messages
                if "text" not in raw or raw["text"] is None:
                    continue

                msg = json.loads(raw["text"])
                msg_type = msg.get("type", "")

                if msg_type == "heartbeat":
                    await ws_manager.update_heartbeat(serial)
                    asyncio.create_task(_update_last_seen(serial))
                    await websocket.send_text(json.dumps({
                        "type": "pong",
                        "cpu": msg.get("cpu"),
                        "memory": msg.get("memory"),
                    }))

                elif msg_type == "task_result":
                    logger.info(f"WS task_result from {serial}: {msg}")

                elif msg_type == "status":
                    logger.debug(f"WS status from {serial}: {msg}")

                # ★ v4.8: remote_frame_bin（二进制 JPEG 的尺寸头）
                elif msg_type == "remote_frame_bin":
                    await ws_manager.broadcast_to_remote_viewers(
                        serial, msg)

                # old remote_frame (base64, compat)
                elif msg_type == "remote_frame":
                    await ws_manager.broadcast_to_remote_viewers(
                        serial, msg)

                elif msg_type in ("viewer_ready", "remote_started"):
                    await ws_manager.broadcast_to_remote_viewers(
                        serial, msg)
                else:
                    logger.warning(
                        f"WS unknown msg type [{serial}]: {msg_type}")

            except asyncio.TimeoutError:
                logger.warning(f"WS heartbeat timeout: {serial}")
                break

    except WebSocketDisconnect:
        logger.info(f"WS normal disconnect: {serial}")
    except Exception as e:
        logger.error(f"WS error [{serial}]: {e}")
    finally:
        await ws_manager.disconnect(serial)


# ════════════════════════════════════════════════════════
# Remote Session Request: POST /api/remote/request/{client_id}
# ════════════════════════════════════════════════════════

@router.post("/api/remote/request/{client_id}")
async def request_remote_session(
    client_id: int,
    _: bool = Depends(require_glpi_token),
    db: AsyncSession = Depends(get_db),
):
    """生成远程桌面会话 token，同时通知 Agent"""
    res = await db.execute(select(Client).where(Client.id == client_id))
    client = res.scalar_one_or_none()
    if not client:
        raise HTTPException(status_code=404, detail="客户端不存在")

    token = ws_manager.generate_session(client.hash_serial)
    await ws_manager.send(client.hash_serial, {"type": "remote_start", "session_token": token})
    return {"session_token": token, "hostname": client.hostname}

# ═══════════════════════════════════════════════════════
# Remote Viewer WebSocket: /ws/remote/{client_id}
# ═══════════════════════════════════════════════════════

@router.websocket("/ws/remote/{client_id}")
async def remote_viewer_websocket(
    websocket: WebSocket,
    client_id: str,
    token: str = Query(""),
):
    """Browser remote desktop viewer (with auth)"""
    from app.core.config import get_settings
    settings = get_settings()

    # 必须先 accept() 再做业务校验，否则 Starlette 返回 403
    await websocket.accept()
    client_found = False

    # 认证优先级：
    #   1. 有 token → 尝试 session token 验证（一次性，GLPI 代理生成）
    #   2. token 为空 → 无 GLPI_API_TOKEN 配置时直接放行（内网访问），否则拒绝
    if token:
        serial = ws_manager.validate_session(token)
        if serial:
            logger.info(f"[Remote] viewer connected via session token: {serial}")
            client = type('obj', (object,), {'hash_serial': serial, 'serial': serial})()
            client_found = True
        else:
            logger.warning(f"[Remote] invalid session token: {token!r}")
            await websocket.close(code=4002, reason="invalid session token")
            return
    else:
        # v4.9.1: 无 token → 一律拒绝（消除空 GLPI_API_TOKEN 时认证绕过）
        logger.warning("[Remote] viewer rejected: no session token")
        await websocket.close(code=4001, reason="auth required")
        return

    if not client_found:
        async with AsyncSessionLocal() as db:
            res = await db.execute(
                select(Client).where(Client.id == int(client_id)))
            client = res.scalar_one_or_none()
            if not client:
                await websocket.close(code=4001, reason="client not found")
                return
            serial = client.hash_serial
    await ws_manager.add_viewer(serial, websocket)
    # v4.8.1: 发送 viewer_connected + session_token，Agent 端验证 token 后才启动截图
    # POST /api/remote/request 已经提前把 remote_start + session_token 发给 Agent，
    # 这里只做 viewer 确认，Agent 比对 token 一致才允许截图

    ok = await ws_manager.send(serial, {
        "type": "viewer_connected",
        "session_token": token,
    })
    if not ok:
        await websocket.send_text(json.dumps({
            "type": "error", "code": "agent_offline",
            "message": "viewer_connected failed, agent may have just gone offline"}))
        await websocket.close(code=4002, reason="send failed")
        return
    await websocket.send_text(json.dumps({"type": "viewer_ready", "serial": serial}))
    logger.info(
        f"[Remote] viewer connected: serial={serial}, client_id={client_id}")

    stop_sent = False
    try:
        while True:
            try:
                raw = await asyncio.wait_for(
                    websocket.receive_text(), timeout=45)
            except asyncio.TimeoutError:
                # 超时：发 ping 探测浏览器是否还在
                try:
                    await websocket.send_text(
                        json.dumps({"type": "ping"}))
                except Exception:
                    break  # 浏览器已断开
                continue
            msg = json.loads(raw)
            msg_type = msg.get("type", "")

            if msg_type == "remote_stop":
                stop_sent = True
                await ws_manager.send(serial, {"type": "remote_stop"})
                break
            elif msg_type == "ping":
                await websocket.send_text(json.dumps({"type": "pong"}))
            elif msg_type == "remote_input":
                # click 事件忽略：mousedown+mouseup 已是完整点击，click 会造成双击
                if msg.get('event_type') == 'click':
                    continue
                event_t = msg.get("event_type", "")
                if event_t not in ("move",):
                    logger.info(
                        f"[RemoteInput] viewer->agent serial={serial} "
                        f"type={event_t} btn={msg.get('button')} "
                        f"x={msg.get('mouse_x', 0):.3f} y={msg.get('mouse_y', 0):.3f}")
                ok = await ws_manager.send(serial, msg)
                if not ok:
                    logger.warning(
                        f"[RemoteInput] send failed: agent {serial} offline?")

    except WebSocketDisconnect:
        logger.info(f"Remote viewer disconnected: {serial}")
    except Exception as e:
        logger.error(f"Remote viewer error [{serial}]: {e}")
    finally:
        await ws_manager.remove_viewer(serial, websocket)
        # 浏览器断开时立即吊销 session token，防止重放
        if token:
            ws_manager.revoke_session(token)
        if not stop_sent:
            remaining = len(ws_manager._viewers.get(serial, []))
            if remaining == 0:
                await ws_manager.send(serial, {"type": "remote_stop"})
            else:
                logger.info(f"[Remote] viewer left but {remaining} still watching, skip remote_stop")
