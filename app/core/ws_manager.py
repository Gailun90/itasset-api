import asyncio
import json
import time
import logging
import secrets
from typing import Dict, List, Optional
from dataclasses import dataclass, field
from fastapi import WebSocket

logger = logging.getLogger(__name__)


@dataclass
class ClientConnection:
    """Agent connection state"""
    serial: str
    websocket: WebSocket
    connected_at: float = field(default_factory=time.time)
    last_heartbeat: float = field(default_factory=time.time)

    def is_closed(self) -> bool:
        return (hasattr(self.websocket, 'close_code')
                and self.websocket.close_code is not None)


class ConnectionManager:
    """
    # v4.9: +revoke_session, import secrets fix
    WebSocket connection manager v2
    - ClientConnection wraps connection metadata
    - Safe old-connection eviction
    - Auto-clean empty viewer lists
    - Supports both text and binary send modes
    """

    def __init__(self):
        self._connections: Dict[str, ClientConnection] = {}
        self._viewers: Dict[str, List[WebSocket]] = {}
        self._sessions: Dict[str, tuple] = {}  # token -> (serial, expires_at)
        self._lock = asyncio.Lock()

    # ================================================================
    # Agent connections
    # ================================================================

    async def connect(self, serial: str, ws: WebSocket) -> None:
        await ws.accept()
        old: Optional[ClientConnection] = None
        async with self._lock:
            if serial in self._connections:
                old = self._connections[serial]
            self._connections[serial] = ClientConnection(
                serial=serial, websocket=ws)

        # Close old ws outside the lock to avoid deadlock
        if old is not None and old.websocket is not ws:
            try:
                if not old.is_closed():
                    await old.websocket.close(code=1001, reason='replaced')
            except Exception:
                pass
        logger.info(f'WS connected: {serial} (total={len(self._connections)})')

    async def disconnect(self, serial: str) -> None:
        async with self._lock:
            self._connections.pop(serial, None)
        logger.info(f'WS disconnected: {serial}')
        # agent 断线时通知所有 viewer，避免画面冻住无感知
        viewers = list(self._viewers.get(serial, []))
        for ws in viewers:
            try:
                await ws.send_text(json.dumps({
                    "type": "agent_offline",
                    "serial": serial,
                    "message": "Agent disconnected, waiting for reconnect..."
                }))
            except Exception:
                pass

    async def send(self, serial: str, payload: dict) -> bool:
        """Push text message to agent"""
        conn = self._connections.get(serial)
        if not conn:
            return False
        try:
            if conn.is_closed():
                logger.warning(f'WS [{serial}] already closed, removing')
                await self.disconnect(serial)
                return False
            await conn.websocket.send_text(
                json.dumps(payload, ensure_ascii=False))
            return True
        except Exception as e:
            logger.warning(f'WS send failed [{serial}]: {e}')
            await self.disconnect(serial)
            return False

    async def send_bytes(self, serial: str, data: bytes) -> bool:
        """Push binary message to agent (remote_frame only)"""
        conn = self._connections.get(serial)
        if not conn:
            return False
        try:
            if conn.is_closed():
                logger.warning(f'WS [{serial}] already closed, removing')
                await self.disconnect(serial)
                return False
            await conn.websocket.send_bytes(data)
            return True
        except Exception as e:
            logger.warning(f'WS send_bytes failed [{serial}]: {e}')
            await self.disconnect(serial)
            return False

    # ================================================================
    # Viewer management
    # ================================================================

    async def accept_viewer(self, serial: str, ws: WebSocket) -> None:
        """Accept WS and add to viewers (legacy)"""
        await ws.accept()
        async with self._lock:
            self._viewers.setdefault(serial, []).append(ws)

    # -- session tokens --
    SESSION_TTL = 300  # 5 min

    def _clean_expired_sessions(self):
        now = time.time()
        expired = [t for t, (_, exp) in self._sessions.items() if exp < now]
        for t in expired:
            self._sessions.pop(t, None)
        if expired:
            logger.debug(f"Cleaned {len(expired)} expired session tokens")

    def generate_session(self, serial: str) -> str:
        self._clean_expired_sessions()
        token = secrets.token_urlsafe(32)
        self._sessions[token] = (serial, time.time() + self.SESSION_TTL)
        logger.info(f"Session token generated for {serial}: {token[:12]}...")
        return token
    # Note: _sessions is accessed without _lock here.
    # Safe under pure asyncio; if threads are introduced, wrap in async lock.

    def validate_session(self, token: str) -> Optional[str]:
        entry = self._sessions.get(token)
        if entry is None:
            return None
        serial, expires = entry
        if time.time() > expires:
            self._sessions.pop(token, None)
            return None
        return serial

    def revoke_session(self, token: str) -> None:
        serial = self._sessions.pop(token, None)
        if serial:
            logger.info(f"Session revoked: {token[:12]}... ({serial})")

    async def add_viewer(self, serial: str, ws: WebSocket) -> None:
        """Add already-accepted WS to viewers (no accept)"""
        async with self._lock:
            self._viewers.setdefault(serial, []).append(ws)

    async def remove_viewer(self, serial: str, ws: WebSocket) -> None:
        async with self._lock:
            if serial not in self._viewers:
                return
            self._viewers[serial] = [
                v for v in self._viewers[serial] if v is not ws]
            # Auto-clean empty lists to avoid memory leak
            if not self._viewers[serial]:
                del self._viewers[serial]

    async def broadcast_to_remote_viewers(
            self, serial: str, payload: dict) -> None:
        """Forward frame to all viewers (text json, browser-compatible)"""
        viewers = list(self._viewers.get(serial, []))  # 快照
        if not viewers:
            return
        text = json.dumps(payload, ensure_ascii=False)
        dead: List[WebSocket] = []
        for ws in viewers:
            try:
                await ws.send_text(text)
            except Exception:
                dead.append(ws)
        for ws in dead:
            await self.remove_viewer(serial, ws)

    async def broadcast_bytes_to_viewers(
            self, serial: str, data: bytes) -> None:
        """Forward binary frame to all viewers (v2 binary mode)"""
        viewers = list(self._viewers.get(serial, []))  # 快照，避免遍历时被修改
        if not viewers:
            return
        dead: List[WebSocket] = []
        for ws in viewers:
            try:
                await ws.send_bytes(data)
            except Exception:
                dead.append(ws)
        for ws in dead:
            await self.remove_viewer(serial, ws)

    async def broadcast(
            self, payload: dict, serials: Optional[list] = None) -> None:
        targets = serials or list(self._connections.keys())
        tasks = [self.send(s, payload) for s in targets]
        await asyncio.gather(*tasks, return_exceptions=True)

    # ================================================================
    # Status queries
    # ================================================================

    def is_online(self, serial: str) -> bool:
        return serial in self._connections

    def online_count(self) -> int:
        return len(self._connections)

    def online_serials(self) -> List[str]:
        return list(self._connections.keys())

    async def update_heartbeat(self, serial: str) -> None:
        async with self._lock:
            conn = self._connections.get(serial)
            if conn:
                conn.last_heartbeat = time.time()


ws_manager = ConnectionManager()
