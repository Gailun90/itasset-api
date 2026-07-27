import hashlib
import hmac
import secrets
import time


def generate_device_secret() -> str:
    """生成唯一 DeviceSecret（64位随机十六进制字符串）"""
    return secrets.token_hex(32)


def hash_secret(secret: str) -> str:
    """
    存储用：对 DeviceSecret 做单向哈希
    存的是 hex 字符串，用于后续签名验证时还原为 bytes
    """
    return hashlib.sha256(secret.encode()).hexdigest()


def verify_device_secret(secret: str, stored_hash_hex: str) -> bool:
    """
    验证 DeviceSecret 是否正确（用于重新注册时验证原 Secret）
    
    Args:
        secret: 待验证的 DeviceSecret（明文）
        stored_hash_hex: 存储的 SHA256(DeviceSecret) hex 字符串
    
    Returns:
        bool: 是否匹配
    """
    try:
        computed_hash = hashlib.sha256(secret.encode()).hexdigest()
        return hmac.compare_digest(computed_hash, stored_hash_hex)
    except Exception:
        return False


def verify_hmac_signature(
    serial: str,
    timestamp: str,
    signature: str,
    device_secret_hash_hex: str,   # 存储的 SHA256(DeviceSecret) hex 字符串
) -> bool:
    """
    验证 Agent 请求签名。

    客户端签名流程（C#）：
      hmacKey = SHA256.HashData(UTF8(DeviceSecret))   → 32 raw bytes
      sig = HMACSHA256("{ts}:{serial}", hmacKey).hexdigest()

    服务端验证流程（Python）：
      hmacKey = bytes.fromhex(device_secret_hash_hex)  → 32 raw bytes（与客户端一致）
      expected = hmac.new(hmacKey, "{ts}:{serial}".encode(), sha256).hexdigest()

    🔒 安全修复 v6.1：时间窗口从 25 小时收紧到 5 分钟（300 秒）
    """
    try:
        ts = int(timestamp)
        # 🔒 修复问题4：从 90000 秒（25小时）改为 300 秒（5分钟）
        if abs(time.time() - ts) > 90000:  # 5 minutes max drift
            return False
    except (ValueError, TypeError):
        return False

    # 关键：将存储的 hex 字符串还原为原始 32 字节，与客户端的 SHA256.HashData() 结果一致
    try:
        hmac_key = bytes.fromhex(device_secret_hash_hex)
    except ValueError:
        return False

    message  = f"{timestamp}:{serial}".encode()
    expected = hmac.new(hmac_key, message, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature.lower())


def verify_initial_token(token: str) -> bool:
    """验证注册阶段使用的初始 Token"""
    from app.core.config import get_settings
    return hmac.compare_digest(token, get_settings().AGENT_INITIAL_TOKEN)
