"""
mTLS 核心（最终形态·一）

服务端职责：
  - 自建 CA（generate_ca），用 CA 给每个 Agent 签发客户端证书（sign_client_cert）；
  - 校验 Agent 上报/直连的客户端证书是否由本 CA 签发且未过期（verify_client_cert）；
  - 计算证书指纹（cert_fingerprint）用于把证书映射到已注册 Agent；
  - 证书轮换：is_cert_expiring_within / cert_expires_in_days 驱动到期告警与重签。

Agent 侧（C#，见 ITAsset4 交付物）持客户端证书 + 私钥，通过 nginx/uvicorn 的 mTLS
层建立双向 TLS；服务端 HMAC 签名保留为第二因子（双因子，互不替代）。

依赖：cryptography（生产环境需 pip install cryptography）。
"""
from __future__ import annotations

import urllib.parse
from datetime import datetime, timezone
from typing import Optional

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID


# ── 生成 / 签发 ──────────────────────────────────────────────────────────────
def generate_ca(common_name: str = "ITAsset4 Root CA", days: int = 3650) -> tuple[bytes, bytes]:
    """生成自签 CA 证书 + 私钥，返回 (cert_pem, key_pem)。"""
    key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + _timedelta_days(days))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=False, key_cert_sign=True,
                crl_sign=True, encipher_only=False, decipher_only=False),
            critical=True)
        .sign(key, hashes.SHA256())
    )
    return (_dump_pem(cert), _dump_pem(key))


def sign_client_cert(ca_cert_pem: bytes, ca_key_pem: bytes,
                     common_name: str, serial_hint: Optional[str] = None,
                     days: int = 825) -> tuple[bytes, bytes]:
    """用 CA 给某个 Agent 签发客户端证书，返回 (cert_pem, key_pem)。

    common_name 建议用 Agent 的 hash_serial（与现有 HMAC 身份一致），
    serial_hint 可选（用于审计/命名，不影响链校验）。
    """
    ca_cert = _load_certificate(ca_cert_pem)
    ca_key = _load_private_key(ca_key_pem)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ]))
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + _timedelta_days(days))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, content_commitment=False, key_encipherment=True,
                data_encipherment=False, key_agreement=False, key_cert_sign=False,
                crl_sign=False, encipher_only=False, decipher_only=False),
            critical=True)
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]),
            critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    return (_dump_pem(cert), _dump_pem(key))


# ── 加载 / 序列化 ──────────────────────────────────────────────────────────────
def _load_certificate(pem: bytes | str) -> x509.Certificate:
    if isinstance(pem, str):
        pem = pem.encode("utf-8")
    return x509.load_pem_x509_certificate(pem)


def _load_private_key(pem: bytes | str):
    if isinstance(pem, str):
        pem = pem.encode("utf-8")
    return serialization.load_pem_private_key(pem, password=None)


def _dump_pem(obj) -> bytes:
    if isinstance(obj, rsa.RSAPrivateKey):
        return obj.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    return obj.public_bytes(serialization.Encoding.PEM)


def _timedelta_days(days: int):
    from datetime import timedelta
    return timedelta(days=days)


# ── 校验 ──────────────────────────────────────────────────────────────────────
def verify_client_cert(cert_pem: bytes | str, ca_pem: bytes | str,
                       check_expiry: bool = True) -> bool:
    """校验客户端证书：由指定 CA 直接签发 + （可选）未过期 + 具备客户端认证用途。

    返回 True 表示可信。任何异常（格式错误 / 链不符 / 过期）一律 False（保守拒绝）。
    """
    try:
        cert = _load_certificate(cert_pem)
        ca = _load_certificate(ca_pem)
        # 1) 链校验：必须是由该 CA 直接签发（verify_directly_issued_by 成功返回 None，
        #    失败抛 ValueError）
        try:
            cert.verify_directly_issued_by(ca)
        except Exception:
            return False
        # 2) 用途校验：具备 CLIENT_AUTH 扩展用法
        try:
            eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
            if ExtendedKeyUsageOID.CLIENT_AUTH not in eku.value:
                return False
        except x509.ExtensionNotFound:
            # 没有 EKU 扩展也允许（宽松），但优先要求显式 CLIENT_AUTH
            pass
        # 3) 过期校验
        if check_expiry:
            now = datetime.now(timezone.utc)
            if cert.not_valid_before_utc > now:
                return False
            if cert.not_valid_after_utc < now:
                return False
        return True
    except Exception:
        return False


def cert_common_name(cert_pem: bytes | str) -> Optional[str]:
    try:
        cert = _load_certificate(cert_pem)
        cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        return cn[0].value if cn else None
    except Exception:
        return None


def cert_fingerprint(cert_pem: bytes | str, algorithm: str = "sha256",
                    colon: bool = False) -> str:
    """证书指纹（默认 SHA256，小写十六进制；colon=True 用冒号分组）。"""
    cert = _load_certificate(cert_pem)
    h = cert.fingerprint(getattr(hashes, algorithm.upper())())
    hexed = h.hex()
    if colon:
        return ":".join(hexed[i:i + 2] for i in range(0, len(hexed), 2))
    return hexed


def cert_not_valid_after(cert_pem: bytes | str) -> datetime:
    return _load_certificate(cert_pem).not_valid_after_utc


def cert_expires_in_days(cert_pem: bytes | str) -> int:
    """距过期的天数（负数表示已过期）。"""
    after = cert_not_valid_after(cert_pem)
    delta = after - datetime.now(timezone.utc)
    return int(delta.total_seconds() // 86400)


def is_cert_expiring_within(cert_pem: bytes | str, days: int) -> bool:
    """证书将在 days 天内过期（含已过期）返回 True。"""
    return cert_expires_in_days(cert_pem) <= days


# ── nginx 透传的客户端证书解析 ────────────────────────────────────────────────
def decode_nginx_client_cert(header_value: str) -> bytes:
    """解析 nginx 通过 $ssl_client_cert 透传的客户端证书。

    nginx 把 PEM 做 URL 编码后放在请求头（换行→%0a 等），此处先 URL 解码，
    再规整为以 '-----BEGIN CERTIFICATE-----' 开头的 PEM 字节串。
    """
    if header_value is None:
        raise ValueError("X-Ssl-Client-Cert 为空")
    decoded = urllib.parse.unquote(header_value).strip()
    # nginx 有时用 %0a 表示换行，unquote 后已是真实换行；兜底再处理一次
    if "-----BEGIN CERTIFICATE-----" not in decoded:
        # 极少数情况下 nginx 用 %20 之外的编码，再次确保换行正确
        decoded = decoded.replace("\\n", "\n").replace("%0a", "\n").replace("%0A", "\n")
    if not decoded.startswith("-----BEGIN CERTIFICATE-----"):
        raise ValueError("无法识别的客户端证书格式")
    return decoded.encode("utf-8")
