from pydantic_settings import BaseSettings
from functools import lru_cache

class Settings(BaseSettings):
    DATABASE_URL: str
    AGENT_INITIAL_TOKEN: str
    GLPI_API_TOKEN: str = ""         # GLPI插件专用（空则禁止 GLPI 端点访问，不再回退到 AGENT_INITIAL_TOKEN）
    ALLOWED_ORIGINS: list[str] = ["http://localhost:8000"]  # CORS白名单（不再允许 "*"）
    SECRET_KEY: str
    SERVER_URL: str = "http://localhost:8000"
    WS_ENDPOINT: str = "ws://localhost:8000/ws/agent/"
    PACKAGES_DIR: str = "/opt/itasset/packages"
    # 客户端自更新：更新包与 version.json 所在目录
    # 该目录下应放置 version.json（描述最新版本）与对应的更新包 zip 文件
    CLIENT_UPDATE_DIR: str = "/opt/itasset/packages/updates"
    # 防惊群：Agent 首次上报最大随机延迟秒数
    AGENT_JITTER_MAX: int = 300

    # ── 漏洞扫描 AI 辅助修复 ──────────────────────────────
    VULN_UPLOAD_DIR: str = "/opt/itasset/tmp"       # xlsx 临时存放目录（解析后删除）
    VULN_XLSX_MAX_MB: int = 20                       # 上传文件大小上限
    VULN_LLM_ENABLED: bool = True                    # 关闭后无规则的 QID 直接转 manual_review
    OPENCLAW_URL: str = "http://90.90.90.90:18789/v1"  # openclaw 网关（OpenAI 兼容）
    OPENCLAW_MODEL: str = "openclaw"                 # agent target: openclaw / openclaw/default
    OPENCLAW_TOKEN: str = ""                         # 网关 Bearer token（放 .env，勿硬编码）
    OPENCLAW_TIMEOUT: int = 180                      # LLM 单次调用超时（秒）
    SETTINGS_ENCRYPTION_KEY: str = ""                 # system_settings 敏感字段加密key，部署时生成写入 .env

    class Config:
        env_file = "/opt/itasset/.env"


@lru_cache
def get_settings() -> Settings:
    return Settings()
