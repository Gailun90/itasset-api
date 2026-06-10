from pydantic_settings import BaseSettings
from functools import lru_cache

class Settings(BaseSettings):
    DATABASE_URL: str
    AGENT_INITIAL_TOKEN: str
    GLPI_API_TOKEN: str = ""         # GLPI插件专用（空则回退到AGENT_INITIAL_TOKEN）
    ALLOWED_ORIGINS: list[str] = ["*"]  # CORS白名单
    SECRET_KEY: str
    SERVER_URL: str = "http://localhost:8000"
    WS_ENDPOINT: str = "ws://localhost:8000/ws/agent/"
    PACKAGES_DIR: str = "/opt/itasset/packages"
    # 防惊群：Agent 首次上报最大随机延迟秒数
    AGENT_JITTER_MAX: int = 300

    class Config:
        env_file = "/opt/itasset/.env"

@lru_cache
def get_settings() -> Settings:
    return Settings()
