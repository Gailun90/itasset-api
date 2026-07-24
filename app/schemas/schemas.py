from datetime import datetime
from typing import Optional, Any
from pydantic import BaseModel, Field


# ── 设备注册 ──────────────────────────────────────────────────────────────────
class RegisterRequest(BaseModel):
    hash_serial:  str = Field(..., min_length=1, max_length=128)
    bios_serial:  Optional[str] = None
    machine_guid: Optional[str] = None
    hostname: str = Field(..., min_length=1, max_length=255)
    ip:       Optional[str] = None
    initial_token: str
    old_device_secret: Optional[str] = None   # 重新注册时携带，用于无损恢复

class RegisterResponse(BaseModel):
    device_secret: str
    client_id: int
    message: str = "注册成功"


# ── 资产上报 ──────────────────────────────────────────────────────────────────
class DiskInfo(BaseModel):
    model:    Optional[str] = None
    size_gb:  Optional[int] = None
    type:     Optional[str] = None   # HDD | SSD | NVMe

class ReportRequest(BaseModel):
    hash_serial:  str
    bios_serial:  Optional[str] = None
    machine_guid: Optional[str] = None
    hostname:     str
    ip:           Optional[str] = None
    os:           Optional[str] = None
    cpu:          Optional[str] = None
    memory_gb:    Optional[int] = None
    disk_info:    Optional[list[DiskInfo]] = None
    current_user: Optional[str] = None
    software:     Optional[list[dict]] = None
    patches:      Optional[list[dict]] = None
    # 认证头（由中间件校验，此处仅文档用）
    timestamp:  Optional[str] = None
    signature:  Optional[str] = None

class ReportResponse(BaseModel):
    client_id: int
    status:    str = "ok"
    jitter_seconds: int = 0   # 服务端建议的随机延迟（防惊群）


# ── 任务 ──────────────────────────────────────────────────────────────────────
class TaskOut(BaseModel):
    target_id:       int
    task_id:         int
    task_name:       str
    task_type:       str = "install"    # install | uninstall
    uninstall_target:Optional[str] = None  # 卸载目标软件名
    package_filename:Optional[str] = None
    package_hash:    Optional[str]
    package_size:    Optional[int]
    silent_args:     Optional[str] = None
    interactive:     bool
    need_reboot:     bool
    timeout:         int
    success_codes:   list[int] = [0]
    defer_count:     int
    max_defer_count: int
    silent_override: bool
    download_url:    Optional[str] = None

class TaskResultRequest(BaseModel):
    success:     bool
    exit_code:   Optional[int] = None
    message:     Optional[str] = None
    reboot_action: Optional[str] = None  # none | prompt | force
    deferred:    bool = False

class TaskLogRequest(BaseModel):
    log: str = Field(..., max_length=524288)   # 512KB


# ── 审计 ──────────────────────────────────────────────────────────────────────
class AuditActionRequest(BaseModel):
    serial:       Optional[str] = None   # 旧版 Agent 字段
    hash_serial:  Optional[str] = None   # 新版 Agent 字段，两者至少一个必填
    process_path: str
    arguments:    Optional[str] = None
    pid:          Optional[int] = None
    exit_code:    Optional[int] = None
    executed_at:  datetime


# ── 策略 ──────────────────────────────────────────────────────────────────────
class PolicyOut(BaseModel):
    global_max_defer:    int
    global_silent_after: bool
    package_overrides:   dict[int, dict] = {}   # package_id -> {max_defer, silent_override}


# ── 仪表盘 ────────────────────────────────────────────────────────────────────
class DashboardOut(BaseModel):
    total_clients:  int
    online_clients: int
    pending_tasks:  int
    failed_tasks:   int
    online_serials: list[str] = []
    version:        str = "1.0.0"

class DiffStatsOut(BaseModel):
    diff_count:     int
    total_clients:  int
    last_report_at: Optional[datetime]


# ── 导出（供 GLPI 插件手动导入）─────────────────────────────────────────────
class ClientExportItem(BaseModel):
    client_id:    int
    serial:       str
    bios_serial:  Optional[str] = None
    machine_guid: Optional[str] = None
    hostname:     str
    ip:           Optional[str]
    os_name:      Optional[str]
    cpu:          Optional[str]
    memory_gb:    Optional[int]
    current_user: Optional[str] = None
    manufacturer: Optional[str]
    model:        Optional[str]
    last_seen:    Optional[datetime]
    real_serial:  Optional[str] = None   # 原始 BIOS 序列号（给 GLPI 展示用）
    group_id:     Optional[int] = None   # 所属分组 ID
    has_diff:     bool = False
    glpi_items_id:int  = 0

class ClientExportList(BaseModel):
    items:  list[ClientExportItem]
    total:  int
    page:   int
    limit:  int


# ── 通用响应 ──────────────────────────────────────────────────────────────────
class OkResponse(BaseModel):
    ok:      bool = True
    message: str  = "success"
