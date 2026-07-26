"""漏洞扫描 AI 辅助修复 — Pydantic Schemas（第一阶段）"""
from datetime import datetime
from typing import Optional, Any
from pydantic import BaseModel, Field


# ── 导入批次 ──────────────────────────────────────────────────────────────────
class ImportOut(BaseModel):
    id:              int
    filename:        str
    uploaded_by:     Optional[str] = None
    uploaded_at:     Optional[datetime] = None
    row_count:       int = 0
    processed_count: int = 0
    status:          str
    error_message:   Optional[str] = None

    class Config:
        from_attributes = True


class ImportStatsOut(ImportOut):
    """单批次进度统计"""
    match_stats: dict[str, int] = {}     # {exact_hostname: n, exact_ip: n, fuzzy: n, unmatched: n}
    task_stats:  dict[str, int] = {}     # {low: n, medium: n, high: n}
    fix_type_stats: dict[str, int] = {}  # {registry_fix: n, ...}
    match_rate:  float = 0.0             # 匹配成功率（非 unmatched 占比）


class FindingOut(BaseModel):
    id:               int
    import_id:        int
    ip:               Optional[str] = None
    dns_name:         Optional[str] = None
    qid:              str
    title:            Optional[str] = None
    results_raw:      Optional[str] = None
    solution_raw:     Optional[str] = None
    asset_id:         Optional[int] = None
    asset_hostname:   Optional[str] = None   # JOIN clients 补充
    match_confidence: str

    class Config:
        from_attributes = True


class ResolveMatchRequest(BaseModel):
    """人工修正资产匹配"""
    asset_id: Optional[int] = None   # None = 明确标记为无法匹配
    regenerate_task: bool = True     # 修正后是否同步更新对应任务的 asset_id


# ── 修复任务 ──────────────────────────────────────────────────────────────────
class TaskListItem(BaseModel):
    id:               int
    finding_id:       int
    import_id:        Optional[int] = None
    asset_id:         Optional[int] = None
    asset_hostname:   Optional[str] = None
    ip:               Optional[str] = None
    dns_name:         Optional[str] = None
    qid:              Optional[str] = None
    title:            Optional[str] = None
    fix_type:         str
    action_summary:   Optional[str] = None   # action_json 的一句话摘要
    risk_level:       str
    auto_approve:     bool = False
    status:           str
    match_confidence: Optional[str] = None
    created_at:       Optional[datetime] = None

    class Config:
        from_attributes = True


class TaskDetailOut(TaskListItem):
    action_json:     Optional[dict] = None
    results_raw:     Optional[str] = None
    solution_raw:    Optional[str] = None
    approved_by:     Optional[str] = None
    approved_at:     Optional[datetime] = None
    result_log:      Optional[str] = None
    verified_at:     Optional[datetime] = None
    verified_result: Optional[str] = None
    # 批准响应专用：本次未自动下发的原因（规则未转正/高风险需显式确认等），持久化字段之外
    dispatch_block_reason: Optional[str] = None


class ApproveRequest(BaseModel):
    operator: str = Field(..., min_length=1, max_length=255)   # GLPI 登录名
    comment:  Optional[str] = None


class BatchApproveRequest(BaseModel):
    task_ids: list[int] = Field(..., min_length=1)
    operator: str = Field(..., min_length=1, max_length=255)


# ── 规则库 ────────────────────────────────────────────────────────────────────
class RuleIn(BaseModel):
    qid:                str = Field(..., min_length=1, max_length=32)
    fix_type:           str
    action_template:    Optional[dict] = None
    default_risk_level: str = "medium"
    status:             str = "active"
    notes:              Optional[str] = None


class RuleUpdate(BaseModel):
    fix_type:           Optional[str] = None
    action_template:    Optional[dict] = None
    default_risk_level: Optional[str] = None
    status:             Optional[str] = None    # active / draft / disabled
    notes:              Optional[str] = None


class RuleOut(BaseModel):
    id:                 int
    qid:                str
    fix_type:           str
    action_template:    Optional[Any] = None
    default_risk_level: str
    status:             str
    source:             str
    notes:              Optional[str] = None
    created_at:         Optional[datetime] = None
    updated_at:         Optional[datetime] = None

    class Config:
        from_attributes = True
