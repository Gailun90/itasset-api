"""
漏洞扫描 AI 辅助修复 — 数据模型（第一阶段：数据层）

四张表：
  vuln_scan_imports  每次 xlsx 上传记录
  vuln_findings      原始每行漏洞数据 + 资产匹配结果
  remediation_tasks  结构化修复任务（人工审核后才允许进入执行阶段）
  remediation_rules  QID -> 固定修复策略映射（命中规则不调 LLM）

说明：
  - JSON 列使用 JSON().with_variant(JSONB, "postgresql")：
    生产 PostgreSQL 落 JSONB，本地 SQLite 测试落 JSON，行为一致。
  - 本阶段不包含任何"下发执行"字段消费方，result_log / verified_* 先留空，
    供第二阶段执行通道回写。
"""
from datetime import datetime
from typing import Optional
from sqlalchemy import (
    Integer, String, Text, Boolean, DateTime,
    ForeignKey, func, Index, JSON,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.core.database import Base
# AUTO_DISPATCH_FIX_TYPES 的单一事实来源在 app.core.vuln_engine，
# 此处仅做再导出，避免两处重复定义（改动同步出问题）。
from app.core.vuln_engine import AUTO_DISPATCH_FIX_TYPES, DEFAULT_EXCLUDED_DISPATCH_ROLES

# PostgreSQL 用 JSONB，其它方言（本地 SQLite 测试）退回通用 JSON
JsonVariant = JSON().with_variant(JSONB(), "postgresql")

# ── 枚举值约定（应用层校验，不用 DB enum，方便后续扩展）─────────────────────
IMPORT_STATUSES   = ("pending", "parsing", "completed", "failed")
MATCH_CONFIDENCES = ("exact_hostname", "exact_ip", "fuzzy", "unmatched")
FIX_TYPES         = ("registry_fix", "software_upgrade", "software_uninstall",
                     "patch_install", "manual_review", "unsupported", "shell_exec")
RISK_LEVELS       = ("low", "medium", "high")
TASK_STATUSES     = ("pending", "approved", "rejected", "needs_manual",
                     "dispatched", "done", "failed",
                     "pending_verify", "rollback_required", "canary_waiting")
RULE_STATUSES     = ("active", "draft", "disabled", "paused")


class VulnScanImport(Base):
    __tablename__ = "vuln_scan_imports"

    id:              Mapped[int]           = mapped_column(Integer, primary_key=True, autoincrement=True)
    filename:        Mapped[str]           = mapped_column(String(255), nullable=False)
    uploaded_by:     Mapped[Optional[str]] = mapped_column(String(255))   # GLPI 登录名（插件透传）
    uploaded_at:     Mapped[datetime]      = mapped_column(DateTime(timezone=True), server_default=func.now())
    row_count:       Mapped[int]           = mapped_column(Integer, default=0)     # 有效数据行数
    processed_count: Mapped[int]           = mapped_column(Integer, default=0)     # 已解析行数（进度）
    status:          Mapped[str]           = mapped_column(String(16), default="pending")
    # pending | parsing | completed | failed
    error_message:   Mapped[Optional[str]] = mapped_column(Text)

    findings: Mapped[list["VulnFinding"]] = relationship(back_populates="scan_import", cascade="all, delete-orphan")

    __table_args__ = (Index("ix_vuln_scan_imports_status", "status"),)


class VulnFinding(Base):
    __tablename__ = "vuln_findings"

    id:               Mapped[int]           = mapped_column(Integer, primary_key=True, autoincrement=True)
    import_id:        Mapped[int]           = mapped_column(Integer, ForeignKey("vuln_scan_imports.id", ondelete="CASCADE"), nullable=False)
    ip:               Mapped[Optional[str]] = mapped_column(String(45))
    dns_name:         Mapped[Optional[str]] = mapped_column(String(255))
    qid:              Mapped[str]           = mapped_column(String(32), nullable=False)
    title:            Mapped[Optional[str]] = mapped_column(Text)
    results_raw:      Mapped[Optional[str]] = mapped_column(Text)
    solution_raw:     Mapped[Optional[str]] = mapped_column(Text)
    asset_id:         Mapped[Optional[int]] = mapped_column(Integer, ForeignKey("clients.id", ondelete="SET NULL"))
    match_confidence: Mapped[str]           = mapped_column(String(16), default="unmatched")
    # exact_hostname | exact_ip | fuzzy | unmatched
    created_at:       Mapped[datetime]      = mapped_column(DateTime(timezone=True), server_default=func.now())

    scan_import: Mapped["VulnScanImport"]        = relationship(back_populates="findings")
    tasks:       Mapped[list["RemediationTask"]] = relationship(back_populates="finding", cascade="all, delete-orphan")

    __table_args__ = (
        Index("ix_vuln_findings_import_id", "import_id"),
        Index("ix_vuln_findings_qid", "qid"),
        Index("ix_vuln_findings_asset_id", "asset_id"),
    )


class RemediationTask(Base):
    __tablename__ = "remediation_tasks"

    id:              Mapped[int]           = mapped_column(Integer, primary_key=True, autoincrement=True)
    finding_id:      Mapped[int]           = mapped_column(Integer, ForeignKey("vuln_findings.id", ondelete="CASCADE"), nullable=False)
    asset_id:        Mapped[Optional[int]] = mapped_column(Integer, ForeignKey("clients.id", ondelete="SET NULL"))
    fix_type:        Mapped[str]           = mapped_column(String(32), nullable=False)
    # registry_fix | software_upgrade | software_uninstall | patch_install | manual_review | unsupported
    action_json:     Mapped[Optional[dict]]= mapped_column(JsonVariant)
    risk_level:      Mapped[str]           = mapped_column(String(8), default="medium")   # low | medium | high
    auto_approve:    Mapped[bool]          = mapped_column(Boolean, default=False)         # 低风险默认勾选（仅 UI 预选，不自动执行）
    status:          Mapped[str]           = mapped_column(String(32), default="pending")
    # pending | approved | rejected | needs_manual | dispatched | done | failed
    # 新增中间态：pending_verify（等待后校验）| rollback_required（需回滚，17 字符，故列宽须 ≥32）| canary_waiting（金丝雀排队等放量）
    approved_by:     Mapped[Optional[str]] = mapped_column(String(255))
    approved_at:     Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    result_log:      Mapped[Optional[str]] = mapped_column(Text)          # 第二阶段执行通道回写
    verified_at:     Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    verified_result: Mapped[Optional[str]] = mapped_column(String(32))    # 第二阶段复扫验证结果（复扫验证，非执行结果）
    # ── 回滚方案（下发时从规则带过来的快照）──
    rollback_plan:   Mapped[Optional[dict]]= mapped_column(JsonVariant)
    # ── 规则版本追踪 ──
    rule_version_id: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    # ── 软件升级专用：匹配到的软件包（software_upgrade 的「可下发」前置条件）──
    # NULL = 尚未匹配到安装包（需人工在软件部署库关联后「重新匹配」）；此标志位区分于
    # 「未匹配资产」（asset_id 为 NULL），前端展示文案须不同。
    matched_package_id: Mapped[Optional[int]] = mapped_column(
        Integer, ForeignKey("packages.id", ondelete="SET NULL"), nullable=True)
    # ── 自动金丝雀：本任务是否进入首批金丝雀批次（True=已实际下发的小批量样本）──
    canary_batch:     Mapped[bool]          = mapped_column(Boolean, default=False, nullable=False)
    # ── 关联规则（dispatch 时写入，便于金丝雀按规则聚合统计）──
    rule_id:          Mapped[Optional[int]] = mapped_column(
        Integer, ForeignKey("remediation_rules.id", ondelete="SET NULL"), nullable=True)
    # ── 细粒度分组键（dispatch 时写入）：QID|fix_type|risk|OU|role|maintenance_window
    #    用于金丝雀「同组同批」——同一资产画像组的机器进入同一小批量观察，
    #    避免把关键服务器与普通工作站混在同一金丝雀样本里。
    dispatch_group_key: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    # ── 补丁安装执行结果：装完但等待重启才生效（区别于真正「done」）──
    # Windows Update 触发后我们显式禁止自动重启；若检测有待重启更新，置 True，
    # 任务保持 status=done 但前端展示「已完成（待重启生效）」警示徽章。
    needs_reboot:    Mapped[bool]          = mapped_column(Boolean, default=False, nullable=False)
    created_at:      Mapped[datetime]      = mapped_column(DateTime(timezone=True), server_default=func.now())

    finding: Mapped["VulnFinding"] = relationship(back_populates="tasks")

    __table_args__ = (
        Index("ix_remediation_tasks_status", "status"),
        Index("ix_remediation_tasks_asset_id", "asset_id"),
        Index("ix_remediation_tasks_finding_id", "finding_id"),
    )


class RemediationRule(Base):
    __tablename__ = "remediation_rules"

    id:                 Mapped[int]           = mapped_column(Integer, primary_key=True, autoincrement=True)
    qid:                Mapped[str]           = mapped_column(String(32), unique=True, nullable=False)
    fix_type:           Mapped[str]           = mapped_column(String(32), nullable=False)
    action_template:    Mapped[Optional[dict]]= mapped_column(JsonVariant)
    default_risk_level: Mapped[str]           = mapped_column(String(8), default="medium")
    status:             Mapped[str]           = mapped_column(String(16), default="active")
    # active | draft（LLM 生成待人工转正）| disabled | paused（金丝雀观察失败被自动暂停）
    source:             Mapped[str]           = mapped_column(String(16), default="manual")  # manual | llm
    # ── 自动金丝雀状态（新建/修改规则默认 pending；观察达标→verified 全量下发）──
    canary_status:      Mapped[str]           = mapped_column(String(16), default="pending", nullable=False)
    # pending | in_progress | verified
    canary_started_at:  Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    notes:              Mapped[Optional[str]] = mapped_column(Text)
    # ── 回滚方案 ──
    rollback_plan:      Mapped[Optional[dict]]= mapped_column(JsonVariant)
    # ── 每规则自动下发排除角色（最终形态·二细化）：
    #    在全局 DEFAULT_EXCLUDED_DISPATCH_ROLES 之外，规则可追加自身禁发的角色。
    #    下发门禁取「全局 ∪ 规则级」的并集。NULL = 不追加（仅用全局默认）。
    excluded_roles:     Mapped[Optional[list]] = mapped_column(JsonVariant, nullable=True)
    # ── 规则版本化 ──
    # current_version_id 指向 rule_versions 表中的当前生效版本
    current_version_id: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    created_at:         Mapped[datetime]      = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at:         Mapped[datetime]      = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())

    __table_args__ = (Index("ix_remediation_rules_status", "status"),)


# ── 规则版本表 ─────────────────────────────────────────────────────────────
class RuleVersion(Base):
    """规则的历史版本记录。改规则时不覆盖当前行，新开一条 version 记录。"""
    __tablename__ = "rule_versions"

    id:              Mapped[int]           = mapped_column(Integer, primary_key=True, autoincrement=True)
    rule_id:         Mapped[int]           = mapped_column(Integer, ForeignKey("remediation_rules.id", ondelete="CASCADE"), nullable=False)
    version:         Mapped[int]           = mapped_column(Integer, nullable=False, default=1)
    action_template: Mapped[Optional[dict]]= mapped_column(JsonVariant)
    rollback_plan:   Mapped[Optional[dict]]= mapped_column(JsonVariant)
    fix_type:        Mapped[str]           = mapped_column(String(32), nullable=False)
    default_risk_level: Mapped[str]        = mapped_column(String(8), default="medium")
    status:          Mapped[str]           = mapped_column(String(16), default="active")
    source:          Mapped[str]           = mapped_column(String(16), default="manual")
    notes:           Mapped[Optional[str]] = mapped_column(Text)
    created_by:      Mapped[Optional[str]] = mapped_column(String(255))
    approved_by:     Mapped[Optional[str]] = mapped_column(String(255))
    deprecated:      Mapped[bool]          = mapped_column(Boolean, default=False)
    created_at:      Mapped[datetime]      = mapped_column(DateTime(timezone=True), server_default=func.now())

    __table_args__ = (
        Index("ix_rule_versions_rule_id", "rule_id"),
        Index("ix_rule_versions_rule_version", "rule_id", "version", unique=True),
    )


# ── 自主策略表（当前仅含全局熔断开关）───────────────────────────────────────
class AutonomyPolicy(Base):
    """自主修复运行时策略（Phase D 基础字段，逐轮扩展）"""
    __tablename__ = "autonomy_policy"

    id:          Mapped[int]           = mapped_column(Integer, primary_key=True, autoincrement=True)
    kill_switch: Mapped[bool]          = mapped_column(Boolean, default=False, nullable=False)
    updated_by:  Mapped[Optional[str]] = mapped_column(String(255))
    updated_at:  Mapped[datetime]      = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())


# ── 金丝雀分级参数表（按 fix_type(+risk_level) 配不同保守程度）─────────────────
class AutonomyRule(Base):
    """自动金丝雀的分级参数：不同修复类型给不同的首批批次大小 / 观察窗口 / 回滚阈值。"""
    __tablename__ = "autonomy_rules"

    id:                     Mapped[int]    = mapped_column(Integer, primary_key=True, autoincrement=True)
    fix_type:               Mapped[str]    = mapped_column(String(32), nullable=False)
    # risk_level: 具体等级，或 "*" 表示通配（resolve_autonomy_params 按顺序回退）
    risk_level:             Mapped[str]    = mapped_column(String(8), default="*", nullable=False)
    canary_batch_size:      Mapped[int]    = mapped_column(Integer, nullable=False, default=5)
    canary_window_minutes:  Mapped[int]    = mapped_column(Integer, nullable=False, default=30)
    # 观察窗口内 rollback_required 超过该阈值 → 自动暂停规则（默认 0 = 一台都不能出问题）
    rollback_threshold:     Mapped[int]    = mapped_column(Integer, nullable=False, default=0)
    created_at:             Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    __table_args__ = (
        Index("ix_autonomy_rules_fix_risk", "fix_type", "risk_level", unique=True),
    )


# ── 资产画像表（细粒度分组 / 自保护分组依据）────────────────────────────────
CRITICALITY_LEVELS = ("low", "medium", "high", "critical")
# 自动下发排除角色：属于这些角色的资产，即使命中 active 规则也不走自动下发，
# 必须人工在管理面「确认下发」（避免对域控 / 关键业务服务器误自动修复）。
# 单一事实来源在 app.core.vuln_engine.DEFAULT_EXCLUDED_DISPATCH_ROLES（已随上方 import 再导出）。


class AssetProfile(Base):
    """资产画像：与客户端 1:1，承载角色 / OU / 软件 / 业务归属 / 关键度 / 维护窗口。

    - role：资产角色（workstation / app_server / domain_controller / sql_server ...）
    - ou：AD 组织单元（用于同组批量与维护窗口对齐）
    - installed_software：已安装软件清单（JSON 列表）
    - business_owner：业务负责人 / 团队
    - criticality：低/中/高/关键（影响自动下发闸门）
    - maintenance_window：维护窗口（JSON，如 {"start":"Sat 02:00","duration_hours":4}）
    """
    __tablename__ = "asset_profiles"

    id:               Mapped[int]           = mapped_column(Integer, primary_key=True, autoincrement=True)
    client_id:        Mapped[int]           = mapped_column(
        Integer, ForeignKey("clients.id", ondelete="CASCADE"), nullable=False, unique=True)
    role:             Mapped[Optional[str]] = mapped_column(String(64))
    ou:               Mapped[Optional[str]] = mapped_column(String(255))
    installed_software: Mapped[Optional[list]] = mapped_column(JsonVariant)
    business_owner:   Mapped[Optional[str]] = mapped_column(String(255))
    criticality:      Mapped[str]           = mapped_column(String(16), default="medium")
    maintenance_window: Mapped[Optional[dict]] = mapped_column(JsonVariant)
    captured_at:      Mapped[datetime]      = mapped_column(DateTime(timezone=True), server_default=func.now())

    __table_args__ = (
        Index("ix_asset_profiles_client_id", "client_id"),
        Index("ix_asset_profiles_role", "role"),
        Index("ix_asset_profiles_ou", "ou"),
    )


# ── 对话式规则纠正表（最终形态·三）────────────────────────────────────────────
# 结构化精确匹配（不做 embedding / 语义相似）：
#   记录某 QID+fix_type 下「用户纠正后的正确动作」，下次 LLM/规则匹配到相同条件时直接复用，
#   避免对同一错误重复纠偏。仅按 match_fields 的精确键值命中，命中即采用 corrected_action。
# 与 RemediationRule（人工/LLM 产出的稳定规则）互补：corrections 是「即时纠偏缓存」，
# 命中后可选择沉淀为正式 RemediationRule（source=llm）。
class Correction(Base):
    __tablename__ = "corrections"

    id:               Mapped[int]    = mapped_column(Integer, primary_key=True, autoincrement=True)
    qid:              Mapped[str]     = mapped_column(String(64), nullable=False)
    fix_type:         Mapped[str]     = mapped_column(String(32), nullable=False)
    rule_id:          Mapped[Optional[int]] = mapped_column(
        Integer, ForeignKey("remediation_rules.id", ondelete="SET NULL"), nullable=True)
    # 归一化精确匹配键（Correction.match_key 产出）：qid|fix_type|{sorted match_fields}
    # 用于 (qid, fix_type, match_key) 三字段精确命中，避免每次按 JSONB 内容比对。
    match_key:        Mapped[str]     = mapped_column(String(1024), nullable=False, default="")
    # 触发纠正时的结构化条件（精确匹配键），如 {"risk":"high","os":"windows"} 等
    match_fields:     Mapped[dict]    = mapped_column(JsonVariant)
    # 纠正后的正确动作 / 参数（与 Action Validator 产出同构）
    corrected_action: Mapped[dict]    = mapped_column(JsonVariant)
    note:             Mapped[Optional[str]] = mapped_column(Text)
    usage_count:      Mapped[int]     = mapped_column(Integer, default=0)
    created_at:       Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    __table_args__ = (
        Index("ix_corrections_qid_fix", "qid", "fix_type"),
        Index("ix_corrections_lookup", "qid", "fix_type", "match_key"),
    )

    @staticmethod
    def build_match_key(qid: str, fix_type: str, match_fields: dict) -> str:
        """把精确匹配条件归一为稳定字符串键（用于同组快速比对）。"""
        import json
        norm = {k: match_fields.get(k) for k in sorted(match_fields.keys())}
        return "|".join([str(qid or ""), str(fix_type or ""),
                         json.dumps(norm, sort_keys=True, ensure_ascii=False,
                                    separators=(",", ":"))])
