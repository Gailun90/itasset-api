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

# PostgreSQL 用 JSONB，其它方言（本地 SQLite 测试）退回通用 JSON
JsonVariant = JSON().with_variant(JSONB(), "postgresql")

# ── 枚举值约定（应用层校验，不用 DB enum，方便后续扩展）─────────────────────
IMPORT_STATUSES   = ("pending", "parsing", "completed", "failed")
MATCH_CONFIDENCES = ("exact_hostname", "exact_ip", "fuzzy", "unmatched")
FIX_TYPES         = ("registry_fix", "software_upgrade", "software_uninstall",
                     "patch_install", "manual_review", "unsupported")
RISK_LEVELS       = ("low", "medium", "high")
TASK_STATUSES     = ("pending", "approved", "rejected", "needs_manual",
                     "dispatched", "done", "failed")
RULE_STATUSES     = ("active", "draft", "disabled")

# 可自动下发到客户端代理执行的修复类型（其余类型批准后不自动下发，需人工处理）
AUTO_DISPATCH_FIX_TYPES = ("registry_fix", "software_uninstall")


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
    status:          Mapped[str]           = mapped_column(String(16), default="pending")
    # pending | approved | rejected | needs_manual | dispatched | done | failed
    approved_by:     Mapped[Optional[str]] = mapped_column(String(255))
    approved_at:     Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    result_log:      Mapped[Optional[str]] = mapped_column(Text)          # 第二阶段执行通道回写
    verified_at:     Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    verified_result: Mapped[Optional[str]] = mapped_column(String(32))    # 第二阶段复扫验证结果
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
    # active | draft（LLM 生成待人工转正）| disabled
    source:             Mapped[str]           = mapped_column(String(16), default="manual")  # manual | llm
    notes:              Mapped[Optional[str]] = mapped_column(Text)
    created_at:         Mapped[datetime]      = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at:         Mapped[datetime]      = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())

    __table_args__ = (Index("ix_remediation_rules_status", "status"),)
