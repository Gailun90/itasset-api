from datetime import datetime
from typing import Optional
from sqlalchemy import (
    Integer, String, Text, Boolean, DateTime,
    ForeignKey, BigInteger, func, UniqueConstraint, Index
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.core.database import Base


class Client(Base):
    __tablename__ = "clients"

    id:              Mapped[int]           = mapped_column(Integer, primary_key=True, autoincrement=True)
    hostname:        Mapped[str]           = mapped_column(String(255), nullable=False)
    ip:              Mapped[Optional[str]] = mapped_column(String(45))
    hash_serial:     Mapped[str]           = mapped_column(String(128), unique=True, nullable=False)
    os:              Mapped[Optional[str]] = mapped_column(String(255))
    cpu:             Mapped[Optional[str]] = mapped_column(String(255))
    memory_gb:       Mapped[Optional[int]] = mapped_column(Integer)
    bios_serial:    Mapped[Optional[str]] = mapped_column(String(255))
    machine_guid:   Mapped[Optional[str]] = mapped_column(String(128))
    disk_info:       Mapped[Optional[dict]]= mapped_column(JSONB)       # [{model, size_gb, type}]
    group_id:        Mapped[Optional[int]] = mapped_column(Integer, ForeignKey("groups.id", ondelete="SET NULL"))
    device_secret_hash: Mapped[Optional[str]] = mapped_column(String(64))  # SHA256(DeviceSecret)
    last_seen:       Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    created_at:      Mapped[datetime]      = mapped_column(DateTime(timezone=True), server_default=func.now())

    reports:         Mapped[list["ClientReport"]]   = relationship(back_populates="client", cascade="all, delete-orphan")
    task_targets:    Mapped[list["TaskTarget"]]     = relationship(back_populates="client")
    audit_actions:   Mapped[list["ActionAudit"]]   = relationship(back_populates="client")
    group:           Mapped[Optional["Group"]]      = relationship(back_populates="clients")

    __table_args__ = (Index("ix_clients_serial", "hash_serial"),)


class DeviceRegistration(Base):
    __tablename__ = "device_registrations"

    id:               Mapped[int]           = mapped_column(Integer, primary_key=True, autoincrement=True)
    hash_serial:      Mapped[str]           = mapped_column(String(128), unique=True, nullable=False)
    initial_token_used: Mapped[bool]        = mapped_column(Boolean, default=True)
    device_secret_hash: Mapped[str]         = mapped_column(String(64), nullable=False)
    bound_at:         Mapped[datetime]      = mapped_column(DateTime(timezone=True), server_default=func.now())
    last_ip:          Mapped[Optional[str]] = mapped_column(String(45))


class Group(Base):
    __tablename__ = "groups"

    id:          Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name:        Mapped[str] = mapped_column(String(128), unique=True, nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text)

    clients: Mapped[list["Client"]] = relationship(back_populates="group")


class ClientReport(Base):
    __tablename__ = "client_reports"

    id:           Mapped[int]           = mapped_column(Integer, primary_key=True, autoincrement=True)
    client_id:    Mapped[int]           = mapped_column(Integer, ForeignKey("clients.id", ondelete="CASCADE"))
    current_user: Mapped[Optional[str]] = mapped_column(String(255))
    software:     Mapped[Optional[list]]= mapped_column(JSONB)   # [{name,version,publisher,install_date,install_dir}]
    patches:      Mapped[Optional[list]]= mapped_column(JSONB)   # [{hotfix_id,installed_on}]
    collected_at: Mapped[datetime]      = mapped_column(DateTime(timezone=True), server_default=func.now())

    client: Mapped["Client"] = relationship(back_populates="reports")

    __table_args__ = (Index("ix_client_reports_client_id", "client_id"),)


class Package(Base):
    __tablename__ = "packages"

    id:             Mapped[int]           = mapped_column(Integer, primary_key=True, autoincrement=True)
    name:           Mapped[str]           = mapped_column(String(255), nullable=False)
    version:        Mapped[str]           = mapped_column(String(64), nullable=False)
    filename:       Mapped[str]           = mapped_column(String(255), nullable=False)
    silent_args:    Mapped[Optional[str]] = mapped_column(String(512))
    file_hash:      Mapped[Optional[str]] = mapped_column(String(64))   # SHA256
    file_size:      Mapped[Optional[int]] = mapped_column(BigInteger)
    description:    Mapped[Optional[str]] = mapped_column(Text)
    default_policy: Mapped[Optional[dict]]= mapped_column(JSONB)
    created_at:     Mapped[datetime]      = mapped_column(DateTime(timezone=True), server_default=func.now())

    tasks: Mapped[list["Task"]] = relationship(back_populates="package")

    __table_args__ = (UniqueConstraint("name", "version", name="uq_package_name_version"),)


class Task(Base):
    __tablename__ = "tasks"

    id:                 Mapped[int]           = mapped_column(Integer, primary_key=True, autoincrement=True)
    name:               Mapped[str]           = mapped_column(String(255), nullable=False)
    task_type:          Mapped[str]           = mapped_column(String(32), default="install")  # install | uninstall | run_command | registry | cleanup
    uninstall_target:   Mapped[Optional[str]] = mapped_column(String(512))  # 软件卸载目标名称
    package_id:         Mapped[Optional[int]] = mapped_column(Integer, ForeignKey("packages.id", ondelete="SET NULL"))
    # ── 命令类任务字段（run_command / registry / cleanup）──
    command:            Mapped[Optional[str]] = mapped_column(Text)         # 下发的脚本内容（bat/cmd/powershell）
    interpreter:        Mapped[Optional[str]] = mapped_column(String(32))   # bat | cmd | powershell（空=按内容推断）
    registry_ops:       Mapped[Optional[list]]= mapped_column(JSONB)        # [{action,root,subkey,name,value,type}]
    cleanup_paths:      Mapped[Optional[list]]= mapped_column(JSONB)        # [{path,recursive}]
    run_as:             Mapped[str]           = mapped_column(String(16), default="system")  # system | user
    target_type:        Mapped[str]           = mapped_column(String(32), default="client")  # client | group | all
    target_id:          Mapped[Optional[int]] = mapped_column(Integer)
    interactive:        Mapped[bool]          = mapped_column(Boolean, default=True)
    need_reboot:        Mapped[bool]          = mapped_column(Boolean, default=False)
    timeout:            Mapped[int]           = mapped_column(Integer, default=600)
    success_codes:      Mapped[Optional[list]]= mapped_column(JSONB, default=[0])  # 🔒 修复问题22：默认 [0] 而不是空列表
    status:             Mapped[str]           = mapped_column(String(32), default="active")
    maintenance_window: Mapped[Optional[dict]]= mapped_column(JSONB)
    bandwidth_limit_kb: Mapped[Optional[int]] = mapped_column(Integer)
    created_at:         Mapped[datetime]      = mapped_column(DateTime(timezone=True), server_default=func.now())

    package: Mapped["Package"]            = relationship(back_populates="tasks")
    targets: Mapped[list["TaskTarget"]]   = relationship(back_populates="task", cascade="all, delete-orphan")


class TaskTarget(Base):
    __tablename__ = "task_targets"

    id:           Mapped[int]           = mapped_column(Integer, primary_key=True, autoincrement=True)
    task_id:      Mapped[int]           = mapped_column(Integer, ForeignKey("tasks.id", ondelete="CASCADE"))
    client_id:    Mapped[int]           = mapped_column(Integer, ForeignKey("clients.id", ondelete="CASCADE"))
    # 漏洞修复联动：若本 target 由 remediation_task 下发，回报结果时回写该修复任务
    remediation_task_id: Mapped[Optional[int]] = mapped_column(Integer, ForeignKey("remediation_tasks.id", ondelete="SET NULL"))
    status:       Mapped[str]           = mapped_column(String(32), default="pending")
    # pending | running | success | failed | deferred | cancelled
    message:      Mapped[Optional[str]] = mapped_column(Text)
    reboot_action:Mapped[Optional[str]] = mapped_column(String(32))
    install_log:  Mapped[Optional[str]] = mapped_column(Text)
    retry_count:  Mapped[int]           = mapped_column(Integer, default=0)
    defer_count:  Mapped[int]           = mapped_column(Integer, default=0)
    executed_at:  Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    started_at:  Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    created_at:   Mapped[datetime]      = mapped_column(DateTime(timezone=True), server_default=func.now())

    task:   Mapped["Task"]   = relationship(back_populates="targets")
    client: Mapped["Client"] = relationship(back_populates="task_targets")

    __table_args__ = (
        Index("ix_task_targets_client_status", "client_id", "status"),
        Index("ix_task_targets_task_id", "task_id"),
    )


class InteractionPolicy(Base):
    __tablename__ = "interaction_policies"

    id:               Mapped[int]           = mapped_column(Integer, primary_key=True, autoincrement=True)
    package_id:       Mapped[Optional[int]] = mapped_column(Integer, ForeignKey("packages.id", ondelete="CASCADE"))
    max_defer_count:  Mapped[int]           = mapped_column(Integer, default=3)
    silent_after_max: Mapped[bool]          = mapped_column(Boolean, default=True)
    silent_override:  Mapped[bool]          = mapped_column(Boolean, default=False)
    updated_at:       Mapped[datetime]      = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())


class ActionAudit(Base):
    __tablename__ = "action_audit"

    id:           Mapped[int]           = mapped_column(Integer, primary_key=True, autoincrement=True)
    hash_serial:  Mapped[str]           = mapped_column(String(128), nullable=False)
    client_id:    Mapped[Optional[int]] = mapped_column(Integer, ForeignKey("clients.id", ondelete="SET NULL"))
    process_path: Mapped[str]           = mapped_column(String(512), nullable=False)
    arguments:    Mapped[Optional[str]] = mapped_column(Text)
    pid:          Mapped[Optional[int]] = mapped_column(Integer)
    exit_code:    Mapped[Optional[int]] = mapped_column(Integer)
    executed_at:  Mapped[datetime]      = mapped_column(DateTime(timezone=True))
    started_at:  Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    reported_at:  Mapped[datetime]      = mapped_column(DateTime(timezone=True), server_default=func.now())

    client: Mapped[Optional["Client"]] = relationship(back_populates="audit_actions")

    __table_args__ = (
        Index("ix_action_audit_serial", "hash_serial"),
        Index("ix_action_audit_reported_at", "reported_at"),
    )


class SystemSetting(Base):
    """通用键值配置表（目前用于 AI 解析设置：openclaw_url/model/token/timeout/llm_enabled）"""
    __tablename__ = "system_settings"

    key:        Mapped[str]                = mapped_column(String(100), primary_key=True)
    value:      Mapped[Optional[str]]       = mapped_column(Text)
    updated_at: Mapped[Optional[datetime]]  = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_by: Mapped[Optional[str]]       = mapped_column(String(100))
