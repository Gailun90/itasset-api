"""
软件包模糊匹配服务（software_upgrade 修复类型）

将修复任务的 action_json（vendor/product/版本）与软件部署库 packages 表做模糊匹配：
  - 归一化软件名：去版本号、小写、非字母数字统一为空格（大小写/空格/连字符不敏感）
  - 版本比较：target_version 须 >= package.version（即库里要有「不低于目标」的包）
  - 评分：归一化完全相等 > 归一化包含；同分时取版本更高者
  说明：归一化不做「厂商前缀剔除」，以对齐漏洞扫描命名（如 "Adobe Reader" 与 "Adobe Acrobat
  Reader" 仍靠包含评分区分），避免把 "Microsoft Visual C++ 2015 Redistributable" 之类归一化成空串。

匹配时机：
  1) 任务生成时（vuln_service.parse_import 落库后立刻跑一次）
  2) 用户点击「重新匹配」（POST /api/vuln/tasks/{id}/rematch-package），
     因为 packages 库可能晚于任务生成才补充上传
"""
import logging
import re
from typing import Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.models import Package

logger = logging.getLogger(__name__)


def normalize_sw_name(name: str) -> str:
    """软件名归一化：小写、去版本号 token、非字母数字统一为空格、折叠空白。"""
    if not name:
        return ""
    s = str(name).lower().strip()
    # 1) 去掉版本号片段：连续的数字、数字+点（如 2021, 1.2.3, 10.0.19041）
    s = re.sub(r"\b\d+(?:\.\d+)*\b", " ", s)
    # 2) 非字母数字统一成空格（保留空格做分词），连字符/下划线 → 空格
    s = re.sub(r"[^a-z0-9]+", " ", s)
    # 3) 折叠空白
    s = re.sub(r"\s+", " ", s).strip()
    return s


def parse_version(v: str) -> tuple[int, ...]:
    """'1.2.3' -> (1,2,3)；提取每段整数，非数字段忽略。无数字返回空元组。"""
    if not v:
        return ()
    parts = re.split(r"[.\-_ ]+", str(v).lower())
    out = []
    for p in parts:
        m = re.search(r"\d+", p)
        if m:
            out.append(int(m.group()))
    return tuple(out)


def _version_ge(a: str, b: str) -> bool:
    """a >= b？任一无法解析则视为满足（不卡版本）。"""
    va, vb = parse_version(a), parse_version(b)
    if not vb:
        return True
    if not va:
        return False
    # 逐段比较，a 段不足时补 0
    n = max(len(va), len(vb))
    va = va + (0,) * (n - len(va))
    vb = vb + (0,) * (n - len(vb))
    return va >= vb


async def match_package(db: AsyncSession, software: str,
                        target_version: str = "") -> Optional[Package]:
    """
    在 packages 库中模糊匹配软件安装包。
    返回最匹配的 Package，或 None（无匹配 / 版本不满足）。
    """
    candidates = (await db.execute(select(Package))).scalars().all()
    if not candidates:
        return None

    query_norm = normalize_sw_name(software)
    if not query_norm:
        return None

    best: Optional[Package] = None
    best_score = 0.0
    for pkg in candidates:
        pkg_norm = normalize_sw_name(pkg.name)
        if not pkg_norm:
            continue
        # 评分：完全相等最高，包含次之
        if pkg_norm == query_norm:
            score = 1.0
        elif query_norm in pkg_norm:
            score = 0.7
        elif pkg_norm in query_norm:
            score = 0.6
        else:
            continue  # 无重叠直接跳过
        # 版本约束：库里包版本须 >= 目标版本
        if target_version and not _version_ge(pkg.version, target_version):
            continue
        # 同分时取版本更高者
        if score > best_score or (
            score == best_score and best is not None
            and _version_ge(pkg.version, best.version)
        ):
            best, best_score = pkg, score

    if best:
        logger.info("软件包匹配：'%s' v%s → package #%s (%s v%s, score=%.2f)",
                    software, target_version, best.id, best.name, best.version, best_score)
    else:
        logger.info("软件包匹配：'%s' v%s 未匹配到任何安装包", software, target_version)
    return best
