from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.deps import require_glpi_token
from app.models.models import Group, Client
from app.schemas.schemas import OkResponse

router = APIRouter(prefix="/api/groups", tags=["groups"])


@router.get("")
async def list_groups(
    _:  bool = Depends(require_glpi_token),
    db: AsyncSession = Depends(get_db),
):
    """列出所有分组及成员数（JOIN 单次查询，避免 N+1）"""
    from sqlalchemy import func as sqlfunc
    rows = await db.execute(
        select(
            Group.id, Group.name, Group.description,
            sqlfunc.count(Client.id).label("client_count")
        )
        .outerjoin(Client, Client.group_id == Group.id)
        .group_by(Group.id)
        .order_by(Group.name)
    )
    return [
        {"id": r[0], "name": r[1], "description": r[2] or "", "client_count": r[3]}
        for r in rows
    ]


@router.post("", response_model=OkResponse)
async def create_group(
    name:        str,
    description: str = "",
    _:  bool = Depends(require_glpi_token),
    db: AsyncSession = Depends(get_db),
):
    exists = await db.execute(select(Group).where(Group.name == name))
    if exists.scalar_one_or_none():
        raise HTTPException(400, f"分组名 '{name}' 已存在")
    db.add(Group(name=name, description=description))
    await db.commit()
    return OkResponse(message=f"已创建分组：{name}")


@router.patch("/{group_id}", response_model=OkResponse)
async def update_group(
    group_id:    int,
    name:        str = "",
    description: Optional[str] = None,
    _:  bool = Depends(require_glpi_token),
    db: AsyncSession = Depends(get_db),
):
    res = await db.execute(select(Group).where(Group.id == group_id))
    g = res.scalar_one_or_none()
    if not g:
        raise HTTPException(404, "分组不存在")
    if name:
        g.name = name
    if description is not None:   # 只在显式传入时更新，避免只改名时清空描述
        g.description = description
    await db.commit()
    return OkResponse(message=f"已更新分组：{g.name}")


@router.delete("/{group_id}", response_model=OkResponse)
async def delete_group(
    group_id: int,
    _:  bool = Depends(require_glpi_token),
    db: AsyncSession = Depends(get_db),
):
    res = await db.execute(select(Group).where(Group.id == group_id))
    g = res.scalar_one_or_none()
    if not g:
        raise HTTPException(404, "分组不存在")
    members = await db.execute(select(Client).where(Client.group_id == group_id))
    for c in members.scalars().all():
        c.group_id = None
    await db.delete(g)
    await db.commit()
    return OkResponse(message=f"已删除分组：{g.name}")


@router.post("/{group_id}/members", response_model=OkResponse)
async def set_group_members(
    group_id:   int,
    client_ids: str = "",
    _:  bool = Depends(require_glpi_token),
    db: AsyncSession = Depends(get_db),
):
    res = await db.execute(select(Group).where(Group.id == group_id))
    if not res.scalar_one_or_none():
        raise HTTPException(404, "分组不存在")

    ids = [int(x) for x in client_ids.split(",") if x.strip().isdigit()]

    old = await db.execute(select(Client).where(Client.group_id == group_id))
    for c in old.scalars().all():
        c.group_id = None

    if ids:
        new_members = await db.execute(select(Client).where(Client.id.in_(ids)))
        for c in new_members.scalars().all():
            c.group_id = group_id

    await db.commit()
    return OkResponse(message=f"分组成员已更新，共 {len(ids)} 台")

@router.get("/{group_id}/members")
async def get_group_members(
    group_id: int,
    _: bool = Depends(require_glpi_token),
    db: AsyncSession = Depends(get_db),
):
    """获取分组内的成员终端 ID 列表"""
    res = await db.execute(select(Group).where(Group.id == group_id))
    if not res.scalar_one_or_none():
        raise HTTPException(404, "分组不存在")
    members = await db.execute(
        select(Client.id, Client.hostname, Client.hash_serial)
        .where(Client.group_id == group_id)
    )
    return [
        {"id": row[0], "hostname": row[1], "serial": row[2]}
        for row in members
    ]
