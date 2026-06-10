"""
包管理端点：上传、下载（断点续传）、列表
"""
import hashlib
import os
import logging
from pathlib import Path
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Request
from fastapi.responses import FileResponse, StreamingResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.core.database import get_db
from app.core.deps import require_glpi_token, require_agent_auth
from app.core.config import get_settings
from app.models.models import Package, Client
from app.schemas.schemas import OkResponse

router = APIRouter(prefix="/api/packages", tags=["packages"])
settings = get_settings()
logger = logging.getLogger(__name__)

PKG_DIR = Path(settings.PACKAGES_DIR)
PKG_DIR.mkdir(parents=True, exist_ok=True)


# ── GET /api/packages/download/{filename} ────────────────────────────────────
@router.get("/download/{filename}")
async def download_package(
    filename: str,
    request: Request,
    _: Client = Depends(require_agent_auth),
):
    """支持 Range 断点续传的包下载"""
    safe_name = Path(filename).name   # 防路径穿越
    file_path = PKG_DIR / safe_name
    if not file_path.exists():
        raise HTTPException(status_code=404, detail="包文件不存在")

    file_size = file_path.stat().st_size
    range_header = request.headers.get("Range")

    if range_header:
        # 解析 Range: bytes=start-end
        try:
            range_val = range_header.replace("bytes=", "")
            start_str, _, end_str = range_val.partition("-")
            start = int(start_str) if start_str else 0
            end   = int(end_str)   if end_str   else file_size - 1
            end   = min(end, file_size - 1)
            length = end - start + 1

            def iter_file():
                with open(file_path, "rb") as f:
                    f.seek(start)
                    remaining = length
                    while remaining > 0:
                        chunk = f.read(min(65536, remaining))
                        if not chunk:
                            break
                        remaining -= len(chunk)
                        yield chunk

            return StreamingResponse(
                iter_file(),
                status_code=206,
                media_type="application/octet-stream",
                headers={
                    "Content-Range":  f"bytes {start}-{end}/{file_size}",
                    "Content-Length": str(length),
                    "Accept-Ranges":  "bytes",
                    "Content-Disposition": f'attachment; filename="{safe_name}"',
                },
            )
        except (ValueError, IndexError):
            raise HTTPException(status_code=416, detail="Range 格式错误")

    return FileResponse(
        path=file_path,
        filename=safe_name,
        media_type="application/octet-stream",
        headers={"Accept-Ranges": "bytes", "Content-Length": str(file_size)},
    )


# ── POST /api/packages/upload ────────────────────────────────────────────────
@router.post("/upload", response_model=OkResponse)
async def upload_package(
    name:        str,
    version:     str,
    silent_args: str = "",
    description: str = "",
    file: UploadFile = File(...),
    _:   bool = Depends(require_glpi_token),
    db:  AsyncSession = Depends(get_db),
):
    """上传安装包，自动计算 SHA256"""
    safe_name = Path(file.filename).name
    dest = PKG_DIR / safe_name

    sha256 = hashlib.sha256()
    size   = 0
    with open(dest, "wb") as f:
        while chunk := await file.read(65536):
            f.write(chunk)
            sha256.update(chunk)
            size += len(chunk)

    file_hash = sha256.hexdigest()

    # upsert Package 记录
    result = await db.execute(
        select(Package).where(Package.name == name, Package.version == version)
    )
    pkg = result.scalar_one_or_none()
    if pkg:
        pkg.filename    = safe_name
        pkg.file_hash   = file_hash
        pkg.file_size   = size
        pkg.silent_args = silent_args
        pkg.description = description
    else:
        db.add(Package(
            name=name, version=version, filename=safe_name,
            silent_args=silent_args, file_hash=file_hash,
            file_size=size, description=description,
        ))
    await db.commit()
    logger.info(f"Package uploaded: {name} {version} ({size} bytes)")
    return OkResponse(message=f"上传成功，SHA256={file_hash}")


# ── GET /api/packages ─────────────────────────────────────────────────────────
@router.get("")
async def list_packages(
    _:  bool = Depends(require_glpi_token),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(Package))
    pkgs = result.scalars().all()
    return [
        {
            "id": p.id, "name": p.name, "version": p.version,
            "filename": p.filename, "file_hash": p.file_hash,
            "file_size": p.file_size, "description": p.description,
            "silent_args": p.silent_args,
        }
        for p in pkgs
    ]


# ── POST /api/packages/register ─────────────────────────────────────────────
@router.post("/register", response_model=OkResponse)
async def register_package(
    name:        str,
    version:     str,
    filename:    str,
    file_size:   int,
    file_hash:   str = "",
    silent_args: str = "",
    description: str = "",
    _:   bool = Depends(require_glpi_token),
    db:  AsyncSession = Depends(get_db),
):
    """注册包元数据（文件已由调用方放到 packages 目录）"""
    result = await db.execute(
        select(Package).where(Package.name == name, Package.version == version)
    )
    pkg = result.scalar_one_or_none()
    if pkg:
        pkg.filename    = filename
        pkg.file_hash   = file_hash
        pkg.file_size   = file_size
        pkg.silent_args = silent_args
        pkg.description = description
    else:
        db.add(Package(
            name=name, version=version, filename=filename,
            silent_args=silent_args, file_hash=file_hash,
            file_size=file_size, description=description,
        ))
    await db.commit()
    return OkResponse(message=f"包已注册: {name} {version}")


# ── DELETE /api/packages/{pkg_id} ────────────────────────────────────────────
@router.delete("/{pkg_id}", response_model=OkResponse)
async def delete_package(
    pkg_id: int,
    _:  bool = Depends(require_glpi_token),
    db: AsyncSession = Depends(get_db),
):
    """删除安装包记录及磁盘文件"""
    result = await db.execute(select(Package).where(Package.id == pkg_id))
    pkg = result.scalar_one_or_none()
    if not pkg:
        raise HTTPException(status_code=404, detail="包不存在")

    # 删除磁盘文件（不存在也不报错）
    file_path = PKG_DIR / pkg.filename
    if file_path.exists():
        file_path.unlink()
        logger.info(f"Package file deleted: {pkg.filename}")

    await db.delete(pkg)
    await db.commit()
    logger.info(f"Package record deleted: {pkg.name} {pkg.version}")
    return OkResponse(message=f"已删除安装包：{pkg.name} {pkg.version}")


# ── PATCH /api/packages/{pkg_id} ─────────────────────────────────────────────
@router.patch("/{pkg_id}", response_model=OkResponse)
async def update_package(
    pkg_id:      int,
    name:        str = "",
    version:     str = "",
    silent_args: str = "",
    description: str = "",
    _:  bool = Depends(require_glpi_token),
    db: AsyncSession = Depends(get_db),
):
    """更新安装包元数据（名称/版本/静默参数/描述）"""
    result = await db.execute(select(Package).where(Package.id == pkg_id))
    pkg = result.scalar_one_or_none()
    if not pkg:
        raise HTTPException(status_code=404, detail="包不存在")

    if name:        pkg.name        = name
    if version:     pkg.version     = version
    if silent_args is not None and silent_args != "":
        pkg.silent_args = silent_args
    if description is not None:
        pkg.description = description
    await db.commit()
    logger.info(f"Package updated: id={pkg_id} name={pkg.name} version={pkg.version}")
    return OkResponse(message=f"已更新：{pkg.name} {pkg.version}")
