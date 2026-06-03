from fastapi import APIRouter, HTTPException, Depends, Query
from sqlalchemy import select, update, delete
from api.auth import get_current_user, UserOut
from database import (
    AsyncSessionLocal, ThreatModel,
    dict_to_threat, threat_to_dict
)
from typing import Optional
import logging

router = APIRouter()
logger = logging.getLogger("cyberai")


def get_threats_store():
    return []


async def add_threats(threats: list[dict], upload_id: str = None):
    """Save threats to SQLite — append, don't delete."""
    if not threats:
        return
    async with AsyncSessionLocal() as db:
        for t in threats:
            if upload_id:
                t["upload_id"] = upload_id
            db.add(dict_to_threat(t))
        await db.commit()
    logger.info(f"Saved {len(threats)} threats to database")


@router.get("/")
async def list_threats(
    severity:    Optional[str] = Query(None),
    attack_type: Optional[str] = Query(None),
    upload_id:   Optional[str] = Query(None),
    all_history: bool          = Query(False),
    limit:       int           = Query(50, le=200),
    current_user: UserOut      = Depends(get_current_user),
):
    async with AsyncSessionLocal() as db:
        # If not viewing all history and no specific upload_id given, find the latest upload
        if not all_history and not upload_id:
            from database import UploadModel
            res = await db.execute(select(UploadModel).order_by(UploadModel.uploaded_at.desc()).limit(1))
            latest = res.scalar_one_or_none()
            if latest:
                upload_id = latest.id

        stmt = select(ThreatModel).order_by(ThreatModel.created_at.desc())
        if severity:
            stmt = stmt.where(ThreatModel.severity == severity.lower())
        if attack_type:
            stmt = stmt.where(ThreatModel.type.ilike(f"%{attack_type}%"))
        if upload_id:
            stmt = stmt.where(ThreatModel.upload_id == upload_id)
        
        result = await db.execute(stmt)
        threats = [threat_to_dict(t) for t in result.scalars().all()]

    try:
        from ml.priority_engine import prioritize_threats
        threats = prioritize_threats(threats)
    except Exception as e:
        logger.warning(f"Priority engine skipped: {e}")

    return {"total": len(threats), "threats": threats[:limit]}


@router.get("/summary")
async def threats_summary(current_user: UserOut = Depends(get_current_user)):
    async with AsyncSessionLocal() as db:
        from database import UploadModel
        # Get latest upload ID
        res = await db.execute(select(UploadModel).order_by(UploadModel.uploaded_at.desc()).limit(1))
        latest = res.scalar_one_or_none()
        
        stmt = select(ThreatModel)
        if latest:
            stmt = stmt.where(ThreatModel.upload_id == latest.id)
            
        result  = await db.execute(stmt)
        threats = [threat_to_dict(t) for t in result.scalars().all()]

    summary      = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    attack_types = {}

    for t in threats:
        sev = t.get("severity", "low")
        summary[sev] = summary.get(sev, 0) + 1
        atype = t.get("type", "unknown")
        attack_types[atype] = attack_types.get(atype, 0) + 1

    return {
        "severity_breakdown": summary,
        "attack_types":       attack_types,
        "total":              len(threats),
        "latest_file":        latest.original_name if latest else "None"
    }


@router.get("/{threat_id}")
async def get_threat(
    threat_id:    str,
    current_user: UserOut = Depends(get_current_user),
):
    async with AsyncSessionLocal() as db:
        result = await db.execute(
            select(ThreatModel).where(ThreatModel.id == threat_id)
        )
        threat = result.scalar_one_or_none()

    if not threat:
        raise HTTPException(404, f"Threat {threat_id} not found")
    return threat_to_dict(threat)


@router.post("/{threat_id}/resolve")
async def resolve_threat(
    threat_id:    str,
    current_user: UserOut = Depends(get_current_user),
):
    async with AsyncSessionLocal() as db:
        result = await db.execute(
            select(ThreatModel).where(ThreatModel.id == threat_id)
        )
        threat = result.scalar_one_or_none()
        if not threat:
            raise HTTPException(404, f"Threat {threat_id} not found")
        threat.status = "resolved"
        await db.commit()

    return {"message": f"Threat {threat_id} marked as resolved"}


@router.delete("/all")
async def clear_all_threats(current_user: UserOut = Depends(get_current_user)):
    async with AsyncSessionLocal() as db:
        await db.execute(delete(ThreatModel))
        await db.commit()
    return {"message": "All threats cleared"}