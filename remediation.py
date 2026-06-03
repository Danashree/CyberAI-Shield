"""
Remediation API routes (R10 — Automated Remediation Suggestion System)
  GET  /remediation/playbooks?upload_id=xxx   — instant playbooks for upload's threats
  POST /remediation/deep-analysis             — Groq LLM deep remediation plan
  POST /remediation/execute/{playbook_id}     — mark a playbook step as done
"""

from fastapi import APIRouter, HTTPException, Depends, Query
from pydantic import BaseModel
from api.auth import require_analyst, UserOut
from database import AsyncSessionLocal, ThreatModel, threat_to_dict
from sqlalchemy import select
from typing import Optional
import logging

router = APIRouter()
logger = logging.getLogger("cyberai.remediation")


class DeepAnalysisRequest(BaseModel):
    upload_id: Optional[str] = None


@router.get("/playbooks")
async def get_playbooks(
    upload_id:    Optional[str] = Query(None),
    current_user: UserOut       = Depends(require_analyst),
):
    """Get instant rule-based playbooks for all threats (optionally scoped to upload)."""
    from ml.remediation_engine import get_all_playbooks

    async with AsyncSessionLocal() as db:
        stmt = select(ThreatModel)
        if upload_id:
            stmt = stmt.where(ThreatModel.upload_id == upload_id)
        else:
            stmt = stmt.where(ThreatModel.status == "active")
        
        result  = await db.execute(stmt)
        threats = [threat_to_dict(t) for t in result.scalars().all()]

    if not threats:
        return {"playbooks": [], "total": 0}

    playbooks = get_all_playbooks(threats)
    # Sort by priority P1 first
    priority_order = {"P1": 0, "P2": 1, "P3": 2, "P4": 3}
    playbooks.sort(key=lambda p: priority_order.get(p.get("priority", "P4"), 3))

    return {"playbooks": playbooks, "total": len(playbooks)}


@router.post("/deep-analysis")
async def deep_analysis(
    req:          DeepAnalysisRequest,
    current_user: UserOut = Depends(require_analyst),
):
    """Run Groq LLM deep remediation analysis across all threats in an upload."""
    from ml.remediation_engine import generate_deep_remediation

    async with AsyncSessionLocal() as db:
        stmt = select(ThreatModel)
        if req.upload_id:
            stmt = stmt.where(ThreatModel.upload_id == req.upload_id)
        else:
            stmt = stmt.where(ThreatModel.status == "active")
        
        result  = await db.execute(stmt)
        threats = [threat_to_dict(t) for t in result.scalars().all()]

    if not threats:
        raise HTTPException(404, "No threats found. Upload logs first.")

    try:
        result = await generate_deep_remediation(threats, req.upload_id)
        return result
    except Exception as e:
        raise HTTPException(500, f"Deep analysis failed: {str(e)}")