from fastapi import APIRouter, HTTPException, Depends
from sqlalchemy import select, delete
from pydantic import BaseModel
from api.auth import require_analyst, UserOut, get_current_user
from database import (
    AsyncSessionLocal, ReportModel,
    dict_to_report, report_to_dict
)
from typing import Optional
import logging

router = APIRouter()
logger = logging.getLogger("cyberai")

class ReportRequest(BaseModel):
    threat_ids: list[str]
    title:      Optional[str] = None
    upload_id:  Optional[str] = None   # ✅ NEW

class ComplianceReportRequest(BaseModel):
    framework:  str           = "gdpr"
    title:      Optional[str] = None
    upload_id:  Optional[str] = None   # ✅ NEW

# ── List all reports ──────────────────────────────────────────
@router.get("/")
async def list_reports(current_user: UserOut = Depends(require_analyst)):
    async with AsyncSessionLocal() as db:
        result  = await db.execute(
            select(ReportModel).order_by(ReportModel.created_at.desc())
        )
        reports = [report_to_dict(r) for r in result.scalars().all()]
    return {"total": len(reports), "reports": reports}

# ── Generate report from selected threats ─────────────────────
@router.post("/generate")
async def generate_report(
    req:          ReportRequest,
    current_user: UserOut = Depends(require_analyst),
):
    from ml.report_gen import generate_incident_report
    from database import ThreatModel, threat_to_dict

    async with AsyncSessionLocal() as db:
        stmt = select(ThreatModel)
        if req.upload_id:
            stmt = stmt.where(ThreatModel.upload_id == req.upload_id)
        
        # SQL-level filter for selected threats
        stmt = stmt.where(ThreatModel.id.in_(req.threat_ids))
        
        result   = await db.execute(stmt)
        selected = [threat_to_dict(t) for t in result.scalars().all()]
    if not selected:
        raise HTTPException(404, "No matching threats found")

    try:
        report = await generate_incident_report(selected, req.title)
        async with AsyncSessionLocal() as db:
            db.add(dict_to_report(report))
            await db.commit()
        logger.info(f"Report saved: {report.get('id')}")
        return report
    except Exception as e:
        logger.error(f"Report generation failed: {e}")
        raise HTTPException(500, f"Report generation failed: {str(e)}")

# ── Generate report from ALL active threats ───────────────────
@router.post("/generate-all")
async def generate_report_all(
    current_user: UserOut = Depends(require_analyst)
):
    from ml.report_gen import generate_incident_report
    from database import ThreatModel, threat_to_dict

    async with AsyncSessionLocal() as db:
        stmt = select(ThreatModel).where(ThreatModel.status == "active")
        result = await db.execute(stmt)
        active = [threat_to_dict(t) for t in result.scalars().all()]
    if not active:
        raise HTTPException(404, "No active threats found. Upload logs first.")

    try:
        report = await generate_incident_report(active, None)
        async with AsyncSessionLocal() as db:
            db.add(dict_to_report(report))
            await db.commit()
        return report
    except Exception as e:
        raise HTTPException(500, f"Report generation failed: {str(e)}")

# ── SIEM test ─────────────────────────────────────────────────
@router.get("/siem/test")
async def test_siem(current_user: UserOut = Depends(require_analyst)):
    try:
        from services.siem import test_siem_connection
        return await test_siem_connection()
    except Exception as e:
        return {"status": "error", "message": str(e)}

# ✅ COMPLIANCE ROUTES — MUST BE ABOVE /{report_id}
@router.get("/compliance/frameworks")
async def list_frameworks(current_user: UserOut = Depends(get_current_user)):
    return {
        "frameworks": [
            {"id": "gdpr",     "name": "GDPR",     "full": "General Data Protection Regulation"},
            {"id": "hipaa",    "name": "HIPAA",    "full": "Health Insurance Portability and Accountability Act"},
            {"id": "pci_dss",  "name": "PCI-DSS",  "full": "Payment Card Industry Data Security Standard"},
            {"id": "iso27001", "name": "ISO 27001", "full": "Information Security Management"},
        ]
    }

@router.post("/compliance/generate")
async def generate_compliance(
    req:          ComplianceReportRequest,
    current_user: UserOut = Depends(require_analyst),
):
    from ml.compliance_gen import generate_compliance_report
    from database import ThreatModel, threat_to_dict

    async with AsyncSessionLocal() as db:
        result  = await db.execute(select(ThreatModel))
        threats = [threat_to_dict(t) for t in result.scalars().all()]

    # ✅ Filter by upload_id if provided, otherwise use all active threats
    if req.upload_id:
        active = [t for t in threats if t.get("upload_id") == req.upload_id]
    else:
        active = [t for t in threats if t.get("status") == "active"]

    if not active:
        raise HTTPException(404, "No threats found for this upload. Upload logs first.")

    try:
        report = await generate_compliance_report(active, req.framework, req.title)
        return report
    except Exception as e:
        raise HTTPException(500, f"Compliance report failed: {str(e)}")

# ✅ /{report_id} MUST BE LAST — below all named routes
@router.get("/{report_id}")
async def get_report(
    report_id:    str,
    current_user: UserOut = Depends(require_analyst),
):
    async with AsyncSessionLocal() as db:
        result = await db.execute(
            select(ReportModel).where(ReportModel.id == report_id)
        )
        report = result.scalar_one_or_none()
    if not report:
        raise HTTPException(404, f"Report {report_id} not found")
    return report_to_dict(report)

@router.delete("/{report_id}")
async def delete_report(
    report_id:    str,
    current_user: UserOut = Depends(require_analyst),
):
    async with AsyncSessionLocal() as db:
        result = await db.execute(
            select(ReportModel).where(ReportModel.id == report_id)
        )
        report = result.scalar_one_or_none()
        if not report:
            raise HTTPException(404, f"Report {report_id} not found")
        await db.delete(report)
        await db.commit()
    return {"message": f"Report {report_id} deleted"}