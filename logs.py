from fastapi import APIRouter, UploadFile, File, HTTPException, Depends
import aiofiles
import os
import uuid
import logging
from datetime import datetime
from api.auth import require_analyst, UserOut

router = APIRouter()
logger = logging.getLogger("cyberai")

UPLOAD_DIR  = os.getenv("UPLOAD_DIR", "data/uploads")
MAX_SIZE_MB = int(os.getenv("MAX_UPLOAD_SIZE_MB", 50))


@router.post("/upload")
async def upload_logs(
    file: UploadFile = File(...),
    current_user: UserOut = Depends(require_analyst),
):
    contents = await file.read()
    size_mb  = len(contents) / (1024 * 1024)
    if size_mb > MAX_SIZE_MB:
        raise HTTPException(400, f"File too large: {size_mb:.1f}MB (max {MAX_SIZE_MB}MB)")

    os.makedirs(UPLOAD_DIR, exist_ok=True)
    file_id  = str(uuid.uuid4())[:8]
    filename = f"{file_id}_{file.filename}"
    filepath = os.path.join(UPLOAD_DIR, filename)

    async with aiofiles.open(filepath, "wb") as f:
        await f.write(contents)

    try:
        from ml.ingestion  import ingest_logs
        from ml.detector   import detect_threats
        from ml.explainer  import explain_threats
        from ml.risk_score import calculate_risk_score
        from api.threats   import add_threats

        df      = ingest_logs(filepath)
        threats = detect_threats(df)
        threats = explain_threats(threats, df)

        try:
            from services.threat_intel import enrich_threats
            threats = await enrich_threats(threats)
            logger.info(f"Threat intel enrichment done for {len(threats)} threats")
        except Exception as e:
            logger.warning(f"Threat intel enrichment skipped: {e}")

        score, label = calculate_risk_score(threats)

        # ✅ Save upload record FIRST to get the upload_id
        try:
            from database import AsyncSessionLocal, UploadModel
            async with AsyncSessionLocal() as db:
                upload_record = UploadModel(
                    id             = file_id,
                    filename       = filename,
                    original_name  = file.filename,
                    size_kb        = round(len(contents) / 1024, 1),
                    rows_ingested  = len(df),
                    threats_found  = len(threats),
                    risk_score     = score,
                    risk_label     = label,
                    uploaded_by    = current_user.email,
                )
                db.add(upload_record)
                await db.commit()
            logger.info(f"Upload record saved: {file_id}")
        except Exception as e:
            logger.warning(f"Upload record save failed: {e}")

        # ✅ Now save threats with the upload_id
        await add_threats(threats, upload_id=file_id)

        try:
            from services.siem import push_threats_bulk
            siem_result = await push_threats_bulk(threats)
            logger.info(f"SIEM push result: {siem_result}")
        except Exception as e:
            logger.warning(f"SIEM push skipped: {e}")

        return {
            "status":        "success",
            "file_id":       file_id,
            "filename":      file.filename,
            "rows_ingested": len(df),
            "threats_found": len(threats),
            "risk_score":    score,
            "risk_label":    label,
            "uploaded_at":   datetime.utcnow().isoformat(),
        }

    except Exception as e:
        logger.error(f"ML pipeline error: {e}", exc_info=True)
        raise HTTPException(500, f"ML pipeline error: {str(e)}")


@router.get("/history")
async def upload_history(current_user: UserOut = Depends(require_analyst)):
    try:
        from database import AsyncSessionLocal, UploadModel
        from sqlalchemy import select
        async with AsyncSessionLocal() as db:
            result  = await db.execute(
                select(UploadModel).order_by(UploadModel.uploaded_at.desc())
            )
            uploads = result.scalars().all()
            return {
                "uploads": [
                    {
                        "file_id":       u.id,
                        "filename":      u.original_name,
                        "size_kb":       u.size_kb,
                        "rows_ingested": u.rows_ingested,
                        "threats_found": u.threats_found,
                        "risk_score":    u.risk_score,
                        "risk_label":    u.risk_label,
                        "uploaded_by":   u.uploaded_by,
                        "uploaded":      u.uploaded_at.isoformat() if u.uploaded_at else "",
                    }
                    for u in uploads
                ]
            }
    except Exception as e:
        logger.warning(f"DB history failed: {e}")
        os.makedirs(UPLOAD_DIR, exist_ok=True)
        files = []
        for fname in os.listdir(UPLOAD_DIR):
            fpath = os.path.join(UPLOAD_DIR, fname)
            files.append({
                "filename": fname,
                "size_kb":  round(os.path.getsize(fpath) / 1024, 1),
                "uploaded": datetime.fromtimestamp(
                    os.path.getmtime(fpath)
                ).isoformat(),
            })
        return {"uploads": sorted(files, key=lambda x: x["uploaded"], reverse=True)}