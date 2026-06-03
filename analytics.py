"""
Analytics API — supplies chart data for Dashboard Visualization (R9)
Endpoints:
  GET /analytics/threat-trend      — threats per day (last 14 days)
  GET /analytics/severity-timeline — severity breakdown over time
  GET /analytics/attack-heatmap    — attack type × hour-of-day matrix
  GET /analytics/top-ips           — top 10 attacker IPs
  GET /analytics/risk-history      — risk score over time (last 20 points)
"""

from fastapi import APIRouter, Depends
from api.auth import get_current_user, UserOut
from database import AsyncSessionLocal, ThreatModel, threat_to_dict
from sqlalchemy import select
from datetime import datetime, timedelta
from collections import defaultdict
import logging

router  = APIRouter()
logger  = logging.getLogger("cyberai.analytics")


@router.get("/threat-trend")
async def threat_trend(current_user: UserOut = Depends(get_current_user)):
    # Efficiency: Select only threats from the last 14 days
    cutoff = datetime.utcnow() - timedelta(days=14)
    async with AsyncSessionLocal() as db:
        stmt = select(ThreatModel).where(ThreatModel.created_at >= cutoff)
        result = await db.execute(stmt)
        threats = [threat_to_dict(t) for t in result.scalars().all()]

    today  = datetime.utcnow().date()
    days   = [(today - timedelta(days=i)) for i in range(13, -1, -1)]
    counts = defaultdict(int)

    for t in threats:
        ca = t.get("created_at")
        if not ca: continue
        try:
            # handle both datetime object and string
            d = datetime.fromisoformat(ca).date() if isinstance(ca, str) else ca.date()
            counts[str(d)] += 1
        except Exception:
            pass

    return {
        "labels": [str(d) for d in days],
        "data":   [counts.get(str(d), 0) for d in days],
    }


@router.get("/severity-timeline")
async def severity_timeline(current_user: UserOut = Depends(get_current_user)):
    cutoff = datetime.utcnow() - timedelta(days=7)
    async with AsyncSessionLocal() as db:
        stmt = select(ThreatModel).where(ThreatModel.created_at >= cutoff)
        result = await db.execute(stmt)
        threats = [threat_to_dict(t) for t in result.scalars().all()]

    today  = datetime.utcnow().date()
    days   = [(today - timedelta(days=i)) for i in range(6, -1, -1)]
    sevs   = ["critical", "high", "medium", "low"]
    matrix = {s: defaultdict(int) for s in sevs}

    for t in threats:
        ca = t.get("created_at")
        if not ca: continue
        try:
            d   = datetime.fromisoformat(ca).date() if isinstance(ca, str) else ca.date()
            sev = t.get("severity", "low")
            if sev in matrix:
                matrix[sev][str(d)] += 1
        except Exception:
            pass

    labels = [str(d) for d in days]
    return {
        "labels":   labels,
        "critical": [matrix["critical"].get(l, 0) for l in labels],
        "high":     [matrix["high"].get(l, 0)     for l in labels],
        "medium":   [matrix["medium"].get(l, 0)   for l in labels],
        "low":      [matrix["low"].get(l, 0)       for l in labels],
    }


@router.get("/attack-heatmap")
async def attack_heatmap(current_user: UserOut = Depends(get_current_user)):
    """Attack type × hour-of-day matrix (for heatmap)."""
    async with AsyncSessionLocal() as db:
        result  = await db.execute(select(ThreatModel))
        threats = [threat_to_dict(t) for t in result.scalars().all()]

    attack_types = ["Brute Force", "Port Scan", "SQL Injection",
                    "C2 Beacon", "Data Exfiltration", "Anomaly"]
    matrix = {a: [0] * 24 for a in attack_types}

    for t in threats:
        atype = t.get("type", "Anomaly")
        if atype not in matrix:
            atype = "Anomaly"
        raw = t.get("raw_features", {})
        hour = int(raw.get("hour_of_day", 0)) if raw else 0
        hour = max(0, min(23, hour))
        matrix[atype][hour] += 1

    return {"attack_types": attack_types, "matrix": matrix}


@router.get("/top-ips")
async def top_ips(current_user: UserOut = Depends(get_current_user)):
    """Top 10 source IPs by threat count."""
    async with AsyncSessionLocal() as db:
        result  = await db.execute(select(ThreatModel))
        threats = [threat_to_dict(t) for t in result.scalars().all()]

    ip_counts = defaultdict(int)
    ip_sev    = defaultdict(lambda: "low")
    sev_rank  = {"critical": 3, "high": 2, "medium": 1, "low": 0}

    for t in threats:
        ip  = t.get("source_ip", "unknown")
        sev = t.get("severity", "low")
        ip_counts[ip] += 1
        if sev_rank[sev] > sev_rank[ip_sev[ip]]:
            ip_sev[ip] = sev

    top = sorted(ip_counts.items(), key=lambda x: -x[1])[:10]
    return {
        "ips":    [x[0] for x in top],
        "counts": [x[1] for x in top],
        "sevs":   [ip_sev[x[0]] for x in top],
    }


@router.get("/risk-history")
async def risk_history_chart(current_user: UserOut = Depends(get_current_user)):
    """Risk score history — last 20 data points."""
    try:
        from ml.risk_score import get_score_history
        history = await get_score_history(20)
        return {
            "labels": [h.get("recorded_at", "")[:16] for h in history],
            "scores": [h.get("score", 0) for h in history],
        }
    except Exception:
        return {"labels": [], "scores": []}