from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
from api.auth import get_current_user, UserOut
from groq import AsyncGroq
import os

router = APIRouter()

client = AsyncGroq(api_key=os.getenv("GROQ_API_KEY"))
MODEL  = os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile")

_chat_history = []

SYSTEM_PROMPT = """You are CyberAI Shield's SOC (Security Operations Center) AI assistant.
You have direct access to real-time threat detection results from an Isolation Forest ML model.
You help security analysts understand threats, prioritize actions, and get remediation advice.
Be concise, technical, and actionable. Use bullet points for lists.
Always reference specific IPs, threat types, and SHAP feature importances when available.
Never say you don't have data — use the context provided below."""


class ChatMessage(BaseModel):
    message: str


@router.post("/")
async def chat(
    body: ChatMessage,
    current_user: UserOut = Depends(get_current_user),
):
    if not body.message.strip():
        raise HTTPException(400, "Message cannot be empty")

    # Build rich context from real database
    threat_context = await build_threat_context()

    messages = [
        {"role": "system", "content": SYSTEM_PROMPT + "\n\n" + threat_context},
        *_chat_history[-10:],
        {"role": "user", "content": body.message},
    ]

    try:
        response = await client.chat.completions.create(
            model=MODEL,
            messages=messages,
            max_tokens=1024,
            temperature=0.4,
        )
        reply = response.choices[0].message.content

        _chat_history.append({"role": "user",      "content": body.message})
        _chat_history.append({"role": "assistant",  "content": reply})

        return {"reply": reply, "model": MODEL}

    except Exception as e:
        raise HTTPException(500, f"Groq API error: {str(e)}")


async def build_threat_context() -> str:
    """Build detailed threat context from database for LLM."""
    try:
        from database import AsyncSessionLocal, ThreatModel, threat_to_dict
        from ml.risk_score import get_current_score
        from sqlalchemy import select

        score, label = get_current_score()

        async with AsyncSessionLocal() as db:
            result  = await db.execute(
                select(ThreatModel).order_by(ThreatModel.created_at.desc())
            )
            threats = [threat_to_dict(t) for t in result.scalars().all()]

        active   = [t for t in threats if t.get("status") == "active"]
        critical = [t for t in threats if t.get("severity") == "critical"]
        high     = [t for t in threats if t.get("severity") == "high"]

        context = f"""
=== CURRENT SECURITY STATUS ===
Risk Score: {score}/100 — {label}
Total Threats: {len(threats)}
Active Threats: {len(active)}
Critical: {len(critical)} | High: {len(high)}

=== ACTIVE THREATS (REAL DATA) ==="""

        for t in active[:8]:
            shap_top = ""
            if t.get("shap"):
                top = t["shap"][0]
                shap_top = f"Top SHAP: {top['feature']} ({top['importance']}% importance)"

            context += f"""
- ID: {t['id']}
  Type: {t['type']} | Severity: {t['severity'].upper()} | Confidence: {int(t['confidence']*100)}%
  Source IP: {t['source_ip']} → {t['dest_ip']}:{t['port']}
  Username: {t.get('username') or 'N/A'} | Timestamp: {t['timestamp']}
  {shap_top}"""

        if not active:
            context += "\nNo active threats. System is clean."

        context += f"""

=== ATTACK TYPE SUMMARY ==="""
        attack_counts = {}
        for t in threats:
            atype = t.get("type", "Unknown")
            attack_counts[atype] = attack_counts.get(atype, 0) + 1

        for atype, count in sorted(attack_counts.items(), key=lambda x: -x[1]):
            context += f"\n- {atype}: {count} instance(s)"

        return context

    except Exception as e:
        return f"Context load error: {str(e)}. Threats may not be loaded yet."


@router.delete("/history")
async def clear_history(current_user: UserOut = Depends(get_current_user)):
    _chat_history.clear()
    return {"message": "Chat history cleared"}