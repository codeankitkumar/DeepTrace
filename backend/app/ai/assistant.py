"""AI Investigation Assistant.

A hybrid, rule-informed assistant that answers investigator questions by mining the
persisted case data (evidence, findings, timeline, anomalies). It supports intents:
summarize, explain, relate, suggest, and report. Every AI response explicitly declares
that its conclusions are HYPOTHESES, not verified forensic findings.
"""
from __future__ import annotations

from collections import Counter
from typing import Any

from sqlalchemy.orm import Session

from app.db import models
from app.services import report_service, timeline_engine

_INTENT_KEYWORDS = {
    "summarize": ("summar", "overview", "brief", "what is this case", "summary"),
    "explain": ("explain", "why", "what happened", "how", "mean", "what does"),
    "relate": ("relate", "correlate", "linked", "related", "connection", "pattern", "relationship"),
    "suggest": ("suggest", "next step", "recommend", "should i", "advise", "investigate further"),
    "report": ("report", "generate report", "write report", "draft report"),
}


def _detect_intent(query: str) -> str:
    q = query.lower()
    scores: dict[str, int] = {}
    for intent, kws in _INTENT_KEYWORDS.items():
        scores[intent] = sum(1 for k in kws if k in q)
    if not any(scores.values()):
        return "summarize"
    return max(scores, key=scores.get)


def _load_context(db: Session, case_id: int) -> dict[str, Any]:
    case = db.get(models.Case, case_id)
    evidence = db.query(models.Evidence).filter(models.Evidence.case_id == case_id).all()
    findings = db.query(models.Finding).filter(models.Finding.case_id == case_id).all()
    timeline = timeline_engine.build_timeline(db, case_id)
    anomalies = timeline_engine.detect_unusual_sequences(db, case_id)
    corr = timeline_engine.correlation_summary(db, case_id)
    return {
        "case": case,
        "evidence": evidence,
        "findings": findings,
        "timeline": timeline,
        "anomalies": anomalies,
        "correlation": corr,
    }


def answer(db: Session, case_id: int, query: str, actor_id: int) -> dict[str, Any]:
    intent = _detect_intent(query)
    ctx = _load_context(db, case_id)
    case = ctx["case"]
    if not case:
        return {"intent": "error", "content": "Case not found.", "is_hypothesis": False,
                "suggestions": [], "matched_evidence": []}

    if intent == "report":
        report = report_service.build_report(db, case_id)
        return {
            "intent": "report",
            "content": report_service.render_markdown(report),
            "is_hypothesis": True,
            "suggestions": ["Review and verify each hypothesis before finalizing the report."],
            "matched_evidence": [e["name"] for e in report["evidence_inventory"]],
        }

    handlers = {
        "summarize": _summarize,
        "explain": _explain,
        "relate": _relate,
        "suggest": _suggest,
    }
    result = handlers[intent](ctx, query)
    result["intent"] = intent
    result["is_hypothesis"] = True
    return result


def _summarize(ctx: dict[str, Any], query: str) -> dict[str, Any]:
    case = ctx["case"]
    evidence = ctx["evidence"]
    findings = ctx["findings"]
    corr = ctx["correlation"]
    sevs = Counter(f.severity for f in findings)
    verified = [f for f in findings if not f.is_hypothesis]
    hyp = [f for f in findings if f.is_hypothesis]

    content = (
        f"## Case Summary (Hypothesis)\n\n"
        f"**Case:** {case.name} ({case.reference_number or 'no reference'})\n"
        f"- {len(evidence)} evidence item(s) ingested; "
        f"{sum(1 for e in evidence if e.integrity_status == 'verified')} integrity-verified.\n"
        f"- {len(findings)} finding(s): {sevs.get('high', 0)} high, {sevs.get('medium', 0)} medium, "
        f"{sevs.get('low', 0)} low, {sevs.get('info', 0)} info.\n"
        f"- Timeline: {corr['total_events']} events spanning {(corr['earliest_utc'] or 'N/A')} "
        f"to {(corr['latest_utc'] or 'N/A')} UTC.\n"
        f"- {len(ctx['anomalies'])} unusual sequence(s) flagged.\n"
    )
    if verified:
        content += "\n**Verified findings:**\n" + "\n".join(f"- {f.title}" for f in verified[:5])
    if hyp:
        content += "\n**Hypotheses (requires verification):**\n" + "\n".join(
            f"- {f.title}" for f in hyp[:5]
        )
    content += "\n\n> This summary is an AI-generated hypothesis and must be verified by an analyst."
    return {
        "content": content,
        "suggestions": [
            "Verify AI-tagged hypotheses against raw evidence.",
            "Run the suspicious-file module on un-analyzed evidence.",
        ],
        "matched_evidence": [e.original_name for e in evidence],
    }


def _explain(ctx: dict[str, Any], query: str) -> dict[str, Any]:
    findings = ctx["findings"]
    anomalies = ctx["anomalies"]
    by_severity = [f for f in findings if f.severity in ("critical", "high", "medium")]
    key = by_severity[:3] or findings[:3]
    content = "## Explanation of Suspicious Activity (Hypothesis)\n\n"
    if key:
        for f in key:
            content += f"- **{f.title}** ({f.severity}): {f.description}\n"
    else:
        content += "_No high/medium findings were produced by the analysis modules._\n"
    if anomalies:
        content += "\n**Notable correlated sequences:**\n"
        for a in anomalies[:3]:
            content += f"- {a['description']} (severity {a['severity']})\n"
    content += "\n> Explanation is a hypothesis; correlation does not establish causation."
    return {
        "content": content,
        "suggestions": ["Correlate the flagged processes with the network connections in the timeline."],
        "matched_evidence": [],
    }


def _relate(ctx: dict[str, Any], query: str) -> dict[str, Any]:
    corr = ctx["correlation"]
    sour = "/".join(f"{k}={v}" for k, v in list(corr["by_source"].items())[:6])
    content = (
        "## Related Events Across Sources (Hypothesis)\n\n"
        f"- Events by source: {sour or 'none'}.\n"
        f"- Categories present: {', '.join(corr['by_category'].keys()) or 'none'}.\n"
    )
    if corr["by_category"].get("browsing") and corr["by_category"].get("network"):
        content += "- Co-occurrence of browsing and network events suggests a possible download→exfil link.\n"
    if ctx["anomalies"]:
        content += "- Detected anomalous sequences may connect logon and process artifacts.\n"
    content += "\n> Relationships are hypothesized; manual validation recommended."
    return {
        "content": content,
        "suggestions": ["Build a focused timeline around the anomalous window to confirm the linkage."],
        "matched_evidence": [],
    }


def _suggest(ctx: dict[str, Any], query: str) -> dict[str, Any]:
    evidence = ctx["evidence"]
    analyzed = {e.id for e in evidence if e.status == "analyzed"}
    not_analyzed = [e for e in evidence if e.id not in analyzed]
    suggestions = []
    if not_analyzed:
        suggestions.append(f"Run analysis modules on {len(not_analyzed)} not-yet-analyzed evidence item(s).")
    if ctx["anomalies"]:
        suggestions.append("Deep-dive the flagged unusual sequences (e.g., brute-force pattern).")
    suggestions.append("Verify all AI hypotheses against original artifacts before reporting.")
    suggestions.append("Re-run integrity verification on all evidence immediately before finalizing.")
    suggestions.append("Generate a structured forensic report once findings are verified.")
    content = (
        "## Suggested Investigation Steps (Hypothesis)\n\n"
        + "\n".join(f"{i+1}. {s}" for i, s in enumerate(suggestions))
        + "\n\n> Recommendations are advisory and AI-generated."
    )
    return {"content": content, "suggestions": suggestions,
            "matched_evidence": [e.original_name for e in not_analyzed]}