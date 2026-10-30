"""Forensic report generation.

Assembles a professional, structured report from persisted case data: case information,
evidence inventory with SHA-256 hashes, analysis methodology, timeline, findings,
limitations, and analyst conclusions. AI-generated content is clearly separated and
labeled as hypothesis.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from sqlalchemy.orm import Session

from app.db import models
from app.services import timeline_engine


def build_report(db: Session, case_id: int, analyst_name: str = "Analyst") -> dict[str, Any]:
    case = db.get(models.Case, case_id)
    if not case:
        raise ValueError("Case not found")
    evidence = db.query(models.Evidence).filter(models.Evidence.case_id == case_id).all()
    findings = (
        db.query(models.Finding)
        .filter(models.Finding.case_id == case_id)
        .order_by(models.Finding.created_at)
        .all()
    )
    timeline = timeline_engine.build_timeline(db, case_id)
    anomalies = timeline_engine.detect_unusual_sequences(db, case_id)
    runs = (
        db.query(models.AnalysisRun)
        .join(models.Evidence, models.AnalysisRun.evidence_id == models.Evidence.id)
        .filter(models.Evidence.case_id == case_id)
        .order_by(models.AnalysisRun.started_at)
        .all()
    )
    verified = sum(1 for e in evidence if e.integrity_status == "verified")
    verified_findings = [f for f in findings if not f.is_hypothesis]
    hypotheses = [f for f in findings if f.is_hypothesis]

    return {
        "report_metadata": {
            "generated_at_utc": datetime.now(timezone.utc).isoformat(),
            "analyst": analyst_name,
            "tool": "DeepTrace Forensic Platform",
        },
        "case_information": {
            "id": case.id,
            "name": case.name,
            "description": case.description,
            "reference_number": case.reference_number,
            "status": case.status,
            "created_at_utc": case.created_at.isoformat() if case.created_at else None,
        },
        "evidence_inventory": [
            {
                "id": e.id,
                "name": e.original_name,
                "category": e.category,
                "type": e.evidence_type,
                "size_bytes": e.size_bytes,
                "sha256": e.sha256_original,
                "integrity_status": e.integrity_status,
                "source": e.source,
            }
            for e in evidence
        ],
        "integrity_summary": {
            "total": len(evidence),
            "verified": verified,
            "failed": len(evidence) - verified,
            "methodology": "SHA-256 of original artifact recorded at ingest; analyzed on "
                           "decrypted working copies re-hashed before every analysis run.",
        },
        "analysis_methodology": [
            f"{r.module} module executed on evidence #{r.evidence_id} (status {r.status})."
            for r in runs
        ],
        "timeline": timeline,
        "unusual_sequences": anomalies,
        "findings": [
            {
                "id": f.id,
                "severity": f.severity,
                "title": f.title,
                "description": f.description,
                "module": f.module,
                "is_hypothesis": f.is_hypothesis,
                "confidence": f.confidence,
                "created_at_utc": f.created_at.isoformat() if f.created_at else None,
            }
            for f in findings
        ],
        "findings_sections": {
            "verified_findings": len(verified_findings),
            "hypotheses": len(hypotheses),
            "total": len(findings),
        },
        "limitations": _limitations(),
        "conclusions": _conclusions(findings, anomalies, timeline),
    }


def _limitations() -> list[str]:
    return [
        "Original evidence media was not within scope of this analysis; working copies provided remotely.",
        "Findings marked as hypotheses are AI/rule-generated and require verification by a qualified analyst.",
        "Memory-dump analysis depends on the availability of the Volatility 3 framework.",
        "Timestamp accuracy depends on the source system clock and evidence acquisition process.",
        "Encrypted or unsupported file formats may not be fully parsed.",
    ]


def _conclusions(findings: list[models.Finding], anomalies: list[dict], timeline: list[dict]) -> list[str]:
    lines = []
    if timeline:
        start = timeline[0]["event_time_utc"]
        end = timeline[-1]["event_time_utc"]
        lines.append(f"Analysis reconstructed a timeline spanning {start} to {end} (UTC).")
    critical = [f for f in findings if f.severity in ("critical", "high")]
    if critical:
        lines.append(
            f"{len(critical)} high/critical finding(s) were identified and warrant priority review."
        )
    else:
        lines.append("No high-severity findings were confirmed within the analyzed evidence.")
    if anomalies:
        lines.append(f"{len(anomalies)} unusual sequence(s) were flagged for further investigation.")
    else:
        lines.append("No unusual event sequences were detected.")
    lines.append("All conclusions above are hypotheses; they are not verified forensic findings.")
    return lines


def render_markdown(report: dict[str, Any]) -> str:
    md: list[str] = []
    meta = report["report_metadata"]
    case = report["case_information"]
    md.append(f"# Forensic Investigation Report: {case['name']}\n")
    md.append(f"- **Generated (UTC):** {meta['generated_at_utc']}")
    md.append(f"- **Analyst:** {meta['analyst']}")
    md.append(f"- **Tool:** {meta['tool']}")
    md.append(f"- **Reference:** {case.get('reference_number') or 'N/A'}")
    md.append(f"- **Status:** {case['status']}\n")

    md.append("## 1. Case Information\n")
    md.append(case.get("description") or "_No description._")

    md.append("\n## 2. Evidence Inventory\n")
    md.append("| ID | Name | Category | Type | Size | SHA-256 | Integrity |")
    md.append("|----|------|----------|------|------|---------|-----------|")
    for e in report["evidence_inventory"]:
        md.append(f"| {e['id']} | {e['name']} | {e['category']} | {e['type']} | "
                  f"{e['size_bytes']} | `{e['sha256']}` | {e['integrity_status']} |")

    md.append("\n## 3. Analysis Methodology\n")
    for m in report["analysis_methodology"]:
        md.append(f"- {m}")

    md.append("\n## 4. Timeline of Events\n")
    md.append("| Time (UTC) | Source | Category | Event |")
    md.append("|-----------|--------|----------|-------|")
    for t in report["timeline"][:200]:
        md.append(f"| {t['event_time_utc']} | {t['source_module']} | {t['category'] or '-'} | {t['description'][:120]} |")

    md.append("\n## 5. Findings\n")
    verified = [f for f in report["findings"] if not f["is_hypothesis"]]
    hypotheses = [f for f in report["findings"] if f["is_hypothesis"]]
    md.append("### 5.1 Verified Findings")
    for f in verified or [{}]:
        if not f:
            md.append("_None._")
            break
        md.append(f"- **[{f['severity'].upper()}]** {f['title']} — {f['description']}")
    md.append("\n### 5.2 Hypotheses (requires verification)")
    for f in hypotheses or [{}]:
        if not f:
            md.append("_None._")
            break
        md.append(f"- **[{f['severity'].upper()}]** {f['title']} (confidence {f['confidence']:.2f}) — {f['description']}")

    md.append("\n## 6. Unusual Sequences Flagged\n")
    for a in report["unusual_sequences"] or [{}]:
        if not a:
            md.append("_None._")
            break
        md.append(f"- **[{a['severity'].upper()}]** {a['description']}")

    md.append("\n## 7. Limitations\n")
    for lim in report["limitations"]:
        md.append(f"- {lim}")

    md.append("\n## 8. Analyst Conclusions\n")
    for c in report["conclusions"]:
        md.append(f"- {c}")

    md.append("\n---\n*Report generated by DeepTrace. AI-derived content is hypothesis only.*")
    return "\n".join(md)