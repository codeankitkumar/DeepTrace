"""Windows EVTX log analysis.

Parses Windows Event Log (.evtx) binaries when `python-evtx` is available, and also
introspects XML-exported event logs. Extraction is namespace-agnostic (matches element
local names) so it tolerates common export variants. Extracts per-record fields
(EventID, Provider, Level, Computer, TimeCreated) normalized into timeline events and
notable findings. Reads the working copy only.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
from xml.etree import ElementTree as ET

from app.forensics.base import AnalysisResult, ForensicsModule

_LEVEL_MAP = {"0": "Info", "1": "Critical", "2": "Error", "3": "Warning", "4": "Info", "5": "Verbose"}


def _local(tag: str) -> str:
    return tag.rpartition("}")[2]


def _child(elem: ET.Element | None, name: str) -> ET.Element | None:
    if elem is None:
        return None
    for ch in elem:
        if _local(ch.tag) == name:
            return ch
    return None


def _children(elem: ET.Element, name: str) -> list[ET.Element]:
    return [ch for ch in elem.iter() if _local(ch.tag) == name]


def _text(elem: ET.Element | None, tag: str, attr_key: str | None = None) -> str | None:
    node = _child(elem, tag)
    if node is None:
        return None
    if attr_key:
        return node.get(attr_key)
    return (node.text or "").strip() or None


def _attr(elem: ET.Element | None, tag: str, attr: str) -> str | None:
    node = _child(elem, tag)
    return node.get(attr) if node is not None else None


def _parse_evtx_with_library(path: str, result: AnalysisResult) -> None:
    from Evtx.Evtx import Evtx  # type: ignore

    record_count = 0
    with Evtx(path) as log:
        for record in log.records():
            xml = record.xml() if hasattr(record, "xml") else record.to_xml()
            _ingest_xml_record(xml, result)
            record_count += 1
    result.summary["parser"] = "python-evtx"
    result.summary["record_count"] = record_count


def _ingest_xml_record(xml: str, result: AnalysisResult) -> None:
    try:
        root = ET.fromstring(xml)
    except ET.ParseError:
        return
    system = _child(root, "System")
    if system is None:
        return
    event_id = _text(system, "EventID")
    provider = _attr(system, "Provider", "Name")
    record_id = _text(system, "EventRecordID")
    level = _text(system, "Level")
    computer = _text(system, "Computer")
    time_raw = _text(system, "TimeCreated", attr_key="SystemTime")

    data_parts = [
        {"name": d.get("Name"), "value": (d.text or "").strip()}
        for d in _children(root, "Data")
        if (d.text or "").strip()
    ]
    payload = " | ".join(f"{p['name']}={p['value']}" for p in data_parts if p["name"])
    category = "logon" if _is_logon_fields(data_parts) else (
        "process" if _is_process_fields(data_parts) else None)

    props = {
        "EventID": event_id, "Provider": provider, "RecordID": record_id,
        "Level": _LEVEL_MAP.get(level, level), "Computer": computer,
        "Channel": _source_from_provider(provider), "Payload": payload[:500] if payload else None,
    }

    event_time = None
    if time_raw:
        try:
            event_time = datetime.fromisoformat(time_raw.replace("Z", "+00:00")).astimezone(timezone.utc)
        except ValueError:
            event_time = None

    desc = f"[{_LEVEL_MAP.get(level, level)}] {provider} EventID {event_id}"
    if payload:
        desc += f": {payload[:240]}"

    if event_time:
        result.add_event(
            event_time_utc=event_time,
            source_module="evtx",
            category=category,
            description=desc,
            properties=props,
            confidence=0.85,
        )

    severity = _severity_for(int(event_id or 0)) if event_id else None
    if severity:
        result.add_finding(
            title=f"Notable Windows event: {provider} / ID {event_id}",
            description=payload[:800] or desc[:800],
            severity=severity,
            is_hypothesis=True,
            confidence=0.6 if severity in ("medium", "low") else 0.75,
            properties={"record_id": record_id, "computer": computer, "event_id": event_id},
        )


_NOTABLE_EVID = {
    4625: "high", 4616: "medium", 4648: "high", 4675: "medium", 4697: "medium",
    4104: "low", 1102: "high", 7045: "medium", 4688: "low", 4698: "low",
    4720: "medium", 4732: "low", 4740: "high", 4624: "info", 4690: "medium",
}


def _severity_for(event_id: int) -> str | None:
    return _NOTABLE_EVID.get(event_id)


def _is_logon_fields(data_parts: list[dict]) -> bool:
    names = {p.get("name") for p in data_parts}
    return bool({"LogonType", "TargetUserName", "IpAddress", "LogonProcessName"} & names)


def _is_process_fields(data_parts: list[dict]) -> bool:
    names = {p.get("name") for p in data_parts}
    return bool({"NewProcessName", "ProcessId", "CommandLine"} & names)


def _source_from_provider(provider: str | None) -> str | None:
    if not provider:
        return None
    if "Security" in provider:
        return "Security"
    if "Application" in provider:
        return "Application"
    if "System" in provider or "Kernel" in provider:
        return "System"
    return provider


class EvtxModule(ForensicsModule):
    name = "evtx"
    display_name = "Windows EVTX Logs"
    description = "Parses Windows Event Log (.evtx) files into normalized timeline events and findings."
    supported_types = ["evtx", "log", "xml"]

    def analyze(self, working_copy_path: str, context: dict[str, Any] | None = None) -> AnalysisResult:
        result = AnalysisResult(module=self.name)
        result.summary = {"path": working_copy_path, "parser": None, "record_count": 0}

        if working_copy_path.lower().endswith(".xml"):
            try:
                root = ET.parse(working_copy_path).getroot()
                events = [el for el in root.iter() if _local(el.tag) == "Event"]
                if not events and _local(root.tag) == "Event":
                    events = [root]
                for ev in events:
                    _ingest_xml_record(ET.tostring(ev, encoding="unicode"), result)
                result.summary["parser"] = "xml-export"
            except Exception as exc:  # pragma: no cover
                result.errors.append(f"XML parse failed: {exc}")
            return result

        try:
            _parse_evtx_with_library(working_copy_path, result)
        except ImportError:
            result.errors.append(
                "python-evtx is not installed. Install `requirements-forensics.txt` to parse .evtx binaries."
            )
            result.add_finding(
                title="EVTX parser unavailable",
                description="Dependency python-evtx missing; raw log not interpreted.",
                severity="info", is_hypothesis=False,
            )
        except Exception as exc:  # pragma: no cover - defensive
            result.errors.append(f"EVTX parse error: {exc}")

        return result