"""Network log analysis.

Parses common exported network/firewall logs: tab/space/CSV/JSON-lines with timestamp,
source/destination IP, ports, and event fields. Produces timeline events and flags
connections to suspicious or notable destinations. Input is read-only.
"""
from __future__ import annotations

import csv
import ipaddress
import json
import re
from datetime import datetime, timezone
from typing import Any

from app.forensics.base import AnalysisResult, ForensicsModule

_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_TS_MARKERS = ("time", "timestamp", "date", "datetime", "start", "event_time")
_SRC_MARKERS = ("src", "source_ip", "source", "src_ip", "sip")
_DST_MARKERS = ("dst", "dest", "dest_ip", "destination", "dip", "daddr")
_PORT_MARKERS = ("dport", "sport", "port", "dest_port", "src_port")

_PRIVATE = ipaddress.ip_network("10.0.0.0/8"), ipaddress.ip_network("172.16.0.0/12"), ipaddress.ip_network("192.168.0.0/16")


def _parse_time(raw: str) -> datetime | None:
    raw = raw.strip().replace("Z", "+00:00")
    iso = raw.replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(iso).astimezone(timezone.utc)
    except ValueError:
        pass
    for fmt in ("%Y-%m-%d %H:%M:%S", "%m/%d/%Y %H:%M:%S", "%d/%b/%Y:%H:%M:%S", "%b %d %H:%M:%S"):
        try:
            return datetime.strptime(raw.split(" ")[0] + " " + raw.split(" ")[1], fmt) if " " in raw else None
        except (ValueError, IndexError):
            continue
    return None


def _field(row: dict, markers: tuple[str, ...]) -> str | None:
    for k, v in row.items():
        if any(m in k.lower() for m in markers):
            return v
    return None


def _read_rows(path: str) -> list[dict]:
    content = open(path, "r", encoding="utf-8", errors="replace").read()
    rows: list[dict] = []
    if content.lstrip().startswith("["):
        try:
            data = json.loads(content)
            if isinstance(data, list):
                return [d if isinstance(d, dict) else {"line": str(d)} for d in data]
        except json.JSONDecodeError:
            pass
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "\t" in line:
            parts = line.split("\t")
        elif line.startswith("{"):
            try:
                obj = json.loads(line)
                rows.append(obj if isinstance(obj, dict) else {"line": line})
                continue
            except json.JSONDecodeError:
                parts = re.split(r"\s+", line, maxsplit=10)
        elif "," in line:
            parts = line.split(",")
        else:
            parts = re.split(r"\s+", line, maxsplit=10)
        if len(parts) >= 2:
            rows.append({f"f{i}": p for i, p in enumerate(parts)})
    return rows


class NetworkLogModule(ForensicsModule):
    name = "network"
    display_name = "Network Logs"
    description = "Parses exported network/firewall logs into timeline events and suspicious connection findings."
    supported_types = ["network", "csv", "log"]

    def analyze(self, working_copy_path: str, context: dict[str, Any] | None = None) -> AnalysisResult:
        result = AnalysisResult(module=self.name)
        result.summary = {"path": working_copy_path, "connection_count": 0}

        try:
            rows = _read_rows(working_copy_path)
        except OSError as exc:
            result.errors.append(str(exc))
            return result

        count = 0
        suspicious = 0
        for row in rows:
            t_raw = _field(row, _TS_MARKERS)
            evt_time = _parse_time(t_raw) if t_raw else None
            src = _field(row, _SRC_MARKERS)
            dst = _field(row, _DST_MARKERS)
            port = _field(row, _PORT_MARKERS)

            desc_parts = []
            if src:
                desc_parts.append(f"src {src}")
            if dst:
                desc_parts.append(f"dst {dst}")
            if port:
                desc_parts.append(f"port {port}")
            for ip in re.findall(_IP_RE, " ".join([src or "", dst or ""])):
                if ip not in (src or "") and ip not in (dst or ""):
                    desc_parts.append(f"ip {ip}")

            desc = "Network connection: " + ", ".join(desc_parts) if desc_parts else "Network event logged"
            props = {"src": src, "dst": dst, "port": port, "raw": json.dumps(row, default=str)[:400]}
            count += 1

            if dst and _flag_ip(dst, result):
                suspicious += 1

            if evt_time:
                result.add_event(
                    event_time_utc=evt_time,
                    source_module=self.name,
                    category="network",
                    description=desc,
                    properties=props,
                    confidence=0.7,
                )
        result.summary["connection_count"] = count
        result.summary["flagged_count"] = suspicious
        return result


def _flag_ip(ip: str, result: AnalysisResult) -> bool:
    flagged = False
    try:
        obj = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if obj.is_private or obj.is_loopback or obj.is_reserved:
        flagged = True
        result.add_finding(
            title=f"Connection involving {ip}",
            description="Traffic to/from a private, loopback, or reserved address was observed.",
            severity="low", is_hypothesis=True, confidence=0.45,
            properties={"ip": ip, "reason": "private/reserved/loopback"},
        )
    return flagged