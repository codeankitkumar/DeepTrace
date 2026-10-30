"""Suspicious file identification.

Applies heuristic scoring against a file's bytes: recognized executable/script
signatures, high Shannon entropy (packing/encryption), extension mismatches, and
known indicator-of-compromise strings. Produces hypothesis-level findings only.
"""
from __future__ import annotations

import math
import os
from collections import Counter
from typing import Any

from app.forensics.base import AnalysisResult, ForensicsModule

_SAMPLE_LIMIT = 256 * 1024  # analyze first 256 KB per file
_IOC_STRINGS = (
    "Invoke-Mimikatz", "mimikatz", "meterpreter", "cobaltstrike", "beacon",
    "CreateRemoteThread", "VirtualAllocEx", "WriteProcessMemory", "schtasks /create",
    "runonce", "reg add", "powershell -enc", "wscript.shell", "cmd.exe /c",
    "net user", "netsh firewall", "psexec", "91.1", "xor", "yara",
     "http://", "https://", "cmd /c curl", "taskkill",
)
_HIGH_ENTROPY_THRESHOLD = 6.5


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    c = Counter(data)
    length = len(data)
    return -sum((count / length) * math.log2(count / length) for count in c.values())


def _signature(data: bytes) -> str | None:
    if data[:2] == b"MZ":
        return "PE executable (DOS header)"
    if data[:4] == b"\x7fELF":
        return "ELF executable"
    if data[:2] == b"#!":
        return "Script (shebang)"
    for sig, name in ((b"\x89PNG", "PNG image"), (b"%PDF", "PDF"), (b"PK\x03\x04", "ZIP/Office"),
                      (b"\xff\xd8\xff", "JPEG"), (b"RIFF", "RIFF/app"), (b"GIF8", "GIF")):
        if data.startswith(sig):
            return name
    return None


_SUSPICIOUS_EXTS = {".exe", ".scr", ".dll", ".bat", ".cmd", ".vbs", ".ps1", ".js", ".hta", ".wsf", ".jar", ".bin", ".iso", ".img", ".dmp"}


class SuspiciousFilesModule(ForensicsModule):
    name = "suspicious"
    display_name = "Suspicious File Identification"
    description = "Scores files for characteristics commonly associated with malicious artifacts."
    supported_types = ["*"]

    def analyze(self, working_copy_path: str, context: dict[str, Any] | None = None) -> AnalysisResult:
        result = AnalysisResult(module=self.name)
        context = context or {}
        path = working_copy_path
        result.summary = {"path": path, "files_scanned": 0, "flags": 0}

        if os.path.isdir(path):
            targets = []
            for root, _dirs, files in os.walk(path):
                for name in files:
                    targets.append(os.path.join(root, name))
        else:
            targets = [path]

        for fp in targets:
            result.summary["files_scanned"] += 1
            try:
                with open(fp, "rb") as fh:
                    data = fh.read(_SAMPLE_LIMIT)
            except OSError:
                continue
            self._score_file(fp, data, result)
        return result

    def _score_file(self, fp: str, data: bytes, result: AnalysisResult) -> None:
        ext = os.path.splitext(fp)[1].lower()
        size = os.path.getsize(fp)
        sig = _signature(data)
        ent = _entropy(data)
        ioc_matches = [s for s in _IOC_STRINGS if s.encode("utf-8", "ignore").lower() in data.lower()]

        reasons: list[str] = []
        score = 0

        if sig:
            if any(k in sig.lower() for k in ("executable", "elf")):
                score += 2
                reasons.append(f"executable signature ({sig}) in non-source file")
        if ext in _SUSPICIOUS_EXTS:
            score += 1
            reasons.append("suspicious extension")
        if ent > _HIGH_ENTROPY_THRESHOLD:
            # Packed payloads/encrypted blobs are high-entropy.
            if size > 1024:
                score += 2
                reasons.append(f"high entropy ({ent:.2f}) in sampled bytes")
        if ioc_matches:
            score += len(ioc_matches)
            reasons.append("known indicator strings present")
        if size == 0:
            score += 1
            reasons.append("zero-length file")

        if score >= 3:
            sev = "high" if score >= 4 else "medium"
            result.add_finding(
                title=f"Suspicious file: {os.path.basename(fp)}",
                description="; ".join(reasons)
                + (f" | detected signature: {sig}" if sig else "")
                + (f" | IOCs: {', '.join(ioc_matches[:5])}" if ioc_matches else ""),
                severity=sev,
                is_hypothesis=True,
                confidence=min(0.35 + 0.12 * score, 0.85),
                properties={"path": fp, "signature": sig, "entropy": round(ent, 2),
                            "size_bytes": size, "extension": ext, "iocs": ioc_matches[:8]},
            )
            result.summary["flags"] += 1