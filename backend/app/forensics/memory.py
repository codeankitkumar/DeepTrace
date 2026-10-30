"""Memory dump analysis using Volatility 3.

Shells out to the Volatility 3 CLI against the working copy (read-only) when the binary
is installed; otherwise records a clear, actionable error. Produces process-scan
timeline events and suspicious-process findings from `windows.psscan`-style output.
"""
from __future__ import annotations

import shutil
import subprocess
from datetime import datetime, timezone
from typing import Any

from app.core.config import settings
from app.forensics.base import AnalysisResult, ForensicsModule

_VOL_COMMAND = "vol3"  # actual binary name for volatility3 is `vol` in some distros; vol3 alias optional


def _find_volatility() -> str | None:
    if settings.volatility_path:
        return settings.volatility_path
    for candidate in ("vol", "vol3", "volatility3"):
        found = shutil.which(candidate)
        if found:
            return found
    return None


_SUSPICIOUS_PROCESS_NAMES = {
    "mimikatz", "powershell", "cmd", "wscript", "cscript", "rundll32", "regsvr32",
    "taskkill", "psexec", "schtasks", "nc.exe", "netcat", "meterpreter", "cobalt",
}


class MemoryModule(ForensicsModule):
    name = "memory"
    display_name = "Memory Dump (Volatility 3)"
    description = "Analyzes memory dumps via the Volatility 3 framework (windows.psscan)."
    supported_types = ["memory", "raw", "bin", "img"]

    def analyze(self, working_copy_path: str, context: dict[str, Any] | None = None) -> AnalysisResult:
        context = context or {}
        result = AnalysisResult(module=self.name)
        result.summary = {"path": working_copy_path, "volatility_available": False}

        vol = _find_volatility()
        if not vol:
            result.errors.append(
                "Volatility 3 not found. Set VOLATILITY_PATH or install the 'volatility3' package."
            )
            result.add_finding(
                title="Volatility 3 unavailable",
                description="Memory analysis requires the volatility3 CLI image. No memory parsing performed.",
                severity="info", is_hypothesis=False,
            )
            return result

        plugin = context.get("plugin", "windows.psscan")
        try:
            proc = subprocess.run(
                [vol, "-q", "-f", working_copy_path, plugin],
                capture_output=True, text=True, timeout=context.get("timeout", 180),
            )
        except FileNotFoundError:
            result.errors.append(f"Volatility binary '{vol}' could not be executed.")
            return result
        except subprocess.TimeoutExpired:
            result.errors.append("Volatility analysis timed out.")
            result.add_finding(
                title="Analysis timeout",
                description="Volatility 3 did not finish within the configured timeout.",
                severity="info", is_hypothesis=False,
            )
            return result

        result.summary["plugin"] = plugin
        result.summary["exit_code"] = proc.returncode
        if proc.returncode != 0:
            result.errors.append(proc.stderr[-1500:] or "Volatility returned a non-zero exit code.")
            result.add_finding(
                title="Volatility run failed",
                description=(proc.stderr or proc.stdout)[-800:],
                severity="info", is_hypothesis=False,
            )
            return result

        process_count = 0
        for line in proc.stdout.splitlines():
            if not line.strip() or line.lstrip().startswith(("Offset", "PID", "{")):
                continue
            parts = line.split()
            if len(parts) >= 5 and parts[1].isdigit():
                process_count += 1
                pid, name = parts[1], parts[-1].strip()
                result.add_event(
                    event_time_utc=datetime.now(timezone.utc),  # dump-time unknown; flagged separately
                    source_module=self.name,
                    category="process",
                    description=f"Process observed in memory: {name} (PID {pid})",
                    properties={"pid": pid, "name": name, "row": " ".join(parts[:8])},
                    confidence=0.5,
                )
                if any(badge in name.lower() for badge in _SUSPICIOUS_PROCESS_NAMES):
                    result.add_finding(
                        title=f"Notable process in memory: {name} (PID {pid})",
                        description="Process name matches common attack tooling or dual-use utility list.",
                        severity="medium", is_hypothesis=True, confidence=0.5,
                        properties={"pid": pid, "name": name},
                    )
        result.summary["process_count"] = process_count
        result.summary["volatility_available"] = True
        return result