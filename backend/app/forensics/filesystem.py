"""File system metadata analysis.

Extracts MACB timestamps, size, extension, ownership and other metadata from a file
or directory working copy to seed the timeline and identify file-system artifacts.
Never mutates the source.
"""
from __future__ import annotations

import math
import os
import stat
from datetime import datetime, timezone
from typing import Any

from app.forensics.base import AnalysisResult, ForensicsModule


def _dt(ts: float | None) -> datetime | None:
    if not ts:
        return None
    return datetime.fromtimestamp(ts, tz=timezone.utc)


class FileSystemModule(ForensicsModule):
    name = "filesystem"
    display_name = "File System Metadata"
    description = "Extracts MACB timestamps, size, and metadata attributes from a file or directory."
    supported_types = ["*"]

    def analyze(self, working_copy_path: str, context: dict[str, Any] | None = None) -> AnalysisResult:
        context = context or {}
        result = AnalysisResult(module=self.name)
        path = working_copy_path

        if not os.path.exists(path):
            result.errors.append(f"Path not found: {path}")
            result.summary = {"path": path, "exists": False}
            return result

        st = os.stat(path, follow_symlinks=False)
        is_dir = stat.S_ISDIR(st.st_mode)
        size = 0
        file_count = 0
        dir_count = 0
        btime = getattr(st, "st_birthtime", None)

        mac = {
            "created_utc": _dt(btime),
            "modified_utc": _dt(st.st_mtime),
            "accessed_utc": _dt(st.st_atime),
            "changed_utc": _dt(st.st_ctime),
        }

        events_description = {
            "created_utc": f"File creation time (birth) for '{os.path.basename(path)}'",
            "modified_utc": f"Last modification of '{os.path.basename(path)}'",
            "accessed_utc": f"Last access of '{os.path.basename(path)}'",
            "changed_utc": f"Metadata change (ctime) of '{os.path.basename(path)}'",
        }

        if is_dir:
            for root, dirs, files in os.walk(path):
                dir_count += len(dirs)
                for name in files:
                    fp = os.path.join(root, name)
                    try:
                        fst = os.stat(fp, follow_symlinks=False)
                        size += fst.st_size
                        file_count += 1
                    except OSError:
                        continue
            size_bytes = size
        else:
            size_bytes = st.st_size
            file_count = 1

        ext = os.path.splitext(path)[1].lower()

        summary = {
            "path": path,
            "is_directory": is_dir,
            "size_bytes": size_bytes,
            "size_human": _human(size_bytes),
            "file_count": file_count,
            "directory_count": dir_count,
            "extension": ext or None,
            "mac_timestamps": {k: (v.isoformat() if v else None) for k, v in mac.items()},
        }
        result.summary = summary

        # Seed timeline from timestamps
        for key, ts in mac.items():
            if ts:
                result.add_event(
                    event_time_utc=ts,
                    source_module=self.name,
                    category="filesystem",
                    description=events_description[key],
                    properties={"mac_type": key, "path": path},
                    confidence=0.7,
                )

        # Highlight unusual: zero-byte files, unusual extensions
        if not is_dir and size_bytes == 0:
            result.add_finding(
                title="Empty file artifact",
                description=f"'{os.path.basename(path)}' is 0 bytes; may be a placeholder.",
                severity="low",
            )
        if not is_dir and _hollywood_ext(ext):
            result.add_finding(
                title="Potentially suspicious extension",
                description=f"File has an extension ({ext}) commonly used for executables or archives.",
                severity="medium",
                is_hypothesis=True,
                confidence=0.4,
            )

        return result


_COMMON_SUSPECT_EXT = {".exe", ".dll", ".scr", ".vbs", ".bat", ".cmd", ".ps1", ".js", ".hta", ".jar", ".msi", ".iso", ".vhd"}


def _hollywood_ext(ext: str) -> bool:
    return ext in _COMMON_SUSPECT_EXT


def _human(n: int) -> str:
    if n < 1024:
        return f"{n} B"
    size_name = ["B", "KB", "MB", "GB", "TB"]
    i = int(math.floor(math.log(n, 1024))) if n else 0
    p = math.pow(1024, i)
    s = round(n / p, 2)
    return f"{s} {size_name[i]}"