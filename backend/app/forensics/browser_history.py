"""Browser history analysis from exported databases.

Reads Chrome/Chromium `History` and Firefox `places.sqlite` SQLite databases read-only.
Uses the standard library `sqlite3` to avoid hard dependencies. Converts browser-native
timestamps to UTC timeline events. The input database is opened read-only and never
modified.
"""
from __future__ import annotations

import re
import sqlite3
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

from app.forensics.base import AnalysisResult, ForensicsModule

# WebKit/Chrome visits: microseconds since 1601-01-01T00:00:00Z.
_WEBKIT_EPOCH_OFFSET_S = 11644473600.0


def _webkit_to_dt(usec: float) -> datetime:
    epoch = (usec / 1_000_000.0) - _WEBKIT_EPOCH_OFFSET_S
    return datetime.fromtimestamp(epoch, tz=timezone.utc)


_SUSPECT_TLD_PATTERNS = (
    r"\.(tk|ml|ga|cf|gq|xyz|top|icu|download|stream|men|loan|work|click|link|zip)$",
    r"-com\.", r"[0-9]{2,}\.com$",
)


def _open_ro(path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    return conn


def _tables(conn: sqlite3.Connection) -> set[str]:
    rows = conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
    return {r[0] for r in rows}


def _is_suspicious_url(url: str) -> bool:
    try:
        host = (urlparse(url).hostname or "").lower()
    except ValueError:
        return False
    return any(re.search(p, host) for p in _SUSPECT_TLD_PATTERNS)


class BrowserHistoryModule(ForensicsModule):
    name = "browser"
    display_name = "Browser History"
    description = "Extracts URL visits from exported Chrome History / Firefox places.sqlite databases."
    supported_types = ["browser", "sqlite", "db"]

    def analyze(self, working_copy_path: str, context: dict[str, Any] | None = None) -> AnalysisResult:
        result = AnalysisResult(module=self.name)
        result.summary = {"path": working_copy_path, "browser": None, "visit_count": 0}

        try:
            conn = _open_ro(working_copy_path)
        except sqlite3.Error as exc:
            result.errors.append(f"Could not open SQLite database: {exc}")
            result.add_finding(
                title="Browser history database unreadable",
                description=f"Not a valid SQLite browser-history export: {exc}",
                severity="info", is_hypothesis=False,
            )
            return result

        with conn:
            tables = _tables(conn)
            if "urls" in tables and "visits" in tables:
                self._analyze_chrome(conn, result)
            elif "moz_places" in tables and "moz_historyvisits" in tables:
                self._analyze_firefox(conn, result)
            else:
                result.errors.append("SQLite file does not match known browser history schema.")
                result.add_finding(
                    title="Unrecognized schema",
                    description="Database is valid SQLite but not a Chrome or Firefox history export.",
                    severity="info", is_hypothesis=False,
                )
        conn.close()
        return result

    def _analyze_chrome(self, conn: sqlite3.Connection, result: AnalysisResult) -> None:
        result.summary["browser"] = "chrome"
        rows = conn.execute(
            """
            SELECT u.url AS url, u.title AS title, v.visit_time AS visit_time
            FROM visits v JOIN urls u ON u.id = v.url
            ORDER BY v.visit_time
            """
        ).fetchall()
        result.summary["visit_count"] = len(rows)
        for r in rows:
            dt = _webkit_to_dt(r["visit_time"])
            host = urlparse(r["url"]).hostname or "(unknown)"
            result.add_event(
                event_time_utc=dt,
                source_module=self.name,
                category="browsing",
                description=f"Visited {r['url'][:300]}",
                properties={"url": r["url"], "title": r["title"], "host": host},
                confidence=0.85,
            )
            if _is_suspicious_url(r["url"]):
                result.add_finding(
                    title="Suspicious URL visited",
                    description=f"Browser visited a suspicious domain: {r['url'][:300]}",
                    severity="medium", is_hypothesis=True, confidence=0.55,
                    properties={"url": r["url"], "host": host},
                )

    def _analyze_firefox(self, conn: sqlite3.Connection, result: AnalysisResult) -> None:
        result.summary["browser"] = "firefox"
        rows = conn.execute(
            """
            SELECT p.url AS url, p.title AS title, h.visit_date AS visit_time
            FROM moz_historyvisits h JOIN moz_places p ON h.place_id = p.id
            ORDER BY h.visit_date
            """
        ).fetchall()
        result.summary["visit_count"] = len(rows)
        for r in rows:
            dt = datetime.fromtimestamp(r["visit_time"] / 1_000_000.0, tz=timezone.utc)
            host = urlparse(r["url"]).hostname or "(unknown)"
            result.add_event(
                event_time_utc=dt,
                source_module=self.name,
                category="browsing",
                description=f"Visited {r['url'][:300]}",
                properties={"url": r["url"], "title": r["title"], "host": host},
                confidence=0.85,
            )
            if _is_suspicious_url(r["url"]):
                result.add_finding(
                    title="Suspicious URL visited",
                    description=f"Browser visited a suspicious domain: {r['url'][:300]}",
                    severity="medium", is_hypothesis=True, confidence=0.55,
                    properties={"url": r["url"], "host": host},
                )