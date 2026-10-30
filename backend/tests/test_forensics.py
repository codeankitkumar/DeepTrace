import os
import sqlite3
from datetime import datetime, timezone

from app.forensics.browser_history import BrowserHistoryModule
from app.forensics.evtx import EvtxModule
from app.forensics.suspicious_files import SuspiciousFilesModule
from app.forensics.filesystem import FileSystemModule

WEEK = 7 * 24 * 3600
WEBKIT_EPOCH = 11644473600  # seconds between 1601-01-01 and 1970-01-01


def _webkit(epoch_seconds: float) -> int:
    return int((epoch_seconds + WEBKIT_EPOCH) * 1_000_000)


def test_browser_history_chrome(tmp_path):
    db = tmp_path / "History"
    conn = sqlite3.connect(db)
    conn.execute("CREATE TABLE urls (id INTEGER PRIMARY KEY, url TEXT, title TEXT)")
    conn.execute("CREATE TABLE visits (id INTEGER PRIMARY KEY, url INTEGER, visit_time INTEGER)")
    base = datetime(2024, 1, 10, 12, 0, 0, tzinfo=timezone.utc).timestamp()
    conn.execute("INSERT INTO urls (id, url, title) VALUES (1, ?, ?)",
                 ("https://example.com/page", "Example"))
    conn.execute("INSERT INTO urls (id, url, title) VALUES (2, ?, ?)",
                 ("https://freedownload.tk/load", "Suspect"))
    conn.execute("INSERT INTO visits (url, visit_time) VALUES (1, ?)", (_webkit(base),))
    conn.execute("INSERT INTO visits (url, visit_time) VALUES (2, ?)", (_webkit(base + 60),))
    conn.commit()
    conn.close()

    result = BrowserHistoryModule().analyze(str(db))
    assert result.summary["browser"] == "chrome"
    assert result.summary["visit_count"] == 2
    assert any(e["event_time_utc"].tzinfo is not None for e in result.events)
    assert any("Visited" in e["description"] for e in result.events)
    assert any(f["severity"] == "medium" for f in result.findings)  # suspicious URL flagged


def test_evtx_xml(tmp_path):
    xml = tmp_path / "log.xml"
    xml.write_text("""<?xml version="1.0"?>
    <Events>
      <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
        <System>
          <Provider Name="Microsoft-Windows-Security-Auditing"/>
          <EventID>4625</EventID>
          <Level>0</Level>
          <EventRecordID>10</EventRecordID>
          <Computer>HOST01</Computer>
          <TimeCreated SystemTime="2024-02-01T03:00:00.000Z"/>
        </System>
        <EventData>
          <Data Name="TargetUserName">admin</Data>
          <Data Name="LogonType">3</Data>
        </EventData>
      </Event>
    </Events>""")
    result = EvtxModule().analyze(str(xml))
    assert result.summary["parser"] == "xml-export"
    assert any(e["category"] == "logon" for e in result.events)
    assert any(f["severity"] == "high" for f in result.findings)


def test_suspicious_file_flags_pe(tmp_path):
    p = tmp_path / "agent.exe"
    p.write_bytes(b"MZ" + b"\x00" * 16 + b"Invoke-Mimikatz" + b"\x00" * 200)
    result = SuspiciousFilesModule().analyze(str(p))
    assert result.summary["files_scanned"] >= 1
    assert any("Invoke-Mimikatz" in f["description"] or f["severity"] == "high"
               for f in result.findings)


def test_filesystem_summary(tmp_path):
    p = tmp_path / "artifact.txt"
    p.write_bytes(b"some content")
    result = FileSystemModule().analyze(str(p))
    assert result.summary["is_directory"] is False
    assert result.summary["size_bytes"] == len(b"some content")
    assert result.events  # MAC events emitted