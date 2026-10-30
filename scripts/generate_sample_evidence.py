"""Generate sample evidence artifacts for testing DeepTrace without real data.

Creates:
  - sample_evidence/browser_history.sqlite  (Chrome-style History DB)
  - sample_evidence/events.xml              (Windows event log export)
  - sample_evidence/security_events.xml     (Windows Security log with brute-force pattern)
  - sample_evidence/network.log             (firewall/connection log)

Run from the repository root:
    python scripts/generate_sample_evidence.py
"""
from __future__ import annotations

import os
import sqlite3
from datetime import datetime, timedelta, timezone

ROOT = os.path.join(os.path.dirname(__file__), "..", "sample_evidence")
WEBKIT_EPOCH = 11644473600  # seconds between 1601-01-01 and 1970-01-01


def webkit(epoch_seconds: float) -> int:
    return int((epoch_seconds + WEBKIT_EPOCH) * 1_000_000)


def make_browser_history() -> None:
    path = os.path.join(ROOT, "browser_history.sqlite")
    conn = sqlite3.connect(path)
    conn.execute("CREATE TABLE urls (id INTEGER PRIMARY KEY, url TEXT, title TEXT, visit_count INTEGER)")
    conn.execute("CREATE TABLE visits (id INTEGER PRIMARY KEY, url INTEGER, visit_time INTEGER, visit_duration INTEGER)")
    base = datetime(2026, 10, 28, 9, 0, 0, tzinfo=timezone.utc)
    urls = [
        ("https://mail.office365.example/Inbox", "Mail", 12),
        ("https://free-download.xyz/package.zip", "package", 1),
        ("https://docs.example.com/sharepoint", "SharePoint", 8),
        ("https://attacker-panel.tk/beacon", "beacon", 2),
        ("https://defender.example.com/remediate", "Remediation", 3),
    ]
    for i, (u, t, vc) in enumerate(urls, start=1):
        conn.execute("INSERT INTO urls (id, url, title, visit_count) VALUES (?,?,?,?)", (i, u, t, vc))
        for k in range(vc):
            conn.execute("INSERT INTO visits (url, visit_time, visit_duration) VALUES (?,?,?)",
                         (i, webkit((base + timedelta(minutes=k * 13)).timestamp()), 30000))
    conn.commit()
    conn.close()
    print(f"[+] {path}")


def _event(provider, eid, level, record, computer, time_iso, data_pairs):
    data = "".join(f'          <Data Name="{k}">{v}</Data>\n' for k, v in data_pairs)
    return f"""    <Event>
      <System>
        <Provider Name="{provider}"></Provider>
        <EventID>{eid}</EventID>
        <Level>{level}</Level>
        <EventRecordID>{record}</EventRecordID>
        <Computer>{computer}</Computer>
        <TimeCreated SystemTime="{time_iso}"></TimeCreated>
      </System>
      <EventData>
{data}      </EventData>
    </Event>"""


def make_events_xml() -> None:
    path = os.path.join(ROOT, "events.xml")
    base = datetime(2026, 10, 28, 8, 30, 0, tzinfo=timezone.utc)
    records = []
    i = 0
    # A burst of failed logons followed by a success (brute-force signature).
    for k in range(5):
        i += 1
        records.append(_event(
            "Microsoft-Windows-Security-Auditing", 4625, 0, i, "WORKSTATION-01",
            (base + timedelta(seconds=k * 12)).isoformat(),
            [("TargetUserName", "jsmith"), ("LogonType", "3"), ("IpAddress", "172.16.20.10")]))
    i += 1
    records.append(_event(
        "Microsoft-Windows-Security-Auditing", 4624, 0, i, "WORKSTATION-01",
        (base + timedelta(seconds=70)).isoformat(),
        [("TargetUserName", "jsmith"), ("LogonType", "2"), ("IpAddress", "127.0.0.1")]))
    i += 1
    records.append(_event(
        "Microsoft-Windows-PowerShell", 4104, 4, i, "WORKSTATION-01",
        (base + timedelta(minutes=2)).isoformat(),
        [("ScriptBlockText", "powershell -enc IABY... base64 encoded command ...")]))
    i += 1
    records.append(_event(
        "Service Control Manager", 7045, 4, i, "SERVER-DC",
        (base + timedelta(minutes=4)).isoformat(),
        [("ServiceName", "WindowsUpdaterSvc"), ("ImagePath", "C:\\ProgramData\\svchost.exe /k run")]))
    xml = ('<?xml version="1.0" encoding="utf-8"?>\n'
           '<Events xmlns="http://schemas.microsoft.com/win/2004/08/events/event">\n'
           + "\n".join(records) + "\n</Events>\n")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(xml)
    print(f"[+] {path}")

    # The security export is an equivalent copy (kept separate for clarity).
    with open(os.path.join(ROOT, "security_events.xml"), "w", encoding="utf-8") as fh:
        fh.write('<?xml version="1.0" encoding="utf-8"?>\n<Events>\n' + records[0] + "\n</Events>\n")
    print("[+] sample_evidence/security_events.xml")


def make_network_log() -> None:
    path = os.path.join(ROOT, "network.log")
    lines = [
        "# DeepTrace sample firewall/connection log  (ts, src, dst, sport, dport, proto)",
        "2026-10-28T08:30:05Z,172.16.20.10,10.10.5.22,50000,4444,tcp",
        "2026-10-28T08:30:40Z,172.16.20.10,10.10.5.22,50001,4444,tcp",
        "2026-10-28T08:31:20Z,10.10.5.22,192.168.1.50,8080,80,tcp",
        "2026-10-28T08:32:02Z,10.10.5.22,198.51.100.77,50000,5432,tcp",
        "2026-10-28T08:35:10Z,10.10.5.22,10.10.5.13,3389,3389,tcp",
        "2026-10-28T08:36:00Z,10.10.5.13,198.51.100.90,49152,12345,tcp",
    ]
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")
    print(f"[+] {path}")


if __name__ == "__main__":
    os.makedirs(ROOT, exist_ok=True)
    make_browser_history()
    make_events_xml()
    make_network_log()
    print("Sample evidence generated under sample_evidence/")