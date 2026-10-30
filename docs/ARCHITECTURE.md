# DeepTrace Architecture

DeepTrace is a modular, security-first digital forensics platform with a decoupled
FastAPI backend and a React single-page frontend.

## High-level architecture

```
┌─────────────────────────┐        HTTPS        ┌──────────────────────────────┐
│  React SPA (Vite)       │  ─────────────────▶ │  FastAPI (REST /api/*)       │
│  /login /cases /timeline│                     │  JWT auth · RBAC · audit log │
└─────────────────────────┘                     └──────────────┬───────────────┘
                                                               │ SQLAlchemy
                          ┌────────────────────────────────────┼──────────────┐
                          ▼                                    ▼              ▼
                  ┌───────────────┐                   ┌────────────────┐  ┌────────────┐
                  │ Forensic      │                   │ Evidence store │  │ SQLite /    │
                  │ modules       │                   │ (encrypted at  │  │ Postgres    │
                  │ filesystem·evtx│                   │ rest, Fernet)  │  │ (metadata)  │
                  │ browser·memory│                   └────────────────┘  └────────────┘
                  │ network·susp  │
                  └───────────────┘
```

## Backend layers

- **`app/core`** — configuration, JWT security (PBKDF2 password hashing, role-based
  access), Fernet crypto, and an append-only hash-chained audit trail.
- **`app/db`** — SQLAlchemy models (`User`, `Case`, `Evidence`, `CustodyRecord`,
  `AnalysisRun`, `Finding`, `TimelineEvent`, `Report`, `AssistantMessage`, `AuditLog`).
- **`app/schemas`** — Pydantic request/response contracts.
- **`app/services`** — business logic: evidence ingestion/verification/working-copy
  management, SHA-256 hashing, chain-of-custody (hash-linked), timeline engine
  (normalization, correlation, anomaly detection), and report generation.
- **`app/forensics`** — six independent analysis modules built on a common
  `AnalysisResult` contract. See [Forensics modules](#forensics-modules).
- **`app/ai`** — rule-informed investigation assistant with declared hypothesis outputs.
- **`app/api/routes`** — REST endpoints grouped by resource.

### Rest / API routing

All endpoints are mounted under `/api`. Authentication uses bearer JWTs; endpoints
declare required roles (`admin`, `analyst`, `viewer`). Evidence upload/verify/analysis
require `admin` or `analyst`; read-only views allow `viewer`.

## Evidence integrity model

1. **Ingest** — uploaded bytes are SHA-256 hashed and encrypted (Fernet) to a working
   store. The original is never stored unencrypted and never modified.
2. **Verify** — every access decrypts a temporary working copy and re-hashes it. A
   mismatch or tamper marks integrity as **failed**.
3. **Analyze** — modules read only a decrypted, hash-verified temporary working copy
   that is deleted after the run.
4. **Custody** — every capture/transfer/analyze event is appended to a hash-linked chain
   (each record checksum-hashes the prior record).

## Timeline engine

- Timestamps from each module are normalized to UTC and stored as `TimelineEvent`s.
- `build_timeline` returns a chronological stream.
- `detect_unusual_sequences` flags brute-force logon patterns (4625→4624), activity
  spikes, and high-volume sources — all marked as hypotheses.
- `correlation_summary` aggregates by source/category and computes the span.

## Forensics modules

| Module | Type | Function |
|---|---|---|
| `filesystem` | FileSystemModule | MACB timestamps, size, extension, directory walk |
| `evtx` | EvtxModule | Windows event logs (.evtx via python-evtx; XML export natively) |
| `browser` | BrowserHistoryModule | Chrome `History` / Firefox `places.sqlite` (read-only) |
| `memory` | MemoryModule | Volatility 3 `windows.psscan` wrapper |
| `network` | NetworkLogModule | firewall/connection log parsing, private-IP flagging |
| `suspicious` | SuspiciousFilesModule | signature, entropy, IOC heuristic scoring |

Modules are registered in `app/forensics/registry.py` and exposed via `/api/modules`.

## AI Assistant

`app/ai/assistant.py` detects intent (summarize / explain / relate / suggest / report)
and answers from case data. **All** assistant responses are labeled `is_hypothesis:
true` and excluded from verified findings in reports.

## Frontend

React 18 + Vite + React Router + Recharts + Axios. Auth context stores JWT;
`api/client.js` centralizes calls and auto-attaches the bearer token and handles 401s.
Pages: Login, Dashboard, Cases, Case Detail, Timeline, Assistant, Reports.

## Deployment

`docker-compose.yml` runs the backend (gunicorn-ready uvicorn) and a containerized
frontend served by nginx which proxies `/api` to the backend service. SQLite data and
encrypted evidence persist in the `deeptrace_data` volume.