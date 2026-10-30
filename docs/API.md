# DeepTrace API Reference

All endpoints are under `/api`. Auth endpoints return a bearer token; all other
endpoints require `Authorization: Bearer <token>`.

## Health

`GET /api/health` — service liveness.

## Auth

| Method | Path | Auth | Description |
|---|---|---|---|
| POST | `/api/auth/login` | – | `{username,password}` → `{access_token,refresh_token,user}` |
| POST | `/api/auth/refresh` | – | `{refresh_token}` → new token pair |
| GET | `/api/auth/me` | Any | Current user profile |

Roles: `admin`, `analyst`, `viewer`. Password hashing: PBKDF2-HMAC-SHA256 (240k iters).

## Users (admin only)

| Method | Path | Description |
|---|---|---|
| GET | `/api/users` | List users |
| POST | `/api/users` | Create user `{username,email,password,role}` |

## Cases

| Method | Path | Auth | Description |
|---|---|---|---|
| GET | `/api/cases` | Any | List investigations |
| POST | `/api/cases` | analyst+ | Create case |
| GET | `/api/cases/{id}` | Any | Case detail |
| PATCH | `/api/cases/{id}` | analyst+ | Update case |

## Evidence

| Method | Path | Auth | Description |
|---|---|---|---|
| GET | `/api/evidence?case_id=` | Any | List evidence for a case |
| POST | `/api/evidence` | analyst+ | Upload (multipart: `file`, `case_id`, `category`, `evidence_type`, `description`) |
| GET | `/api/evidence/{id}` | Any | Evidence detail (hashes, integrity) |
| POST | `/api/evidence/{id}/verify` | analyst+ | Re-verify SHA-256 integrity |
| GET | `/api/evidence/{id}/custody` | Any | Chain-of-custody records |
| POST | `/api/evidence/{id}/run/{module}` | analyst+ | Run a forensic module |
| GET | `/api/evidence/{id}/findings` | Any | Findings for evidence |

Allowed upload extensions are enforced server-side; files are encrypted at rest.

## Modules

| Method | Path | Description |
|---|---|---|
| GET | `/api/modules` | List analysis modules |

Module names: `filesystem`, `evtx`, `browser`, `memory`, `network`, `suspicious`.

## Timeline

| Method | Path | Description |
|---|---|---|
| GET | `/api/timeline/{case_id}/events` | Chronological events (UTC) |
| GET | `/api/timeline/{case_id}/anomalies` | Flagged unusual sequences (hypotheses) |
| GET | `/api/timeline/{case_id}/summary` | Correlation summary |

## Dashboard

| Method | Path | Description |
|---|---|---|
| GET | `/api/dashboard/overview` | Stats across all investigations |
| GET | `/api/dashboard/activity` | Recent audit activity |
| GET | `/api/dashboard/timeline-bucket` | Event volume over time |

## AI Assistant

| Method | Path | Auth | Description |
|---|---|---|---|
| POST | `/api/assistant/{case_id}/ask` | analyst+ | Ask `{query}`; responses declare `is_hypothesis` |
| GET | `/api/assistant/{case_id}/history` | Any | Conversation history |

Intents: summarize · explain · relate · suggest · report.

## Reports

| Method | Path | Auth | Description |
|---|---|---|---|
| GET | `/api/reports/{case_id}/generate` | analyst+ | Structured report (JSON) |
| GET | `/api/reports/{case_id}/markdown` | analyst+ | Report rendered as Markdown |

## Error handling

Errors are JSON `{"detail": "<message>"}` with standard HTTP status codes (400, 401,
403, 404, 409, 500).