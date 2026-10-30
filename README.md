# DeepTrace — AI-Powered Digital Forensics Investigation Platform

DeepTrace is a professional, security-first digital forensics platform that helps authorized
investigators analyze digital evidence, correlate system events, reconstruct timelines, and
generate structured forensic reports. It is designed around evidence integrity and reproducible
analysis: original evidence is never modified — all analysis runs on verified, SHA-256-hashed
working copies under a complete chain of custody.

> **Legal / Ethical notice:** DeepTrace is intended for use only by authorized investigators on
> evidence they are legally permitted to analyze. AI-generated conclusions in this platform are
> **hypotheses only**, not verified forensic findings.

---

## Objectives

- **Evidence integrity first** — identify, hash (SHA-256), and verify every piece of evidence; never
  modify the original artifact.
- **Modular forensics** — independent analysis modules for file system metadata, Windows EVTX logs,
  browser history exports, memory dumps (Volatility 3), network logs, and suspicious-file
  identification.
- **Timeline reconstruction** — extract, normalize (UTC), correlate, and visualize events across
  evidence sources.
- **AI investigation assistant** — summarize evidence, explain suspicious activity, relate events,
  and suggest next steps, while clearly flagging outputs as hypotheses.
- **Professional reporting** — structure case information, evidence inventory, hashes, methodology,
  timeline, findings, limitations, and analyst conclusions.
- **Security & auditability** — role-based access control, encrypted evidence storage, audit
  logging, and reproducible analysis.

---

## Feature Map

| Requirement | Implementation |
|---|---|
| Evidence upload / categorization / identification | `EvidenceService`, evidence API |
| SHA-256 hashing & integrity verification | `HashingService` |
| File metadata extraction | `forensics/filesystem.py` |
| Chain of custody records | `ChainOfCustodyService` |
| File system metadata analysis | `forensics/filesystem.py` |
| Windows EVTX log analysis | `forensics/evtx.py` |
| Browser history analysis | `forensics/browser_history.py` |
| Memory dump analysis (Volatility 3) | `forensics/memory.py` |
| Network log analysis | `forensics/network_logs.py` |
| Suspicious file identification | `forensics/suspicious_files.py` |
| Timeline reconstruction | `services/timeline_engine.py` |
| AI investigation assistant | `ai/assistant.py` |
| Dashboard | frontend + `dashboard` API |
| Reporting | `services/report_service.py` |
| Role-based auth / encryption / audit | `core/security.py`, `core/crypto.py`, `core/audit.py` |
| Docker + tests + docs | `docker-compose.yml`, `backend/tests`, `docs` |

---

See [docs/INSTALLATION.md](docs/INSTALLATION.md), [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) and
[docs/API.md](docs/API.md) for setup, architecture and the full API reference.

---

## Security Model

- **Roles:** `admin`, `analyst`, `viewer`.
- **Evidence storage:** encrypted at rest with Fernet; keys injected via environment / secrets.
- **Audit logging:** every authentication and evidence operation is recorded in an audit trail.
- **Integrity:** SHA-256 hashes recorded at ingest and re-verified on every access; analysis always
  runs on verified working copies.
- **Secure uploads:** validated file names, extension allow-list, size limits, and encrypted
  persistence. Original files are never modified.

> **AI caveat:** All AI-generated content is labeled as hypothesis and explicitly excluded from
> verified findings in generated reports.

---

## Roadmap

- **v0.1 (this release)** — Core platform: evidence management, hashing, custody, filesystem, EVTX,
  browser-history, network-log and suspicious-file modules, timeline engine, AI assistant
  (rule-based/hybrid), dashboard, reporting, RBAC, audit, Docker, and tests.
- **v0.2** — Full Volatility 3 plugin integration, YARA scanning, scalable search/correlation,
  PostgreSQL migration defaults.
- **v0.3** — Pluggable LLM adapters for the assistant, clustered analysis workers, case
  collaboration and exports (PDF/JDG-X).

---

## License

Licensed under the Apache License 2.0. See [LICENSE](LICENSE).