# Installation & Setup

This guide covers local development and Docker deployment for DeepTrace.

## Prerequisites

- Python 3.11+ (3.12 recommended)
- Node.js 18+ / npm 9+
- Docker + Docker Compose (for containerized deployment)
- Git

## 1. Docker deployment (recommended)

```bash
# From the repository root
cp .env.example .env

# Edit .env and set at least:
#   SECRET_KEY            -> a long random string
#   EVIDENCE_ENCRYPTION_KEY -> run:  python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
#   SEED_ADMIN_PASSWORD   -> a strong initial admin password

docker compose up --build
```

- Backend API + docs: http://localhost:8000/docs
- Frontend SPA: http://localhost:5173

First-boot default admin (from `.env`): `admin` / `ChangeMe!2026`.
**Change it immediately after first login.**

## 2. Local development (backend)

```bash
cd backend
python -m venv .venv
# Windows:
.venv\Scripts\activate
# macOS/Linux:
# source .venv/bin/activate

pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```

Optional forensic parsers (EVTX binaries, Volatility 3, YARA):

```bash
pip install -r requirements-forensics.txt
```

## 3. Local development (frontend)

```bash
cd frontend
npm install
npm run dev          # http://localhost:5173
```

The Vite dev server proxies `/api` to `http://localhost:8000`.

## 4. Generate sample evidence

```bash
python scripts/generate_sample_evidence.py
```

Creates files under `sample_evidence/` that you can upload through the UI to exercise
the browser-history, EVTX (XML), and network-log modules.

## 5. Configuration

All configuration is read from environment variables (see `.env.example`):

| Variable | Purpose |
|---|---|
| `DATABASE_URL` | SQLAlchemy connection string (default `sqlite:///./deeptrace.db`) |
| `SECRET_KEY` | Secret used to sign JWTs |
| `EVIDENCE_ENCRYPTION_KEY` | Fernet key for evidence-at-rest encryption |
| `STORAGE_ROOT` | Where encrypted evidence working copies are stored |
| `MAX_UPLOAD_SIZE_MB` | Maximum upload size |
| `BACKEND_CORS_ORIGINS` | Comma-separated allowed CORS origins |
| `SEED_ADMIN_USERNAME/EMAIL/PASSWORD` | Initial admin (created only when DB is empty) |

## 6. Running tests

```bash
cd backend
pytest -q
```

## 7. Next steps after logging in

1. Create an **Investigation** (Cases).
2. Open the case and **upload evidence** (e.g., the generated samples).
3. **Verify** integrity (SHA-256) — the platform re-checks on every access.
4. **Run analysis modules** (filesystem, evtx, browser, network, suspicious…).
5. Explore the **Timeline** and flagged **unusual sequences**.
6. Ask the **AI Assistant** to summarize / explain / relate / suggest / report.
7. Generate a **Forensic Report** (JSON or Markdown).

AI outputs are always marked as **hypotheses**; they are not verified forensic findings.