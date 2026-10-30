# Deployment

## Option A — Docker Compose (recommended)

From the repository root:

```bash
cp .env.example .env
# edit .env (SECRET_KEY, EVIDENCE_ENCRYPTION_KEY, SEED_ADMIN_PASSWORD)
docker compose up --build -d
```

Services:

| Service | Exposed port | Description |
|---|---|---|
| `backend` | 8000 | FastAPI app; `/api`, Swagger at `/docs` |
| `frontend` | 5173 | React SPA served by nginx; proxies `/api` |

Persistent data (SQLite DB + encrypted evidence) lives in the `deeptrace_data` Docker
volume.

## Option B — Bare metal

Backend:

```bash
cd backend
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
export $(grep -v '^#' ../.env | xargs)   # load env
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

Frontend:

```bash
cd frontend
npm install
npm run build          # outputs to dist/
# serve dist/ with any static server, pointing VITE_API_BASE_URL at the API
```

## Reverse proxy / TLS

Place both services behind a TLS-terminating reverse proxy (e.g., nginx/caddy). Frontend
nginx config at `frontend/nginx.conf` already proxies `/api` to the `backend` service.

## Production checklist

- [ ] Generate and set a strong `SECRET_KEY` and `EVIDENCE_ENCRYPTION_KEY`.
- [ ] Change the seeded admin password immediately.
- [ ] Restrict evidence upload extensions and set a strict `BACKEND_CORS_ORIGINS`.
- [ ] Enable an external database (Postgres) for multi-analyst scale.
- [ ] Back up the `deeptrace_data` volume (DB + encrypted evidence).
- [ ] Put the platform behind authenticated network access / VPN.