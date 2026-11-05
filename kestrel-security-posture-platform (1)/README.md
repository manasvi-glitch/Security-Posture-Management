# Kestrel Freight — Security Posture Management Platform

A working prototype of the platform described in the project spec: it aggregates
findings, computes a transparent risk score per finding, rolls that up into a
security posture score, and tracks each finding through a remediation workflow —
with role-based access control and a full audit trail.

This is a real, running application (Python/FastAPI backend + a browser
frontend), not a mockup. Every number on screen is computed from data in the
database.

## Quick start

```bash
cd backend
python3 -m venv venv && source venv/bin/activate      # optional but recommended
pip install -r requirements.txt

python -m app.seed          # creates spp.db with demo users/assets/findings
uvicorn app.main:app --reload --port 8420
```

**In VS Code:** open the project folder, then either press F5 and choose
"Run API (uvicorn)", or open `backend/run.py` and use the Run button. Don't
run `app/main.py` directly: it fails with `No module named 'app'`.

Open **http://localhost:8420** — the frontend is served by the same process as
the API (from `backend/static/`), so there's nothing else to run.

Interactive API docs (Swagger UI): **http://localhost:8420/docs**

### Demo logins (seeded)

| Username  | Password    | Role    |
|-----------|-------------|---------|
| `admin`   | `admin123`  | admin   |
| `jrivera` | `analyst123`| analyst |
| `viewer`  | `viewer123` | viewer  |

## Deploying to Vercel

1. **Root Directory**: in Vercel > Project Settings > General, set Root Directory
   to the folder that contains `pyproject.toml` (the `backend/` folder; if your
   repo has an extra wrapper folder, e.g. `kestrel-security-posture-platform/backend`).
2. The entrypoint is declared in `backend/pyproject.toml`:
   `[tool.vercel] entrypoint = "app.main:app"`, so no file renaming is needed.
3. **Environment variables** (Settings > Environment Variables):

   | Variable | Value |
   |---|---|
   | `SPP_SECRET_KEY` | a long random string (signs login tokens) |
   | `DATABASE_URL` | your PostgreSQL URL (Neon, Supabase, etc.) |
   | `SPP_AUTO_SEED` | `1` only if you want the demo data loaded (see warning) |

**Database:** Vercel's filesystem is read-only except `/tmp`, and functions are
stateless. Without `DATABASE_URL` the app falls back to SQLite in `/tmp`, which
works for a quick demo but **loses data on cold starts** and isn't shared across
instances. Use PostgreSQL for anything real.

**Seeding:** `SPP_AUTO_SEED=1` creates the demo accounts (`admin/admin123`, ...)
when the database is empty. Do not leave that on for a public deployment.
Without it, the first user to register via `/api/auth/register` becomes admin.

## What's implemented

- **Authentication & RBAC** — JWT sessions, bcrypt-hashed passwords, three
  roles (`admin` / `analyst` / `viewer`) enforced on every write endpoint.
  The first user ever registered becomes admin automatically; nobody can
  self-promote to admin after that.
- **Asset inventory** — CRUD for assets with type, criticality, exposure
  (internet-facing), owner, and environment.
- **Finding management** — CRUD, plus two scanner ingestion formats:
  - a generic JSON scan format (`kestrel_scan`) — see `backend/sample_data/sample_scan.kestrel.json`
  - a Nessus/OpenVAS-style CSV export — see `backend/sample_data/sample_scan_nessus.csv`

  Both importers auto-create assets by hostname, best-effort categorize
  findings by keyword, and skip duplicates on re-import.
- **Risk scoring engine** (`app/risk_engine.py`) — deliberately kept in one
  small, readable file. Each finding's risk score is
  `severity × exposure × asset_criticality × exploitability × 100`, so any
  score can be reproduced by hand. See the module docstring for the exact
  weights and the posture-score rollup formula.
- **Security posture score** — six category scores (Authentication, Network,
  Configuration, Patch Management, Access Control, Application), each
  starting at 100 and losing points for open findings, capped so no single
  finding can zero out a category. The overall score is their average.
- **Remediation workflow** — a real state machine
  (`detected → triaged → assigned → fix_in_progress → remediated →
  verification → resolved`, with `reopened` from either `verification` or
  `resolved`). Invalid transitions are rejected server-side (HTTP 400), not
  just hidden in the UI. Every transition, assignment, and note is recorded
  as an immutable event on the finding.
- **Dashboard** — posture score, findings/assets/remediation summaries, top
  5 priorities by risk score, remediation pipeline counts, and an
  approximate posture trend line — all computed live from `/api/dashboard/summary`.
- **Reporting** — CSV export of the full findings register.
- **Audit log** — every login, create, update, delete, status change, and
  import is recorded with actor, timestamp, and IP; viewable by admins at
  `/api/audit`.
- **Tests** — 22 pytest tests covering RBAC enforcement, the risk-scoring
  math, the workflow state machine (including that invalid transitions are
  rejected), and the importers. Run with `pytest tests/ -v` from `backend/`.

## Architecture

```
backend/
  app/
    main.py          FastAPI app, router registration, static file mount
    database.py       SQLAlchemy engine/session (SQLite by default)
    models.py          ORM models + the remediation state machine definition
    schemas.py          Pydantic request/response models
    auth.py               JWT + bcrypt + RBAC dependency
    risk_engine.py          Risk scoring & posture calculation (read this first)
    normalizer.py             Scanner data → internal Finding schema
    audit.py                    Audit log writer
    seed.py                      Demo data matching the original prototype
    routers/
      auth.py        register / login / me
      users.py         role management (admin)
      assets.py          asset CRUD
      findings.py           finding CRUD + scan import endpoints
      remediation.py           status transitions, assignment, notes, evidence
      dashboard.py                the /summary aggregation endpoint
      reports.py                    CSV export
      audit.py                        audit log listing (admin)
  static/            the built frontend (copy of /frontend), served at "/"
  sample_data/       example scan files for the two import formats
  tests/             pytest suite
frontend/
  index.html         app shell + login screen
  app.js             API client, router, and all views (vanilla JS, no build step)
```

### Why SQLite by default?

So the whole thing runs with zero external setup. Swap to PostgreSQL for
production by setting an environment variable — no code changes needed:

```bash
export DATABASE_URL="postgresql+psycopg2://user:password@localhost:5432/spp"
pip install psycopg2-binary
```

### Running the frontend separately (optional)

If you'd rather not use the static mount, you can serve `/frontend` with any
static file server. It auto-detects a different origin and points API calls
at `http://localhost:8420` — just make sure the backend is running there.

## Known simplifications (documented, not hidden)

- **Posture trend** is approximated by replaying resolved-finding history
  rather than reading from a persisted score-history table. A production
  version would snapshot the posture score on a schedule (e.g. nightly) into
  a `posture_score_history` table instead.
- **Category inference** on imported findings is keyword-based, not a
  scanner-provided field (most scanners don't provide one). It's a
  reasonable starting point but will misclassify some findings — that's
  flagged in `normalizer.py`.
- **CORS is wide open** (`allow_origins=["*"]`) for local development
  convenience; tighten this before deploying anywhere reachable.
- Only two scanner formats are implemented, per the MVP scope in the spec.
  Adding a third format means adding one function to `normalizer.py` and one
  endpoint to `routers/findings.py` — the internal schema doesn't change.
