from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
import os

from app.database import Base, engine
from app.routers import auth, assets, findings, remediation, dashboard, reports, audit, users

Base.metadata.create_all(bind=engine)

# Opt-in demo data (SPP_AUTO_SEED=1). Off by default because the seeded
# accounts use well-known passwords -- never enable on a public deployment
# you care about.
if os.environ.get("SPP_AUTO_SEED") == "1":
    from app.seed import seed_if_empty
    seed_if_empty()

app = FastAPI(
    title="Security Posture Management Platform",
    description="Aggregates findings, scores risk, and tracks remediation across the asset inventory.",
    version="0.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # relax for local/dev use; restrict in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth.router)
app.include_router(users.router)
app.include_router(assets.router)
app.include_router(findings.router)
app.include_router(remediation.router)
app.include_router(dashboard.router)
app.include_router(reports.router)
app.include_router(audit.router)


@app.get("/api/health")
def health():
    return {"status": "ok"}


# Serve the frontend SPA (built as plain static files) if present, so the
# whole platform can be run with a single `uvicorn app.main:app`.
FRONTEND_DIR = os.path.join(os.path.dirname(__file__), "..", "static")
if os.path.isdir(FRONTEND_DIR):
    app.mount("/", StaticFiles(directory=FRONTEND_DIR, html=True), name="frontend")
