"""
Database engine and session configuration.

Connection string resolution order:
  1. DATABASE_URL env var (use this for PostgreSQL: Neon, Supabase, RDS...)
  2. On Vercel with no DATABASE_URL: SQLite in /tmp, the only writable path
     there. This is EPHEMERAL demo storage: it resets on cold starts and is
     not shared between function instances.
  3. Locally: ./spp.db
"""
import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base
from sqlalchemy.pool import NullPool

ON_VERCEL = bool(os.environ.get("VERCEL"))

_raw = os.environ.get("DATABASE_URL")
if _raw:
    # Providers often hand out postgres:// ; SQLAlchemy needs postgresql+driver://
    if _raw.startswith("postgres://"):
        _raw = _raw.replace("postgres://", "postgresql://", 1)
    if _raw.startswith("postgresql://"):
        _raw = _raw.replace("postgresql://", "postgresql+psycopg2://", 1)
    DATABASE_URL = _raw
elif ON_VERCEL:
    DATABASE_URL = "sqlite:////tmp/spp.db"
else:
    DATABASE_URL = "sqlite:///./spp.db"

if DATABASE_URL.startswith("sqlite"):
    engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
elif ON_VERCEL:
    # Serverless: don't hold pooled connections between invocations.
    engine = create_engine(DATABASE_URL, poolclass=NullPool, pool_pre_ping=True)
else:
    engine = create_engine(DATABASE_URL, pool_pre_ping=True)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
