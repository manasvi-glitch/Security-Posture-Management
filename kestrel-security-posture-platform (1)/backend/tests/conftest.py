import os
import tempfile
import pytest
from fastapi.testclient import TestClient

os.environ["DATABASE_URL"] = f"sqlite:///{tempfile.mktemp(suffix='.db')}"

from app.main import app  # noqa: E402
from app.database import Base, engine  # noqa: E402


@pytest.fixture(autouse=True)
def clean_db():
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    yield


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def admin_token(client):
    client.post("/api/auth/register", json={
        "username": "admin", "email": "admin@test.com", "password": "adminpass123"
    })
    resp = client.post("/api/auth/login", data={"username": "admin", "password": "adminpass123"})
    return resp.json()["access_token"]


@pytest.fixture
def viewer_token(client, admin_token):
    client.post("/api/auth/register", json={
        "username": "viewer1", "email": "viewer1@test.com", "password": "viewerpass123", "role": "viewer"
    })
    resp = client.post("/api/auth/login", data={"username": "viewer1", "password": "viewerpass123"})
    return resp.json()["access_token"]


def auth_headers(token):
    return {"Authorization": f"Bearer {token}"}
