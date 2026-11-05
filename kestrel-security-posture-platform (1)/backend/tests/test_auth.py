from tests.conftest import auth_headers


def test_first_user_becomes_admin(client):
    resp = client.post("/api/auth/register", json={
        "username": "first", "email": "first@test.com", "password": "password123"
    })
    assert resp.status_code == 201
    assert resp.json()["role"] == "admin"


def test_second_user_cannot_self_promote_to_admin(client, admin_token):
    resp = client.post("/api/auth/register", json={
        "username": "sneaky", "email": "sneaky@test.com", "password": "password123", "role": "admin"
    })
    assert resp.status_code == 201
    assert resp.json()["role"] == "viewer"  # downgraded, not admin


def test_login_wrong_password_rejected(client, admin_token):
    resp = client.post("/api/auth/login", data={"username": "admin", "password": "wrong"})
    assert resp.status_code == 401


def test_duplicate_registration_rejected(client, admin_token):
    resp = client.post("/api/auth/register", json={
        "username": "admin", "email": "different@test.com", "password": "password123"
    })
    assert resp.status_code == 409


def test_viewer_cannot_create_asset(client, viewer_token):
    resp = client.post("/api/assets", json={"name": "test-asset"}, headers=auth_headers(viewer_token))
    assert resp.status_code == 403


def test_admin_can_create_asset(client, admin_token):
    resp = client.post("/api/assets", json={"name": "test-asset", "criticality": "high"},
                        headers=auth_headers(admin_token))
    assert resp.status_code == 201
    assert resp.json()["name"] == "test-asset"


def test_unauthenticated_request_rejected(client):
    resp = client.get("/api/assets")
    assert resp.status_code == 401
