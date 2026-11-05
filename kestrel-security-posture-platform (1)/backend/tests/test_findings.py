from tests.conftest import auth_headers


def _create_asset(client, token, **overrides):
    payload = {"name": "test-server", "criticality": "high", "internet_facing": True}
    payload.update(overrides)
    resp = client.post("/api/assets", json=payload, headers=auth_headers(token))
    assert resp.status_code == 201
    return resp.json()


def _create_finding(client, token, asset_id, **overrides):
    payload = {
        "asset_id": asset_id, "title": "Test finding", "severity": "high",
        "category": "network", "exploitability": "poc",
    }
    payload.update(overrides)
    resp = client.post("/api/findings", json=payload, headers=auth_headers(token))
    assert resp.status_code == 201
    return resp.json()


def test_create_finding_computes_risk_score(client, admin_token):
    asset = _create_asset(client, admin_token)
    finding = _create_finding(client, admin_token, asset["id"])
    assert finding["risk_score"] > 0
    assert finding["status"] == "detected"


def test_workflow_happy_path(client, admin_token):
    asset = _create_asset(client, admin_token)
    finding = _create_finding(client, admin_token, asset["id"])
    fid = finding["id"]
    h = auth_headers(admin_token)

    steps = ["triaged", "assigned", "fix_in_progress", "remediated", "verification", "resolved"]
    # 'assigned' transition requires the finding to actually be assigned first in real usage,
    # but the state machine only checks status, not the assignee field, so it's allowed.
    for step in steps:
        resp = client.post(f"/api/findings/{fid}/status", json={"to_status": step}, headers=h)
        assert resp.status_code == 200, resp.text
        assert resp.json()["status"] == step

    final = client.get(f"/api/findings/{fid}", headers=h).json()
    assert final["resolved_at"] is not None
    assert len(final["events"]) == 1 + len(steps)  # creation event + each transition


def test_invalid_transition_rejected(client, admin_token):
    asset = _create_asset(client, admin_token)
    finding = _create_finding(client, admin_token, asset["id"])
    h = auth_headers(admin_token)
    resp = client.post(f"/api/findings/{finding['id']}/status", json={"to_status": "resolved"}, headers=h)
    assert resp.status_code == 400


def test_reopen_after_resolved(client, admin_token):
    asset = _create_asset(client, admin_token)
    finding = _create_finding(client, admin_token, asset["id"])
    fid = finding["id"]
    h = auth_headers(admin_token)
    for step in ["triaged", "assigned", "fix_in_progress", "remediated", "verification", "resolved"]:
        client.post(f"/api/findings/{fid}/status", json={"to_status": step}, headers=h)

    resp = client.post(f"/api/findings/{fid}/status", json={"to_status": "reopened"}, headers=h)
    assert resp.status_code == 200
    assert resp.json()["resolved_at"] is None


def test_assign_finding_to_user(client, admin_token):
    asset = _create_asset(client, admin_token)
    finding = _create_finding(client, admin_token, asset["id"])
    h = auth_headers(admin_token)
    me = client.get("/api/auth/me", headers=h).json()

    resp = client.post(f"/api/findings/{finding['id']}/assign",
                        json={"user_id": me["id"], "note": "please fix"}, headers=h)
    assert resp.status_code == 200
    assert resp.json()["assigned_to"] == me["id"]


def test_kestrel_scan_import_creates_asset_and_finding(client, admin_token):
    h = auth_headers(admin_token)
    payload = [{
        "host": "imported-host-01", "ip": "10.5.5.5", "internet_facing": True,
        "finding": "Outdated SSH daemon", "severity": "high",
        "description": "CVE-2024-00000 remote exploit available", "cve": "CVE-2024-00000",
    }]
    resp = client.post("/api/findings/import/kestrel-scan", json=payload, headers=h)
    assert resp.status_code == 200
    body = resp.json()
    assert body["assets_created"] == 1
    assert body["findings_created"] == 1

    # Re-importing the same payload should skip the duplicate.
    resp2 = client.post("/api/findings/import/kestrel-scan", json=payload, headers=h)
    assert resp2.json()["findings_created"] == 0
    assert resp2.json()["findings_skipped"] == 1


def test_dashboard_summary_reflects_open_findings(client, admin_token):
    asset = _create_asset(client, admin_token)
    _create_finding(client, admin_token, asset["id"], severity="critical")
    h = auth_headers(admin_token)
    resp = client.get("/api/dashboard/summary", headers=h)
    assert resp.status_code == 200
    body = resp.json()
    assert body["findings"]["critical"] == 1
    assert body["posture"]["overall"] < 100
