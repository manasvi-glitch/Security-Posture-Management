"""
Seeds the database with demo users, assets, and findings so the platform
looks and behaves like the original static prototype, but the numbers now
come from real computed logic instead of being hardcoded.

Run with:  python -m app.seed
"""
import random
from datetime import datetime, timedelta

from app.database import Base, engine, SessionLocal
from app import models
from app.auth import hash_password
from app.risk_engine import compute_risk_score

random.seed(42)


def run(reset=True):
    if reset:
        Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()

    # --- Users ---
    admin = models.User(username="admin", email="admin@kestrelfreight.com",
                         password_hash=hash_password("admin123"), role=models.Role.admin)
    analyst = models.User(username="jrivera", email="jrivera@kestrelfreight.com",
                           password_hash=hash_password("analyst123"), role=models.Role.analyst)
    viewer = models.User(username="viewer", email="viewer@kestrelfreight.com",
                          password_hash=hash_password("viewer123"), role=models.Role.viewer)
    db.add_all([admin, analyst, viewer])
    db.commit()

    # --- Assets ---
    assets_data = [
        ("prod-db-04", models.AssetType.server, models.Criticality.critical, True, "10.20.4.14"),
        ("web-edge-02", models.AssetType.server, models.Criticality.critical, True, "10.20.1.22"),
        ("portal.kestrelfreight.com", models.AssetType.application, models.Criticality.high, True, None),
        ("core-switch-11", models.AssetType.network_device, models.Criticality.high, False, "10.10.0.11"),
        ("iam-directory-01", models.AssetType.server, models.Criticality.critical, False, "10.20.2.5"),
        ("fleet-tracking-svc", models.AssetType.application, models.Criticality.high, True, None),
        ("hr-fileserver", models.AssetType.server, models.Criticality.medium, False, "10.30.1.9"),
        ("dispatch-workstation-12", models.AssetType.workstation, models.Criticality.low, False, "10.40.5.12"),
        ("billing-api", models.AssetType.cloud_resource, models.Criticality.high, True, None),
        ("warehouse-scanner-gw", models.AssetType.network_device, models.Criticality.medium, False, "10.10.9.2"),
    ]
    assets = {}
    for name, atype, crit, internet, ip in assets_data:
        a = models.Asset(name=name, asset_type=atype, criticality=crit,
                          internet_facing=internet, ip_address=ip, environment="production",
                          owner="IT Operations")
        db.add(a)
        db.commit()
        db.refresh(a)
        assets[name] = a

    # --- Findings: (asset, title, severity, category, exploitability, status_age_days) ---
    findings_data = [
        ("prod-db-04", "Unrestricted SSH access from 0.0.0.0/0", models.Severity.critical,
         models.Category.network, models.Exploitability.active, models.FindingStatus.detected, 2),
        ("web-edge-02", "Critical remote code execution vulnerability (unpatched)", models.Severity.critical,
         models.Category.patch_management, models.Exploitability.active, models.FindingStatus.triaged, 3),
        ("iam-directory-01", "Inactive privileged service account still enabled", models.Severity.high,
         models.Category.access_control, models.Exploitability.poc, models.FindingStatus.assigned, 6),
        ("core-switch-11", "Telnet enabled on management interface", models.Severity.high,
         models.Category.network, models.Exploitability.poc, models.FindingStatus.detected, 1),
        ("portal.kestrelfreight.com", "Weak TLS cipher suites accepted (TLS 1.0/1.1)", models.Severity.medium,
         models.Category.configuration, models.Exploitability.theoretical, models.FindingStatus.fix_in_progress, 9),
        ("billing-api", "API keys stored in plaintext environment config", models.Severity.high,
         models.Category.authentication, models.Exploitability.poc, models.FindingStatus.triaged, 4),
        ("fleet-tracking-svc", "Missing MFA on administrative login", models.Severity.high,
         models.Category.authentication, models.Exploitability.theoretical, models.FindingStatus.assigned, 7),
        ("hr-fileserver", "SMBv1 protocol still enabled", models.Severity.medium,
         models.Category.configuration, models.Exploitability.poc, models.FindingStatus.detected, 5),
        ("dispatch-workstation-12", "Local admin rights granted to standard user", models.Severity.medium,
         models.Category.access_control, models.Exploitability.theoretical, models.FindingStatus.remediated, 12),
        ("warehouse-scanner-gw", "Default vendor credentials in use", models.Severity.high,
         models.Category.authentication, models.Exploitability.active, models.FindingStatus.detected, 1),
        ("prod-db-04", "Outdated PostgreSQL version with known CVEs", models.Severity.high,
         models.Category.patch_management, models.Exploitability.poc, models.FindingStatus.verification, 14),
        ("web-edge-02", "Reflected XSS on search parameter", models.Severity.medium,
         models.Category.application, models.Exploitability.poc, models.FindingStatus.detected, 3),
        ("portal.kestrelfreight.com", "Verbose error messages expose stack traces", models.Severity.low,
         models.Category.application, models.Exploitability.theoretical, models.FindingStatus.detected, 8),
        ("iam-directory-01", "Password policy allows weak passwords (<8 chars)", models.Severity.medium,
         models.Category.authentication, models.Exploitability.theoretical, models.FindingStatus.triaged, 10),
        ("billing-api", "Overly permissive CORS configuration", models.Severity.low,
         models.Category.configuration, models.Exploitability.theoretical, models.FindingStatus.detected, 6),
        ("core-switch-11", "Firmware 3 major versions behind vendor latest", models.Severity.medium,
         models.Category.patch_management, models.Exploitability.theoretical, models.FindingStatus.assigned, 20),
        ("fleet-tracking-svc", "SQL injection in vehicle lookup endpoint", models.Severity.critical,
         models.Category.application, models.Exploitability.poc, models.FindingStatus.fix_in_progress, 2),
        ("hr-fileserver", "Sensitive files accessible without access controls", models.Severity.high,
         models.Category.access_control, models.Exploitability.theoretical, models.FindingStatus.detected, 4),
    ]

    # A batch of already-resolved findings in the last 30 days, to populate
    # the "resolved (30d)" metrics and the improving trend line.
    resolved_titles = [
        ("dispatch-workstation-12", "Unsupported OS version (Windows 8.1)", models.Severity.medium,
         models.Category.patch_management, models.Exploitability.theoretical),
        ("warehouse-scanner-gw", "Unencrypted management traffic (HTTP)", models.Severity.medium,
         models.Category.configuration, models.Exploitability.theoretical),
        ("hr-fileserver", "Guest account enabled", models.Severity.low,
         models.Category.access_control, models.Exploitability.theoretical),
        ("billing-api", "Missing rate limiting on auth endpoint", models.Severity.medium,
         models.Category.authentication, models.Exploitability.poc),
        ("portal.kestrelfreight.com", "Outdated jQuery library with known XSS CVEs", models.Severity.high,
         models.Category.patch_management, models.Exploitability.poc),
        ("core-switch-11", "SNMP community string set to default 'public'", models.Severity.high,
         models.Category.configuration, models.Exploitability.active),
        ("prod-db-04", "Database backups stored unencrypted", models.Severity.high,
         models.Category.configuration, models.Exploitability.theoretical),
    ] * 3  # repeat to reach ~21 resolved items across 30 days, similar to prototype's "23 resolved"

    now = datetime.utcnow()

    def add_finding(asset_name, title, severity, category, exploitability, status, age_days, resolved=False):
        asset = assets[asset_name]
        created = now - timedelta(days=age_days)
        f = models.Finding(
            asset_id=asset.id, title=title, severity=severity, category=category,
            exploitability=exploitability, status=status, source="manual",
            created_at=created, updated_at=now,
        )
        f.risk_score = compute_risk_score(f, asset)
        if resolved:
            f.status = models.FindingStatus.resolved
            f.resolved_at = created + timedelta(days=random.randint(1, min(age_days, 10) or 1))
        db.add(f)
        db.commit()
        db.refresh(f)
        db.add(models.RemediationEvent(finding_id=f.id, actor_id=analyst.id, action="status_change",
                                        from_status=None, to_status=f.status.value, note="Seed data"))
        db.commit()
        return f

    for asset_name, title, sev, cat, expl, status, age in findings_data:
        f = add_finding(asset_name, title, sev, cat, expl, status, age)
        if status in (models.FindingStatus.assigned, models.FindingStatus.fix_in_progress,
                      models.FindingStatus.remediated, models.FindingStatus.verification):
            f.assigned_to = analyst.id
            db.commit()

    for i, (asset_name, title, sev, cat, expl) in enumerate(resolved_titles):
        age = random.randint(3, 29)
        add_finding(asset_name, f"{title} ({i})", sev, cat, expl,
                    models.FindingStatus.detected, age, resolved=True)

    db.close()
    print("Seed complete.")
    print("Login as: admin/admin123, jrivera/analyst123, viewer/viewer123")


def seed_if_empty():
    """Non-destructive: seeds demo data only when there are no users yet."""
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        empty = db.query(models.User).count() == 0
    finally:
        db.close()
    if empty:
        try:
            run(reset=False)
        except Exception as exc:  # e.g. two cold starts racing on a shared DB
            print(f"Auto-seed skipped: {exc}")


if __name__ == "__main__":
    run()
