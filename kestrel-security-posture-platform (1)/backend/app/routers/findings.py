from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Request, UploadFile, File, Query
from sqlalchemy.orm import Session

from app.database import get_db
from app import models, schemas, auth
from app.audit import log_action
from app.risk_engine import compute_risk_score
from app import normalizer

router = APIRouter(prefix="/api/findings", tags=["findings"])


@router.get("", response_model=List[schemas.FindingOut])
def list_findings(
    severity: Optional[models.Severity] = None,
    category: Optional[models.Category] = None,
    status: Optional[models.FindingStatus] = None,
    asset_id: Optional[str] = None,
    assigned_to: Optional[str] = None,
    limit: int = Query(200, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    current_user: models.User = Depends(auth.get_current_user),
):
    q = db.query(models.Finding)
    if severity:
        q = q.filter(models.Finding.severity == severity)
    if category:
        q = q.filter(models.Finding.category == category)
    if status:
        q = q.filter(models.Finding.status == status)
    if asset_id:
        q = q.filter(models.Finding.asset_id == asset_id)
    if assigned_to:
        q = q.filter(models.Finding.assigned_to == assigned_to)
    return q.order_by(models.Finding.risk_score.desc(), models.Finding.created_at.desc()).offset(offset).limit(limit).all()


@router.post("", response_model=schemas.FindingOut, status_code=201)
def create_finding(
    payload: schemas.FindingCreate,
    request: Request,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(auth.require_role(models.Role.admin, models.Role.analyst)),
):
    asset = db.query(models.Asset).get(payload.asset_id)
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")

    finding = models.Finding(**payload.model_dump())
    finding.risk_score = compute_risk_score(finding, asset)
    db.add(finding)
    db.commit()
    db.refresh(finding)

    _record_event(db, finding, current_user, "status_change", None, finding.status.value, "Finding created")
    log_action(db, current_user, "finding.create", "finding", finding.id, finding.title, request)
    return finding


@router.get("/{finding_id}", response_model=schemas.FindingDetailOut)
def get_finding(
    finding_id: str,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(auth.get_current_user),
):
    finding = db.query(models.Finding).get(finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    return finding


@router.patch("/{finding_id}", response_model=schemas.FindingOut)
def update_finding(
    finding_id: str,
    payload: schemas.FindingUpdate,
    request: Request,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(auth.require_role(models.Role.admin, models.Role.analyst)),
):
    finding = db.query(models.Finding).get(finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    changes = payload.model_dump(exclude_unset=True)
    for k, v in changes.items():
        setattr(finding, k, v)
    finding.risk_score = compute_risk_score(finding, finding.asset)
    db.commit()
    db.refresh(finding)
    log_action(db, current_user, "finding.update", "finding", finding.id, str(changes), request)
    return finding


def _record_event(db, finding, actor, action, from_status, to_status, note=None, evidence_url=None):
    event = models.RemediationEvent(
        finding_id=finding.id,
        actor_id=actor.id if actor else None,
        action=action,
        from_status=from_status,
        to_status=to_status,
        note=note,
        evidence_url=evidence_url,
    )
    db.add(event)
    db.commit()


@router.post("/import/kestrel-scan", response_model=schemas.ImportResult)
def import_kestrel_scan(
    payload: List[dict],
    request: Request,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(auth.require_role(models.Role.admin, models.Role.analyst)),
):
    """Import findings from the generic 'kestrel_scan' JSON format."""
    normalized, errors = normalizer.normalize_kestrel_scan(payload)
    result = _ingest_normalized(db, normalized, errors, current_user, request)
    return result


@router.post("/import/nessus-csv", response_model=schemas.ImportResult)
async def import_nessus_csv(
    request: Request,
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    current_user: models.User = Depends(auth.require_role(models.Role.admin, models.Role.analyst)),
):
    """Import findings from a Nessus/OpenVAS-style CSV export."""
    text = (await file.read()).decode("utf-8", errors="replace")
    normalized, errors = normalizer.normalize_nessus_csv(text)
    result = _ingest_normalized(db, normalized, errors, current_user, request)
    return result


@router.post("/import/catalog-batch", response_model=schemas.ImportResult)
def import_catalog_batch(
    payload: List[dict],
    request: Request,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(auth.require_role(models.Role.admin, models.Role.analyst)),
):
    """Import one browser-converted batch from a CVE/CWE vulnerability catalog.

    The browser sends small batches so large source files also work on serverless
    deployments with strict request-body limits.
    """
    if not payload:
        return schemas.ImportResult(assets_created=0, findings_created=0, findings_skipped=0, errors=[])
    if len(payload) > 2000:
        raise HTTPException(status_code=413, detail="Import batches may contain at most 2,000 rows.")

    valid = []
    errors = []
    for index, item in enumerate(payload, start=1):
        try:
            cve = str(item.get("cve_id") or "").strip()
            title = str(item.get("title") or "").strip()
            description = str(item.get("description") or "").strip()
            severity = models.Severity(str(item.get("severity") or "").lower())
            category = models.Category(str(item.get("category") or "").lower())
            external_id = str(item.get("external_id") or cve).strip()
            if not cve or not title:
                raise ValueError("CVE ID and title are required")
            if len(title) > 500:
                title = title[:497] + "..."
            if len(description) > 10000:
                description = description[:9997] + "..."
            valid.append({
                "cve_id": cve[:100],
                "title": title,
                "description": description or None,
                "severity": severity,
                "category": category,
                "external_id": external_id[:100] or cve[:100],
            })
        except (ValueError, TypeError) as exc:
            errors.append(f"batch row {index}: {exc}")

    if not valid:
        return schemas.ImportResult(assets_created=0, findings_created=0, findings_skipped=0, errors=errors[:50])

    # Catalog entries are grouped under clearly-labelled synthetic assets.
    asset_names = {f"cve-catalog-{item['category'].value}" for item in valid}
    assets = {
        asset.name: asset
        for asset in db.query(models.Asset).filter(models.Asset.name.in_(asset_names)).all()
    }
    assets_created = 0
    for name in asset_names:
        if name not in assets:
            asset = models.Asset(
                name=name,
                asset_type=models.AssetType.application,
                owner="Vulnerability catalog (synthetic grouping)",
                environment="catalog",
                criticality=models.Criticality.medium,
                internet_facing=False,
            )
            db.add(asset)
            assets[name] = asset
            assets_created += 1
    db.flush()

    cve_ids = list({item["cve_id"] for item in valid})
    existing_cves = set()
    for start in range(0, len(cve_ids), 500):
        chunk = cve_ids[start:start + 500]
        existing_cves.update(
            value for (value,) in db.query(models.Finding.cve_id)
            .filter(models.Finding.source == "cve_cwe_catalog")
            .filter(models.Finding.cve_id.in_(chunk))
            .all()
        )

    findings = []
    seen = set(existing_cves)
    findings_skipped = 0
    for item in valid:
        cve = item["cve_id"]
        if cve in seen:
            findings_skipped += 1
            continue
        seen.add(cve)
        asset = assets[f"cve-catalog-{item['category'].value}"]
        finding = models.Finding(
            asset_id=asset.id,
            source="cve_cwe_catalog",
            external_id=item["external_id"],
            cve_id=cve,
            title=item["title"],
            description=item["description"],
            severity=item["severity"],
            category=item["category"],
            exploitability=models.Exploitability.theoretical,
        )
        finding.risk_score = compute_risk_score(finding, asset)
        findings.append(finding)

    db.add_all(findings)
    db.flush()
    db.add_all([
        models.RemediationEvent(
            finding_id=finding.id,
            actor_id=current_user.id,
            action="status_change",
            from_status=None,
            to_status=finding.status.value,
            note="Imported from CVE/CWE vulnerability catalog",
        )
        for finding in findings
    ])
    db.add(models.AuditLog(
        user_id=current_user.id,
        username=current_user.username,
        action="finding.import.catalog_batch",
        entity_type="finding",
        detail=f"created={len(findings)} skipped={findings_skipped} assets_created={assets_created}",
        ip_address=request.client.host if request.client else None,
    ))
    db.commit()

    return schemas.ImportResult(
        assets_created=assets_created,
        findings_created=len(findings),
        findings_skipped=findings_skipped,
        errors=errors[:50],
    )


def _ingest_normalized(db: Session, normalized: list, errors: list, current_user, request) -> schemas.ImportResult:
    assets_created = 0
    findings_created = 0
    skipped = 0

    for item in normalized:
        asset = db.query(models.Asset).filter(models.Asset.name == item["asset_name"]).first()
        if not asset:
            asset = models.Asset(
                name=item["asset_name"],
                ip_address=item.get("asset_ip"),
                internet_facing=item.get("internet_facing", False),
                asset_type=models.AssetType.server,
                criticality=models.Criticality.medium,
            )
            db.add(asset)
            db.commit()
            db.refresh(asset)
            assets_created += 1

        # Skip if an identical finding (same asset + title + source) already exists,
        # so re-importing the same scan doesn't create duplicates.
        dup = (
            db.query(models.Finding)
            .filter(models.Finding.asset_id == asset.id)
            .filter(models.Finding.title == item["title"])
            .filter(models.Finding.source == item["source"])
            .first()
        )
        if dup:
            skipped += 1
            continue

        finding = models.Finding(
            asset_id=asset.id,
            source=item["source"],
            external_id=item.get("external_id"),
            cve_id=item.get("cve_id"),
            title=item["title"],
            description=item.get("description"),
            severity=item["severity"],
            category=item["category"],
            exploitability=item["exploitability"],
        )
        finding.risk_score = compute_risk_score(finding, asset)
        db.add(finding)
        db.commit()
        db.refresh(finding)
        _record_event(db, finding, current_user, "status_change", None, finding.status.value,
                      f"Imported from {item['source']}")
        findings_created += 1

    log_action(db, current_user, "finding.import", "finding", None,
               f"created={findings_created} skipped={skipped} assets_created={assets_created}", request)

    return schemas.ImportResult(
        assets_created=assets_created,
        findings_created=findings_created,
        findings_skipped=skipped,
        errors=errors,
    )
