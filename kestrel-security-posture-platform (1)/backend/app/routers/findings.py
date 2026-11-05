from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Request, UploadFile, File
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
    return q.order_by(models.Finding.risk_score.desc()).all()


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
