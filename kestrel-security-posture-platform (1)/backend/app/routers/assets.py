from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from app.database import get_db
from app import models, schemas, auth
from app.audit import log_action

router = APIRouter(prefix="/api/assets", tags=["assets"])


@router.get("", response_model=List[schemas.AssetOut])
def list_assets(
    internet_facing: Optional[bool] = None,
    criticality: Optional[models.Criticality] = None,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(auth.get_current_user),
):
    q = db.query(models.Asset)
    if internet_facing is not None:
        q = q.filter(models.Asset.internet_facing == internet_facing)
    if criticality is not None:
        q = q.filter(models.Asset.criticality == criticality)
    assets = q.order_by(models.Asset.name).all()
    return [_to_asset_out(a) for a in assets]


def _to_asset_out(asset: models.Asset) -> schemas.AssetOut:
    out = schemas.AssetOut.model_validate(asset)
    out.open_finding_count = asset.open_finding_count
    return out


@router.post("", response_model=schemas.AssetOut, status_code=201)
def create_asset(
    payload: schemas.AssetCreate,
    request: Request,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(auth.require_role(models.Role.admin, models.Role.analyst)),
):
    asset = models.Asset(**payload.model_dump())
    db.add(asset)
    db.commit()
    db.refresh(asset)
    log_action(db, current_user, "asset.create", "asset", asset.id, asset.name, request)
    return _to_asset_out(asset)


@router.get("/{asset_id}", response_model=schemas.AssetOut)
def get_asset(
    asset_id: str,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(auth.get_current_user),
):
    asset = db.query(models.Asset).get(asset_id)
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    return _to_asset_out(asset)


@router.patch("/{asset_id}", response_model=schemas.AssetOut)
def update_asset(
    asset_id: str,
    payload: schemas.AssetUpdate,
    request: Request,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(auth.require_role(models.Role.admin, models.Role.analyst)),
):
    asset = db.query(models.Asset).get(asset_id)
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    changes = payload.model_dump(exclude_unset=True)
    for k, v in changes.items():
        setattr(asset, k, v)
    db.commit()
    db.refresh(asset)

    # Criticality/exposure changes affect risk scores of existing findings.
    if "criticality" in changes or "internet_facing" in changes:
        from app.risk_engine import compute_risk_score
        for f in asset.findings:
            f.risk_score = compute_risk_score(f, asset)
        db.commit()

    log_action(db, current_user, "asset.update", "asset", asset.id, str(changes), request)
    return _to_asset_out(asset)


@router.delete("/{asset_id}", status_code=204)
def delete_asset(
    asset_id: str,
    request: Request,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(auth.require_role(models.Role.admin)),
):
    asset = db.query(models.Asset).get(asset_id)
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    db.delete(asset)
    db.commit()
    log_action(db, current_user, "asset.delete", "asset", asset_id, asset.name, request)
    return None
