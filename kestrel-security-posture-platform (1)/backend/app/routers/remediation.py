from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from app.database import get_db
from app import models, schemas, auth
from app.audit import log_action

router = APIRouter(prefix="/api/findings", tags=["remediation"])


def _get_finding_or_404(db: Session, finding_id: str) -> models.Finding:
    finding = db.query(models.Finding).get(finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    return finding


def _record_event(db, finding, actor, action, from_status=None, to_status=None, note=None, evidence_url=None):
    event = models.RemediationEvent(
        finding_id=finding.id, actor_id=actor.id if actor else None, action=action,
        from_status=from_status, to_status=to_status, note=note, evidence_url=evidence_url,
    )
    db.add(event)
    db.commit()


@router.post("/{finding_id}/status", response_model=schemas.FindingDetailOut)
def change_status(
    finding_id: str,
    payload: schemas.StatusChangeRequest,
    request: Request,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(auth.require_role(models.Role.admin, models.Role.analyst)),
):
    finding = _get_finding_or_404(db, finding_id)
    current = finding.status
    target = payload.to_status

    allowed = models.ALLOWED_TRANSITIONS.get(current, set())
    if target not in allowed:
        raise HTTPException(
            status_code=400,
            detail=f"Cannot move a finding from '{current.value}' to '{target.value}'. "
                   f"Allowed next steps: {sorted(s.value for s in allowed) or 'none'}.",
        )

    finding.status = target
    if target == models.FindingStatus.resolved:
        finding.resolved_at = datetime.utcnow()
    if target == models.FindingStatus.reopened:
        finding.resolved_at = None

    db.commit()
    db.refresh(finding)
    _record_event(db, finding, current_user, "status_change", current.value, target.value, payload.note)
    log_action(db, current_user, "finding.status_change", "finding", finding.id,
               f"{current.value} -> {target.value}", request)
    return finding


@router.post("/{finding_id}/assign", response_model=schemas.FindingDetailOut)
def assign_finding(
    finding_id: str,
    payload: schemas.AssignRequest,
    request: Request,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(auth.require_role(models.Role.admin, models.Role.analyst)),
):
    finding = _get_finding_or_404(db, finding_id)
    assignee = db.query(models.User).get(payload.user_id)
    if not assignee:
        raise HTTPException(status_code=404, detail="User not found")

    finding.assigned_to = assignee.id
    db.commit()
    db.refresh(finding)
    _record_event(db, finding, current_user, "assignment", None, None,
                  payload.note or f"Assigned to {assignee.username}")
    log_action(db, current_user, "finding.assign", "finding", finding.id, assignee.username, request)
    return finding


@router.post("/{finding_id}/notes", response_model=schemas.FindingDetailOut)
def add_note(
    finding_id: str,
    payload: schemas.NoteRequest,
    request: Request,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(auth.require_role(models.Role.admin, models.Role.analyst)),
):
    finding = _get_finding_or_404(db, finding_id)
    _record_event(db, finding, current_user, "note", None, None, payload.note)
    log_action(db, current_user, "finding.note", "finding", finding.id, payload.note[:120], request)
    db.refresh(finding)
    return finding


@router.post("/{finding_id}/evidence", response_model=schemas.FindingDetailOut)
def add_evidence(
    finding_id: str,
    payload: schemas.EvidenceRequest,
    request: Request,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(auth.require_role(models.Role.admin, models.Role.analyst)),
):
    finding = _get_finding_or_404(db, finding_id)
    _record_event(db, finding, current_user, "evidence", None, None, payload.note, payload.evidence_url)
    log_action(db, current_user, "finding.evidence", "finding", finding.id, payload.evidence_url, request)
    db.refresh(finding)
    return finding
