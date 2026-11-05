from typing import Optional
from sqlalchemy.orm import Session
from fastapi import Request

from app import models


def log_action(
    db: Session,
    user: Optional[models.User],
    action: str,
    entity_type: Optional[str] = None,
    entity_id: Optional[str] = None,
    detail: Optional[str] = None,
    request: Optional[Request] = None,
):
    """Write an audit log row. Never raises -- audit logging must never
    break the primary request in flight."""
    try:
        entry = models.AuditLog(
            user_id=user.id if user else None,
            username=user.username if user else None,
            action=action,
            entity_type=entity_type,
            entity_id=entity_id,
            detail=detail,
            ip_address=request.client.host if (request and request.client) else None,
        )
        db.add(entry)
        db.commit()
    except Exception:
        db.rollback()
