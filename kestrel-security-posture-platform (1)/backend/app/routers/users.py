from typing import List
from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from app.database import get_db
from app import models, schemas, auth
from app.audit import log_action

router = APIRouter(prefix="/api/users", tags=["users"])


@router.get("", response_model=List[schemas.UserOut])
def list_users(db: Session = Depends(get_db), current_user: models.User = Depends(auth.get_current_user)):
    """Any authenticated user can list users (needed to populate 'assign to' dropdowns)."""
    return db.query(models.User).order_by(models.User.username).all()


@router.patch("/{user_id}/role", response_model=schemas.UserOut)
def change_role(
    user_id: str,
    role: models.Role,
    request: Request,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(auth.require_role(models.Role.admin)),
):
    user = db.query(models.User).get(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    old_role = user.role
    user.role = role
    db.commit()
    db.refresh(user)
    log_action(db, current_user, "user.role_change", "user", user.id,
               f"{old_role.value} -> {role.value}", request)
    return user


@router.patch("/{user_id}/deactivate", response_model=schemas.UserOut)
def deactivate_user(
    user_id: str,
    request: Request,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(auth.require_role(models.Role.admin)),
):
    user = db.query(models.User).get(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    user.is_active = False
    db.commit()
    db.refresh(user)
    log_action(db, current_user, "user.deactivate", "user", user.id, None, request)
    return user
