from fastapi import APIRouter, Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from sqlalchemy import or_

from app.database import get_db
from app import models, schemas, auth
from app.audit import log_action

router = APIRouter(prefix="/api/auth", tags=["auth"])


@router.post("/register", response_model=schemas.UserOut, status_code=201)
def register(payload: schemas.UserCreate, request: Request, db: Session = Depends(get_db)):
    existing = db.query(models.User).filter(
        or_(models.User.username == payload.username, models.User.email == payload.email)
    ).first()
    if existing:
        raise HTTPException(status_code=409, detail="Username or email already registered")

    # First user ever created becomes admin automatically; everyone else
    # gets the role they request, EXCEPT admin -- only an existing admin
    # can promote someone to admin (see users.py).
    is_first_user = db.query(models.User).count() == 0
    role = models.Role.admin if is_first_user else (
        payload.role if payload.role != models.Role.admin else models.Role.viewer
    )

    user = models.User(
        username=payload.username,
        email=payload.email,
        password_hash=auth.hash_password(payload.password),
        role=role,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    log_action(db, user, "user.register", "user", user.id, f"role={role.value}", request)
    return user


@router.post("/login", response_model=schemas.Token)
def login(request: Request, form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(models.User).filter(models.User.username == form_data.username).first()
    if not user or not auth.verify_password(form_data.password, user.password_hash):
        log_action(db, None, "user.login_failed", "user", None, f"username={form_data.username}", request)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if not user.is_active:
        raise HTTPException(status_code=403, detail="Account is disabled")

    token = auth.create_access_token({"sub": user.id, "role": user.role.value})
    log_action(db, user, "user.login", "user", user.id, None, request)
    return schemas.Token(access_token=token, user=user)


@router.get("/me", response_model=schemas.UserOut)
def me(current_user: models.User = Depends(auth.get_current_user)):
    return current_user
