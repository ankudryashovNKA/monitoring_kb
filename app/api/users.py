from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.db.dependencies import get_db
from app.models.user import User
from app.schemas.user import UserCreate, UserRead, UserUpdate
from app.security.user_auth import hash_password

router = APIRouter(prefix="/api/users", tags=["users"])


@router.post("", response_model=UserRead, status_code=status.HTTP_201_CREATED)
def create_user(payload: UserCreate, db: Session = Depends(get_db)) -> User:
    existing_login = db.query(User).filter(User.login == payload.login).first()
    if existing_login:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="User with this login already exists")

    existing = db.query(User).filter(User.email == payload.email).first()
    if existing:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="User with this email already exists")

    user = User(
        login=payload.login.strip(),
        password_hash=hash_password(payload.password),
        email=payload.email,
        display_name=payload.display_name.strip() if payload.display_name else None,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


@router.get("", response_model=list[UserRead])
def list_users(db: Session = Depends(get_db)) -> list[User]:
    return db.query(User).order_by(User.id.asc()).all()


@router.get("/{user_id}", response_model=UserRead)
def get_user(user_id: int, db: Session = Depends(get_db)) -> User:
    user = db.query(User).filter(User.id == user_id).first()
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    return user


@router.patch("/{user_id}", response_model=UserRead)
def update_user(user_id: int, payload: UserUpdate, db: Session = Depends(get_db)) -> User:
    user = db.query(User).filter(User.id == user_id).first()
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    existing_login = db.query(User).filter(User.login == payload.login, User.id != user_id).first()
    if existing_login:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="User with this login already exists")

    existing_email = db.query(User).filter(User.email == payload.email, User.id != user_id).first()
    if existing_email:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="User with this email already exists")

    user.login = payload.login.strip()
    user.password_hash = hash_password(payload.password)
    user.email = payload.email
    user.display_name = payload.display_name.strip() if payload.display_name else None
    db.commit()
    db.refresh(user)
    return user
