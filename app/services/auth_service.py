from sqlalchemy import or_
from sqlalchemy.orm import Session

from app.core.security import hash_password
from app.models.user import User
from app.schemas.user import UserCreate
from app.core.security import (
    create_access_token,
    hash_password,
    verify_password,
)
from datetime import datetime, timezone

def create_user(db: Session, user_data: UserCreate) -> User:
    # Check whether email or username already exists
    existing_user = (
        db.query(User)
        .filter(
            or_(
                User.email == user_data.email,
                User.username == user_data.username,
            )
        )
        .first()
    )

    if existing_user:
        if existing_user.email == user_data.email:
            raise ValueError("Email already registered")

        if existing_user.username == user_data.username:
            raise ValueError("Username already registered")

    # Hash the password before storing it
    hashed_password = hash_password(user_data.password)

    # Create database user
    user = User(
        email=user_data.email,
        username=user_data.username,
        password_hash=hashed_password,
        first_name=user_data.first_name,
        last_name=user_data.last_name,
        role="user",
        is_active=True,
        is_verified=False,
    )

    # Save user
    db.add(user)
    db.commit()
    db.refresh(user)

    return user

def authenticate_user(
    db: Session,
    email: str,
    password: str,
) -> User:

    # Find user by email
    user = (
        db.query(User)
        .filter(User.email == email)
        .first()
    )

    # Do not reveal whether email exists
    if not user:
        raise ValueError("Invalid email or password")

    # Verify password
    if not verify_password(
        password,
        user.password_hash,
    ):
        raise ValueError("Invalid email or password")

    # Check account status
    if not user.is_active:
        raise ValueError("User account is inactive")

    # Update last login
    user.last_login_at = datetime.now(timezone.utc)

    db.commit()
    db.refresh(user)

    return user


def login_user(
    db: Session,
    email: str,
    password: str,
) -> str:

    user = authenticate_user(
        db=db,
        email=email,
        password=password,
    )

    return create_access_token(
        user_id=user.id,
    )