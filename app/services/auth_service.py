from sqlalchemy import or_
from sqlalchemy.orm import Session

from app.core.security import hash_password
from app.models.user import User
from app.schemas.user import UserCreate
from app.core.security import (
    create_access_token,
    create_refresh_token,
    hash_password,
    hash_refresh_token,
    verify_password,
)
from datetime import datetime, timezone,timedelta
from app.core.config import REFRESH_TOKEN_EXPIRE_DAYS
from app.models.refresh_token import RefreshToken

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

def create_user_refresh_token(
    db: Session,
    user: User,
) -> str:

    # Generate secure random refresh token
    raw_token = create_refresh_token()

    # Store only its hash
    token_hash = hash_refresh_token(raw_token)

    expires_at = (
        datetime.now(timezone.utc)
        + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    )

    refresh_token = RefreshToken(
        user_id=user.id,
        token_hash=token_hash,
        expires_at=expires_at,
    )

    db.add(refresh_token)
    db.commit()

    return raw_token

def login_user(
    db: Session,
    email: str,
    password: str,
) -> dict:

    user = authenticate_user(
        db=db,
        email=email,
        password=password,
    )

    access_token = create_access_token(
        user_id=user.id,
    )

    refresh_token = create_user_refresh_token(
        db=db,
        user=user,
    )

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
    }