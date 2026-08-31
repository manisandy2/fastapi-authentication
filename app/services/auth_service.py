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
from app.core.time import utc_now
from app.core.config import (
    EMAIL_VERIFICATION_EXPIRE_MINUTES,
    REFRESH_TOKEN_EXPIRE_DAYS,
)
from app.core.security import (
    create_secure_token,
    hash_token,
)
from app.models.email_verification_token import (
    EmailVerificationToken,
)

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
    verification_token = create_email_verification_token(
    db=db,
    user=user,
    )
    # Development only:
    print(
    f"EMAIL VERIFICATION TOKEN: {verification_token}"
    )



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
        revoked=False,
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

def refresh_user_tokens(
    db: Session,
    raw_refresh_token: str,
) -> dict:

    # Hash the token supplied by the client
    token_hash = hash_refresh_token(
        raw_refresh_token
    )

    # Find token record
    stored_token = (
        db.query(RefreshToken)
        .filter(
            RefreshToken.token_hash == token_hash
        )
        .first()
    )

    # Don't reveal whether the token exists
    if not stored_token:
        raise ValueError("Invalid refresh token")

    # Already used/revoked
    if stored_token.revoked:
        raise ValueError("Invalid refresh token")

    # Check expiration
    now = datetime.now(timezone.utc)

    # SQLite may return a naive datetime
    expires_at = stored_token.expires_at

    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(
            tzinfo=timezone.utc
        )

    if expires_at <= now:
        raise ValueError("Refresh token expired")

    # Find user
    user = (
        db.query(User)
        .filter(User.id == stored_token.user_id)
        .first()
    )

    if not user:
        raise ValueError("Invalid refresh token")

    # Check account
    if not user.is_active:
        raise ValueError("User account is inactive")

    # Revoke OLD refresh token
    stored_token.revoked = True
    stored_token.revoked_at = datetime.utcnow()

    db.commit()

    # Create NEW access token
    access_token = create_access_token(
        user_id=user.id
    )

    # Create NEW refresh token
    new_refresh_token = create_user_refresh_token(
        db=db,
        user=user,
    )

    return {
        "access_token": access_token,
        "refresh_token": new_refresh_token,
        "token_type": "bearer",
    }

def logout_user(
    db: Session,
    raw_refresh_token: str,
) -> None:

    # Hash the refresh token supplied by the client
    token_hash = hash_refresh_token(
        raw_refresh_token
    )

    # Find the refresh token
    stored_token = (
        db.query(RefreshToken)
        .filter(
            RefreshToken.token_hash == token_hash
        )
        .first()
    )

    # If token doesn't exist, simply return.
    # This avoids revealing token information.
    if not stored_token:
        return

    # Already revoked
    if stored_token.revoked:
        return

    # Revoke token
    stored_token.revoked = True
    stored_token.revoked_at = utc_now()

    db.commit()


def create_email_verification_token(
    db: Session,
    user: User,
) -> str:

    # Generate secure random token
    raw_token = create_secure_token()

    # Store only token hash
    token_hash = hash_token(raw_token)

    # Token expiration
    expires_at = (
        utc_now()
        + timedelta(
            minutes=EMAIL_VERIFICATION_EXPIRE_MINUTES
        )
    )

    verification_token = EmailVerificationToken(
        user_id=user.id,
        token_hash=token_hash,
        expires_at=expires_at,
        used=False,
    )

    db.add(verification_token)
    db.commit()

    # Return raw token for email delivery
    return raw_token

def verify_email(
    db: Session,
    raw_token: str,
) -> User:

    # Hash supplied token
    token_hash = hash_token(raw_token)

    # Find token
    verification_token = (
        db.query(EmailVerificationToken)
        .filter(
            EmailVerificationToken.token_hash
            == token_hash
        )
        .first()
    )

    if not verification_token:
        raise ValueError("Invalid verification token")

    # Prevent token reuse
    if verification_token.used:
        raise ValueError("Verification token already used")

    # Check expiration
    expires_at = verification_token.expires_at

    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(
            tzinfo=timezone.utc
        )

    if expires_at <= utc_now():
        raise ValueError("Verification token expired")

    # Find user
    user = (
        db.query(User)
        .filter(
            User.id == verification_token.user_id
        )
        .first()
    )

    if not user:
        raise ValueError("Invalid verification token")

    # Verify user
    user.is_verified = True

    # Mark token as used
    verification_token.used = True
    verification_token.used_at = utc_now()

    db.commit()
    db.refresh(user)

    return user