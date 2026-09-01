from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.database.database import get_db
from app.schemas.user import UserCreate, UserResponse
from app.services.auth_service import create_user,login_user,refresh_user_tokens
from app.schemas.auth import LoginRequest, TokenResponse,RefreshRequest
from app.services.auth_service import login_user

from app.dependencies.auth import get_current_user
from app.models.user import User
from app.schemas.auth import LogoutRequest
from app.services.auth_service import logout_user
from app.schemas.auth import (
    EmailVerificationRequest,
)
from app.services.auth_service import (
    verify_email,
)
# from app.database import get_db
from app.models.password_reset_token import PasswordResetToken
from app.models.user import User
from app.schemas.password_reset import ForgotPasswordRequest
from app.schemas.password_reset import ResetPasswordRequest
from datetime import datetime, timedelta, timezone
from fastapi import APIRouter, HTTPException, Request
from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import (
    generate_password_reset_token,
    hash_password_reset_token,
    hash_password
)
from app.schemas.password_reset import (
    ForgotPasswordRequest,
    ResetPasswordRequest,
)

from fastapi import Request
from app.core.rate_limit import check_rate_limit
from app.core.config import (
    RESET_PASSWORD_LIMIT,
    RESET_PASSWORD_WINDOW,
)

from app.services.rate_limiter import (
    is_login_blocked,
    record_failed_login,
    clear_failed_logins,
    get_login_retry_after,
    is_forgot_password_blocked,
    record_forgot_password_attempt,
    get_forgot_password_retry_after,
)

router = APIRouter(
    prefix="/auth",
    tags=["Authentication"],
)


@router.post(
    "/register",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
)
def register(
    user_data: UserCreate,
    db: Session = Depends(get_db),
):
    try:
        user = create_user(db, user_data)
        return user

    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(exc),
        )


@router.post(
    "/login",
    response_model=TokenResponse,
)
async def login(
    request: Request,
    login_data: LoginRequest,
    db: Session = Depends(get_db),
):
    ip_address = (
        request.client.host
        if request.client
        else "unknown"
    )

    email = login_data.email.strip().lower()

    # Check whether login is blocked
    blocked = await is_login_blocked(
        ip_address,
        email,
    )

    if blocked:
        retry_after = await get_login_retry_after(
            ip_address,
            email,
        )

        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many failed login attempts. Please try again later.",
            headers={
                "Retry-After": str(retry_after),
            },
        )

    try:

        tokens = login_user(
            db=db,
            email=email,
            password=login_data.password,
        )

        # Successful login → clear failed attempts
        await clear_failed_logins(
            ip_address,
            email,
        )

        return tokens

    except ValueError as exc:

        # Failed login → record attempt
        attempts = await record_failed_login(
            ip_address,
            email,
        )

        # Block after maximum attempts
        if attempts >= 5:
            retry_after = await get_login_retry_after(
                ip_address,
                email,
            )

            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Too many failed login attempts. Please try again later.",
                headers={
                    "Retry-After": str(retry_after),
                },
            )

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(exc),
            headers={
                "WWW-Authenticate": "Bearer",
            },
        )

@router.get(
    "/me",
    response_model=UserResponse,
)
def get_me(
    current_user: User = Depends(get_current_user),
):
    return current_user

@router.post(
    "/refresh",
    response_model=TokenResponse,
)
def refresh_token(
    refresh_data: RefreshRequest,
    db: Session = Depends(get_db),
):

    try:

        tokens = refresh_user_tokens(
            db=db,
            raw_refresh_token=refresh_data.refresh_token,
        )

        return tokens

    except ValueError as exc:

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(exc),
        )


@router.post("/logout")
def logout(
    logout_data: LogoutRequest,
    db: Session = Depends(get_db),
):
    logout_user(
        db=db,
        raw_refresh_token=logout_data.refresh_token,
    )

    return {
        "success": True,
        "message": "Logged out successfully",
    }

@router.post("/verify-email")
def verify_user_email(
    verification_data: EmailVerificationRequest,
    db: Session = Depends(get_db),
):

    try:

        user = verify_email(
            db=db,
            raw_token=verification_data.token,
        )

        return {
            "success": True,
            "message": "Email verified successfully",
            "user_id": user.id,
        }

    except ValueError as exc:

        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        )

@router.post("/forgot-password")
async def forgot_password(
    request: Request,
    data: ForgotPasswordRequest,
    db: Session = Depends(get_db),
):
    ip_address = (
        request.client.host
        if request.client
        else "unknown"
    )

    email = data.email.strip().lower()

    # Check rate limit
    blocked = await is_forgot_password_blocked(
        ip_address,
        email,
    )

    if blocked:
        retry_after = await get_forgot_password_retry_after(
            ip_address,
            email,
        )

        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many password reset requests. Please try again later.",
            headers={
                "Retry-After": str(retry_after),
            },
        )

    # Record the request
    attempts = await record_forgot_password_attempt(
        ip_address,
        email,
    )

    if attempts > 5:
        retry_after = await get_forgot_password_retry_after(
            ip_address,
            email,
        )

        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many password reset requests. Please try again later.",
            headers={
                "Retry-After": str(retry_after),
            },
        )

    result = db.execute(
        select(User).where(User.email == email)
    )

    user = result.scalar_one_or_none()

    # Do not reveal whether the email exists.
    if not user:
        return {
            "success": True,
            "message": "If the email exists, a password reset link has been sent.",
        }

    token = generate_password_reset_token()
    token_hash = hash_password_reset_token(token)

    expires_at = (
        datetime.utcnow()
        + timedelta(minutes=15)
    )

    reset_token = PasswordResetToken(
        user_id=user.id,
        token_hash=token_hash,
        expires_at=expires_at,
        used=False,
    )

    db.add(reset_token)
    db.commit()

    # Email sending will be connected here.
    reset_link = (
        f"http://localhost:3000/reset-password?token={token}"
    )

    # TEMPORARY DEVELOPMENT ONLY
    print(f"Password reset link: {reset_link}")

    return {
        "success": True,
        "link": reset_link,
        "message": "If the email exists, a password reset link has been sent.",
    }

@router.post("/reset-password")
def reset_password(
    data: ResetPasswordRequest,
    db: Session = Depends(get_db),
):
    token_hash = hash_password_reset_token(data.token)

    result = db.execute(
        select(PasswordResetToken).where(
            PasswordResetToken.token_hash == token_hash
        )
    )

    reset_token = result.scalar_one_or_none()

    if not reset_token:
        return {
            "success": False,
            "message": "Invalid or expired reset token.",
        }

    now = datetime.utcnow()


    if reset_token.used:
        return {
            "success": False,
            "message": "Invalid or expired reset token.",
        }

    if reset_token.expires_at <= now:
        return {
            "success": False,
            "message": "Invalid or expired reset token.",
        }

    result = db.execute(
        select(User).where(
            User.id == reset_token.user_id
        )
    )

    user = result.scalar_one_or_none()

    if not user:
        return {
            "success": False,
            "message": "Invalid or expired reset token.",
        }

    # Use your existing password hashing function
    user.password_hash = hash_password(data.new_password)

    # Make the token single-use
    reset_token.used = True

    db.commit()

    return {
        "success": True,
        "message": "Password reset successfully.",
    }



@router.post("/reset-password")
async def reset_password(
    request: Request,
    data: ResetPasswordRequest,
):
    client_ip = request.client.host

    rate_limit_key = f"rate_limit:reset_password:{client_ip}"

    allowed, retry_after = await check_rate_limit(
    key=rate_limit_key,
    limit=RESET_PASSWORD_LIMIT,
    window=RESET_PASSWORD_WINDOW,
)

    if not allowed:
        raise HTTPException(
            status_code=429,
            detail="Too many password reset attempts. Please try again later.",
            headers={"Retry-After": str(retry_after)},

        )

    # existing reset-password logic...