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
def login(
    login_data: LoginRequest,
    db: Session = Depends(get_db),
):

    try:

        tokens = login_user(
            db=db,
            email=login_data.email,
            password=login_data.password,
        )

        return tokens

    except ValueError as exc:

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