import hashlib
import secrets
from datetime import datetime, timedelta, timezone

from app.core.config import (
    ACCESS_TOKEN_EXPIRE_MINUTES,
    ALGORITHM,
    SECRET_KEY,
)

import jwt
from pwdlib import PasswordHash


# ============================================================
# Password Hashing
# ============================================================
password_hash = PasswordHash.recommended()

MAX_PASSWORD_BYTES = 72

def validate_password_length(password: str) -> None:
    """
    Validate password size before sending it to bcrypt.
    bcrypt supports a maximum of 72 bytes.
    """

    if len(password.encode("utf-8")) > MAX_PASSWORD_BYTES:
        raise ValueError(
            "Password must not exceed 72 bytes"
        )

# Hash a plain-text password
def hash_password(password: str) -> str:
    """
    Hash a plain-text password.
    """

    validate_password_length(password)

    return password_hash.hash(password)



# Verify a password against its hash
def verify_password(
    password: str,
    hashed_password: str,
) -> bool:
    """
    Verify a plain-text password against its hash.
    """

    validate_password_length(password)

    return password_hash.verify(
        password,
        hashed_password,
    )






# ============================================================
# JWT Access Token
# ============================================================

def create_access_token(user_id: str) -> str:
    """
    Create a JWT access token.
    """

    expire = datetime.now(timezone.utc) + timedelta(
        minutes=ACCESS_TOKEN_EXPIRE_MINUTES
    )

    payload = {
        "sub": user_id,
        "exp": expire,
    }

    token = jwt.encode(
        payload,
        SECRET_KEY,
        algorithm=ALGORITHM,
    )

    return token

# ============================================================
# Refresh Token
# ============================================================

def create_refresh_token() -> str:
    """
    Generate a secure refresh token.
    """

    return secrets.token_urlsafe(64)


def hash_refresh_token(token: str) -> str:
    """
    Hash refresh token before storing it.
    """

    return hashlib.sha256(
        token.encode("utf-8")
    ).hexdigest()

# ============================================================
# Secure Token
# ============================================================

def create_secure_token() -> str:
    """
    Generate a cryptographically secure token.
    """

    return secrets.token_urlsafe(64)


def hash_token(token: str) -> str:
    """
    SHA-256 hash for secure tokens.
    """

    return hashlib.sha256(
        token.encode("utf-8")
    ).hexdigest()

# ============================================================
# Password Reset Token
# ============================================================

def generate_password_reset_token() -> str:
    """
    Generate a password reset token.
    """

    return secrets.token_urlsafe(32)


def hash_password_reset_token(token: str) -> str:
    """
    Hash password reset token before storing it.
    """

    return hashlib.sha256(
        token.encode("utf-8")
    ).hexdigest()
