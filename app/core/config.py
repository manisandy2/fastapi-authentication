import os

from dotenv import load_dotenv


# Load environment variables from .env
load_dotenv()


# JWT configuration
SECRET_KEY = os.getenv("SECRET_KEY")

ALGORITHM = os.getenv(
    "ALGORITHM",
    "HS256",
)

ACCESS_TOKEN_EXPIRE_MINUTES = int(
    os.getenv(
        "ACCESS_TOKEN_EXPIRE_MINUTES",
        "30",
    )
)
REFRESH_TOKEN_EXPIRE_DAYS = int(
    os.getenv(
        "REFRESH_TOKEN_EXPIRE_DAYS",
        "7",
    )
)

EMAIL_VERIFICATION_EXPIRE_MINUTES = int(
    os.getenv(
        "EMAIL_VERIFICATION_EXPIRE_MINUTES",
        "30",
    )
)

# Fail immediately if SECRET_KEY is missing
if not SECRET_KEY:
    raise RuntimeError(
        "SECRET_KEY is not configured. "
        "Add SECRET_KEY to your .env file."
    )

# ============================================================
# Security / CORS configuration
# ============================================================

ALLOWED_HOSTS = os.getenv(
    "ALLOWED_HOSTS",
    "localhost,127.0.0.1",
).split(",")

CORS_ORIGINS = os.getenv(
    "CORS_ORIGINS",
    "http://localhost:3000",
).split(",")
