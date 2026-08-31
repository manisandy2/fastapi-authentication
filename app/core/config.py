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

# Fail immediately if SECRET_KEY is missing
if not SECRET_KEY:
    raise RuntimeError(
        "SECRET_KEY is not configured. "
        "Add SECRET_KEY to your .env file."
    )
