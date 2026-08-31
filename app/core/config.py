import os


# JWT secret key
SECRET_KEY = os.getenv(
    "SECRET_KEY",
    "dev-secret-change-this-in-production",
)

# JWT signing algorithm
ALGORITHM = "HS256"

# Access token lifetime
ACCESS_TOKEN_EXPIRE_MINUTES = 30
