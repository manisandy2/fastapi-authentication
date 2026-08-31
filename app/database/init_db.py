from app.database.database import engine
from app.database.base import Base
from app.models.user import User
from app.models.refresh_token import RefreshToken
from app.models.email_verification_token import EmailVerificationToken
from app.models.password_reset_token import PasswordResetToken

# Create all database tables
Base.metadata.create_all(bind=engine)

print("Database created successfully")
