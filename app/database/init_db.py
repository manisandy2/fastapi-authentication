from app.database.database import engine
from app.database.base import Base
from app.models.user import User
from app.models.refresh_token import RefreshToken


# Create all database tables
Base.metadata.create_all(bind=engine)

print("Database created successfully")
