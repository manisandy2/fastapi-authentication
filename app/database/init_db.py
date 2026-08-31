from app.database.database import engine
from app.database.base import Base
from app.models.user import User


# Create all database tables
Base.metadata.create_all(bind=engine)

print("Database created successfully")
