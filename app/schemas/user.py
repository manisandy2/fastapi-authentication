from pydantic import BaseModel, ConfigDict, EmailStr, Field


# Data received when creating a user
class UserCreate(BaseModel):
    email: EmailStr
    username: str = Field(min_length=3, max_length=50)
    password: str = Field(min_length=8, max_length=128)
    first_name: str | None = Field(default=None, max_length=100)
    last_name: str | None = Field(default=None, max_length=100)


# Data returned to the client
class UserResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    email: EmailStr
    username: str
    first_name: str | None
    last_name: str | None
    is_active: bool
    is_verified: bool
    role: str
