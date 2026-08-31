from pydantic import BaseModel, EmailStr


# Login request
class LoginRequest(BaseModel):
    email: EmailStr
    password: str


# JWT token response
class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
