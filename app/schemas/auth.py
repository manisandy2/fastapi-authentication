from pydantic import BaseModel, EmailStr


# Login request
class LoginRequest(BaseModel):
    email: EmailStr
    password: str


# JWT token response
class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"

# Refresh request
class RefreshRequest(BaseModel):
    refresh_token: str


class LogoutRequest(BaseModel):
    refresh_token: str

class EmailVerificationRequest(BaseModel):
    token: str