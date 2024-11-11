from pydantic import BaseModel


class LoginResponse(BaseModel):
    access: str
    refresh: str


class RefreshJWTRequest(BaseModel):
    token: str


class RefreshJWTResponse(BaseModel):
    access: str
