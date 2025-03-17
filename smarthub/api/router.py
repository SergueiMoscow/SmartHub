from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel
from typing import Annotated

from smarthub.services.auth import AuthService, TokenResponse  # Импортируем из services
from smarthub.db.models import User

router = APIRouter()

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/token")

# Модель для входных данных в /token
class TokenRequest(BaseModel):
    username: str
    password: str

# Endpoints
@router.post("/token", response_model=TokenResponse)
async def login_for_access_token(
    form_data: TokenRequest,
    auth_service: Annotated[AuthService, Depends()],
):
    token_data = await auth_service.login(form_data.username, form_data.password)
    if not token_data:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return token_data

@router.post("/refresh")
async def refresh_access_token(
    refresh_token: str,
    auth_service: Annotated[AuthService, Depends()],
):
    access_token = await auth_service.refresh_token(refresh_token)
    if not access_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return {"access_token": access_token, "token_type": "bearer"}

@router.get("/")
async def root():
    return {"message": "SmartHub is running!"}

@router.get("/devices")
async def devices(
    current_user: Annotated[User, Depends(AuthService.get_current_user)],
):
    return {"message": f"Hello, {current_user.username}! This is the devices endpoint."}
