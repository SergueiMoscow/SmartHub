from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
from datetime import datetime, timedelta, timezone
from pydantic import BaseModel
from typing import Annotated

from smarthub.db.models import User
from smarthub.settings import settings
from smarthub.repositories.user_repository import UserRepository

# Настройка хеширования паролей
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Модель для ответа с токенами
class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str


class AuthService:
    def __init__(self, user_repo: UserRepository = Depends()):
        self.user_repo = user_repo

    def verify_password(self, plain_password: str, hashed_password: str) -> bool:
        return pwd_context.verify(plain_password, hashed_password)

    def create_access_token(self, data: dict, expires_delta: timedelta) -> str:
        to_encode = data.copy()
        expire = datetime.now(timezone.utc) + expires_delta
        to_encode.update({"exp": expire})
        return jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)

    def create_refresh_token(self, data: dict, expires_delta: timedelta) -> str:
        to_encode = data.copy()
        expire = datetime.now(timezone.utc) + expires_delta
        to_encode.update({"exp": expire})
        return jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)

    async def authenticate_user(self, username: str, password: str) -> User | None:
        user = await self.user_repo.get_user_by_username(username)
        if not user or not self.verify_password(password, user.hashed_password):
            return None
        return user

    async def login(self, username: str, password: str) -> TokenResponse | None:
        user = await self.authenticate_user(username, password)
        if not user:
            return None
        access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
        refresh_token_expires = timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
        access_token = self.create_access_token(
            data={"sub": user.username}, expires_delta=access_token_expires
        )
        refresh_token = self.create_refresh_token(
            data={"sub": user.username}, expires_delta=refresh_token_expires
        )
        return TokenResponse(
            access_token=access_token,
            refresh_token=refresh_token,
            token_type="bearer",
        )

    async def refresh_token(self, refresh_token: str) -> str | None:
        try:
            payload = jwt.decode(refresh_token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
            username: str = payload.get("sub")
            if username is None:
                return None
        except JWTError:
            return None
        user = await self.user_repo.get_user_by_username(username)
        if user is None:
            return None
        access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
        return self.create_access_token(
            data={"sub": user.username}, expires_delta=access_token_expires
        )

    @staticmethod
    async def get_current_user(
        token: Annotated[str, Depends(OAuth2PasswordBearer(tokenUrl="/api/token"))],
        user_repo: Annotated[UserRepository, Depends()],
    ) -> User:
        credentials_exception = HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
        try:
            payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
            username: str = payload.get("sub")
            if username is None:
                raise credentials_exception
        except JWTError:
            raise credentials_exception
        user = await user_repo.get_user_by_username(username)
        if user is None:
            raise credentials_exception
        return user
