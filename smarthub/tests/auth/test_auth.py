import pytest
from unittest.mock import AsyncMock, MagicMock
from datetime import datetime, timedelta, timezone
from fastapi import HTTPException
from jose import jwt, JWTError
from pydantic import ValidationError

from smarthub.services.auth import AuthService, TokenResponse, pwd_context
from smarthub.db.models import User
from smarthub.settings import settings
from smarthub.repositories.user_repository import UserRepository
from smarthub.db.connector import AsyncSession
from smarthub.tests.conftest import apply_migrations


def test_verify_password(auth_service):
    plain_password = "testpassword"
    hashed_password = pwd_context.hash(plain_password)
    assert auth_service.verify_password(plain_password, hashed_password) is True
    assert auth_service.verify_password("wrongpassword", hashed_password) is False


# Тест создания access-токена
def test_create_access_token(auth_service):
    data = {"sub": "testuser"}
    expires_delta = timedelta(minutes=15)
    token = auth_service.create_access_token(data, expires_delta)

    payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
    assert payload["sub"] == "testuser"
    assert "exp" in payload
    # deprecated
    # assert datetime.utcfromtimestamp(payload["exp"]) > datetime.utcnow()
    assert datetime.fromtimestamp(payload["exp"], timezone.utc) > datetime.now(timezone.utc)


# Тест создания refresh-токена
def test_create_refresh_token(auth_service):
    data = {"sub": "testuser"}
    expires_delta = timedelta(days=7)
    token = auth_service.create_refresh_token(data, expires_delta)

    payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
    assert payload["sub"] == "testuser"
    assert "exp" in payload
    assert datetime.fromtimestamp(payload["exp"], timezone.utc) > datetime.now(timezone.utc)

# Асинхронные тесты
@pytest.mark.asyncio
async def test_authenticate_user_success(auth_service):
    # Мокаем пользователя
    user = User(username="testuser", hashed_password=pwd_context.hash("testpassword"))
    auth_service.user_repo.get_user_by_username.return_value = user

    result = await auth_service.authenticate_user("testuser", "testpassword")
    assert result == user


@pytest.mark.asyncio
async def test_authenticate_user_failure(auth_service):
    # Пользователь не найден
    auth_service.user_repo.get_user_by_username.return_value = None
    result = await auth_service.authenticate_user("testuser", "testpassword")
    assert result is None

    # Неверный пароль
    user = User(username="testuser", hashed_password=pwd_context.hash("testpassword"))
    auth_service.user_repo.get_user_by_username.return_value = user
    result = await auth_service.authenticate_user("testuser", "wrongpassword")
    assert result is None


@pytest.mark.asyncio
async def test_login_success(auth_service):
    user = User(username="testuser", hashed_password=pwd_context.hash("testpassword"))
    auth_service.user_repo.get_user_by_username.return_value = user

    response = await auth_service.login("testuser", "testpassword")
    assert isinstance(response, TokenResponse)
    assert response.token_type == "bearer"
    assert response.access_token is not None
    assert response.refresh_token is not None

    # Проверяем содержимое токенов
    access_payload = jwt.decode(response.access_token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
    refresh_payload = jwt.decode(response.refresh_token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
    assert access_payload["sub"] == "testuser"
    assert refresh_payload["sub"] == "testuser"


@pytest.mark.asyncio
async def test_login_failure(auth_service):
    auth_service.user_repo.get_user_by_username.return_value = None
    response = await auth_service.login("testuser", "wrongpassword")
    assert response is None


@pytest.mark.asyncio
async def test_refresh_token_success(auth_service):
    user = User(username="testuser", hashed_password=pwd_context.hash("testpassword"))
    refresh_token = auth_service.create_refresh_token({"sub": "testuser"}, timedelta(days=7))
    auth_service.user_repo.get_user_by_username.return_value = user

    new_access_token = await auth_service.refresh_token(refresh_token)
    assert new_access_token is not None
    payload = jwt.decode(new_access_token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
    assert payload["sub"] == "testuser"


@pytest.mark.asyncio
async def test_refresh_token_failure(auth_service):
    # Неверный токен
    invalid_token = "invalid.token.here"
    result = await auth_service.refresh_token(invalid_token)
    assert result is None

    # Пользователь не найден
    refresh_token = auth_service.create_refresh_token({"sub": "testuser"}, timedelta(days=7))
    auth_service.user_repo.get_user_by_username.return_value = None
    result = await auth_service.refresh_token(refresh_token)
    assert result is None


@pytest.mark.asyncio
async def test_get_current_user_success():
    user_repo = AsyncMock(spec=UserRepository)
    user = User(username="testuser", hashed_password="hashedpassword")
    user_repo.get_user_by_username.return_value = user
    token = jwt.encode({"sub": "testuser"}, settings.SECRET_KEY, algorithm=settings.ALGORITHM)

    result = await AuthService.get_current_user(token=token, user_repo=user_repo)
    assert result == user


@pytest.mark.asyncio
async def test_get_current_user_failure():
    user_repo = AsyncMock(spec=UserRepository)

    # Неверный токен
    with pytest.raises(HTTPException) as exc_info:
        await AuthService.get_current_user(token="invalid.token", user_repo=user_repo)
    assert exc_info.value.status_code == 401

    # Пользователь не найден
    token = jwt.encode({"sub": "testuser"}, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    user_repo.get_user_by_username.return_value = None
    with pytest.raises(HTTPException) as exc_info:
        await AuthService.get_current_user(token=token, user_repo=user_repo)
    assert exc_info.value.status_code == 401


# Тест с реальной БД
@pytest.mark.asyncio
@pytest.mark.usefixtures('apply_migrations')
async def test_authenticate_user_with_db():
    # Создаем сессию для записи пользователя
    async with AsyncSession() as session:
        user_repo = UserRepository()  # Репозиторий сам управляет сессиями внутри методов

        # Создаем тестового пользователя
        hashed_password = pwd_context.hash("testpassword")
        user = User(username="dbuser", hashed_password=hashed_password)

        # Вставляем пользователя напрямую через сессию, так как у UserRepository нет create_user
        session.add(user)
        await session.commit()

        # Проверяем аутентификацию через AuthService
        auth_service = AuthService(user_repo=user_repo)
        result = await auth_service.authenticate_user("dbuser", "testpassword")
        assert result is not None
        assert result.username == "dbuser"
