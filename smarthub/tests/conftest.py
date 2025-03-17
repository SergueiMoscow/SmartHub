import os
from unittest.mock import AsyncMock

import pytest
from httpx import AsyncClient
from typing import AsyncGenerator

from smarthub.db.connector import Session
from smarthub.main import app as main_app
from smarthub.db.models import Base, User
from smarthub.repositories.user_repository import UserRepository
from smarthub.services.auth import AuthService
from smarthub.settings import settings, ROOT_DIR
from sqlalchemy import text as sa_text, select
from alembic.config import Config
from alembic import command

@pytest.fixture
def apply_migrations():
    assert 'TEST' in settings.DATABASE_SCHEMA.upper(), 'Попытка использовать не тестовую схему.'
    alembic_ini = os.path.join(ROOT_DIR, 'alembic.ini')

    with Session() as session:
        session.execute(sa_text(f'CREATE SCHEMA IF NOT EXISTS {settings.DATABASE_SCHEMA};'))
        session.commit()

    alembic_cfg = Config(alembic_ini)
    alembic_cfg.set_main_option('script_location', os.path.join(ROOT_DIR, 'alembic'))
    command.downgrade(alembic_cfg, 'base')
    command.upgrade(alembic_cfg, 'head')

    yield command, alembic_cfg

    command.downgrade(alembic_cfg, 'base')

    with Session() as session:
        if 'TEST' in settings.DATABASE_SCHEMA.upper():
            session.execute(sa_text(f'DROP SCHEMA IF EXISTS {settings.DATABASE_SCHEMA} CASCADE;'))
            session.commit()
        else:
            raise Exception('Использование не тестовой схемы')


# Переопределяем зависимость UserRepository
@pytest.fixture
def user_repo(db_session):
    class TestUserRepository(UserRepository):
        async def get_user_by_username(self, username: str) -> User | None:
            result = await db_session.execute(
                select(User).filter(User.username == username)
            )
            return result.scalar_one_or_none()

    return TestUserRepository()


# Переопределяем AuthService
# @pytest.fixture
# def auth_service(user_repo):
#     return AuthService(user_repo=user_repo)

@pytest.fixture
def auth_service():
    user_repo = AsyncMock(spec=UserRepository)
    return AuthService(user_repo=user_repo)

# Фикстура для HTTP-клиента
@pytest.fixture
async def client(db_session) -> AsyncGenerator[AsyncClient, None]:
    async with AsyncClient(app=main_app, base_url="http://test") as c:
        yield c


# Создаем тестового пользователя
@pytest.fixture
async def test_user(db_session):
    user = User(
        username="testuser",
        hashed_password=AuthService().verify_password("testpassword", "hashed_password")
    )
    db_session.add(user)
    await db_session.commit()
    return user
