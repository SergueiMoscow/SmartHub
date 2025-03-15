# admin.py
from sqladmin import ModelView
from sqladmin.authentication import AuthenticationBackend
from passlib.context import CryptContext
from sqlalchemy import select

from smarthub.db.connector import AsyncSession
from smarthub.db.models import User
from smarthub.settings import settings

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

class AdminAuth(AuthenticationBackend):
    def __init__(self):
        super().__init__(secret_key=settings.KEY)  # Корректно передаём secret_key

    async def login(self, request):
        form = await request.form()
        username, password = form["username"], form["password"]
        async with AsyncSession() as session:
            user = await session.execute(
                select(User).filter(User.username == username)
            )
            user = user.scalar_one_or_none()
            if user and pwd_context.verify(password, user.hashed_password):
                request.session.update({"user_id": user.id})
                return True
        return False

    async def logout(self, request):
        request.session.clear()
        return True

    async def authenticate(self, request):
        user_id = request.session.get("user_id")
        if not user_id:
            return False
        async with AsyncSession() as session:
            user = await session.get(User, user_id)
            return bool(user)

class UserAdmin(ModelView, model=User):  # Новый синтаксис для версии 0.20.1
    column_list = ["id", "username"]
    name = "User"  # Имя модели в админке
    name_plural = "Users"  # Множественное имя для отображения
