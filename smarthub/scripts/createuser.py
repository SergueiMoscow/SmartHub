# create_user.py
import asyncio
from sqlalchemy.future import select
from passlib.context import CryptContext

from smarthub.db.connector import AsyncSession
from smarthub.db.models import User

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

async def create_user(username: str, password: str):
    async with AsyncSession() as session:
        # Проверяем, существует ли пользователь
        result = await session.execute(select(User).filter(User.username == username))
        if result.scalar_one_or_none():
            print(f"User {username} already exists!")
            return

        # Создаём нового пользователя
        hashed_password = pwd_context.hash(password)
        new_user = User(username=username, hashed_password=hashed_password)
        session.add(new_user)
        await session.commit()
        print(f"User {username} created successfully!")

if __name__ == "__main__":
    asyncio.run(create_user("sergey", "Olga_Feb1068"))
