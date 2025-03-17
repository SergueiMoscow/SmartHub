from sqlalchemy import select
from smarthub.db.connector import AsyncSession
from smarthub.db.models import User


class UserRepository:
    async def get_user_by_username(self, username: str) -> User | None:
        async with AsyncSession() as session:
            result = await session.execute(select(User).filter(User.username == username))
            return result.scalar_one_or_none()
