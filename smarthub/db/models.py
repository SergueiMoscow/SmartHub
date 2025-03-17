import datetime

from sqlalchemy.orm import declarative_base
from sqlalchemy import Column, String, DateTime, BigInteger, Integer

from smarthub.settings import settings

Base = declarative_base()

# Модель пользователя
class User(Base):
    __tablename__ = "users"
    __table_args__ = {"schema": settings.DATABASE_SCHEMA}  # Указываем схему
    id = Column(Integer, primary_key=True)
    username = Column(String, unique=True, nullable=False)
    hashed_password = Column(String)

# class User(SQLAlchemyBaseUserTableUUID, Base):
#     username = Column(String, unique=True, nullable=False)

class DeviceData(Base):
    __tablename__ = "device_data"

    id = Column(BigInteger, primary_key=True, autoincrement=True)
    object = Column(String, nullable=False)
    room = Column(String, nullable=False)
    device = Column(String, nullable=False)
    state = Column(String, nullable=False)
    module = Column(String, nullable=False)
    value = Column(String, nullable=False)
    timestamp = Column(DateTime, nullable=False, default=datetime.datetime.now)
