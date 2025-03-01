import datetime

from fastapi_users.db import SQLAlchemyBaseUserTableUUID
from sqlalchemy.ext.declarative import DeclarativeMeta, declarative_base
from sqlalchemy import Column, String, JSON, DateTime, BigInteger

Base = declarative_base()

class User(SQLAlchemyBaseUserTableUUID, Base):
    username = Column(String, unique=True, nullable=False)

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
