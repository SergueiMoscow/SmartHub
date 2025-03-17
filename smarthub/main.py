from fastapi import FastAPI
from contextlib import asynccontextmanager

from sqladmin import Admin

from smarthub.db.db import engine
from smarthub.mqtt.mqtt_client import start_mqtt_client, stop_mqtt_client
from smarthub.services.admin import AdminAuth, UserAdmin
from smarthub.settings import settings
from smarthub.api.router import router
import uvicorn

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Запускаем MQTT-клиент
    app.state.mqtt_client = await start_mqtt_client()
    yield
    # Останавливаем MQTT-клиент при завершении
    await stop_mqtt_client(app.state.mqtt_client)

app = FastAPI(lifespan=lifespan)
admin = Admin(app, engine, authentication_backend=AdminAuth())
admin.add_view(UserAdmin)

app.include_router(router, prefix="/api")  # Добавляем префикс /api для всех маршрутов

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=settings.APP_PORT)