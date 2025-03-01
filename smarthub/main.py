from fastapi import FastAPI
from contextlib import asynccontextmanager
from smarthub.mqtt.mqtt_client import start_mqtt_client, stop_mqtt_client
from smarthub.settings import settings
import uvicorn

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Запускаем MQTT-клиент
    app.state.mqtt_client = await start_mqtt_client()
    yield
    # Останавливаем MQTT-клиент при завершении
    await stop_mqtt_client(app.state.mqtt_client)

app = FastAPI(lifespan=lifespan)

@app.get("/")
async def root():
    return {"message": "SmartHub is running!"}

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=settings.APP_PORT)
