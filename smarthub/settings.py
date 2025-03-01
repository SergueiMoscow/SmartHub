from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

ROOT_DIR = Path(__file__).parent.parent
CACHE_COLLAGE_FILE = '.folder.jpg'
CACHE_COLLAGE_INFO = '.folder.json'


class Settings(BaseSettings):
    APP_PORT: int = 8000
    ROOT_DIR: Path = ROOT_DIR
    DB_DSN: str = ''
    DB_TEST_DSN: str = ''
    DATABASE_SCHEMA: str = 'public'
    KEY: str = ''
    SWAGGER_URL: str | None = None
    REDOC_URL: str | None = None
    # RabbitMQ
    RABBITMQ_HOST: str = 'localhost'
    RABBITMQ_PORT: int = 1883
    RABBITMQ_USER: str = 'guest'
    RABBITMQ_PASSWORD: str = 'guest'
    TOPIC: str = '#'

    PER_PAGE: int = 10
    model_config = SettingsConfigDict(
        env_file=ROOT_DIR / '.env',
        env_file_encoding='utf-8',
        extra='allow',
    )


settings = Settings()
