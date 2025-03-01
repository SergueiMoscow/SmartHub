from logging.config import fileConfig

from sqlalchemy import engine_from_config, text
from sqlalchemy import pool

from alembic import context
from sqlalchemy.sql.ddl import CreateSchema

from smarthub.db import models
from smarthub.db.db import db_url
from smarthub.settings import settings

# this is the Alembic Config object, which provides
# access to the values within the .ini file in use.
config = context.config

# Interpret the config file for Python logging.
# This line sets up loggers basically.
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# add your model's MetaData object here
# for 'autogenerate' support
# from myapp import mymodel
# target_metadata = mymodel.Base.metadata
# changed target_metadata by sss (1 string)
# target_metadata = None
target_metadata = models.Base.metadata

# other values from the config, defined by the needs of env.py,
# can be acquired:
# my_important_option = config.get_main_option("my_important_option")
# ... etc.


def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode.

    This configures the context with just a URL
    and not an Engine, though an Engine is acceptable
    here as well.  By skipping the Engine creation
    we don't even need a DBAPI to be available.

    Calls to context.execute() here emit the given string to the
    script output.

    """
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations in 'online' mode.

    In this scenario we need to create an Engine
    and associate a connection with the context.

    """
    # added by ssss
    configuration = config.get_section(config.config_ini_section)
    configuration['sqlalchemy.url'] = db_url
    # end added by sss

    connectable = engine_from_config(
        # changed by sss
        # config.get_section(config.config_ini_section, {}),
        configuration,
        # end changed by sss
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        # added by sss
        connection = connection.execution_options(
            isolation_level='AUTOCOMMIT', schema_translate_map={None: settings.DATABASE_SCHEMA}
        )
        if not connection.dialect.has_schema(connection, settings.DATABASE_SCHEMA):
            connection.execute(CreateSchema(settings.DATABASE_SCHEMA))
        connection.execute(text(f'SET search_path TO {settings.DATABASE_SCHEMA}'))

        # end added by sss
        context.configure(
            connection=connection, target_metadata=target_metadata
        )

        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
