"""Alembic environment configuration."""

import os
from logging.config import fileConfig

from sqlalchemy import engine_from_config, pool

from alembic import context
from app.db.models import Base

config = context.config

if config.config_file_name is not None:
    # disable_existing_loggers defaults to True, which disables every logger
    # that already exists and is not named in alembic.ini. Migrations run
    # inside application startup, so that silenced app.routes.guard,
    # app.services.scheduler and the rest for the life of the process — every
    # capture failure, detector failure and scheduler error reported to an
    # operator went nowhere, while the code that reported them looked correct.
    fileConfig(config.config_file_name, disable_existing_loggers=False)

target_metadata = Base.metadata

db_url = os.environ.get("DB_URL")
if db_url:
    config.set_main_option("sqlalchemy.url", db_url)


def run_migrations_offline() -> None:
    url = config.get_main_option("sqlalchemy.url")
    context.configure(url=url, target_metadata=target_metadata, literal_binds=True)
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    with connectable.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata)
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
