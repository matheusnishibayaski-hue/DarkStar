"""Camada de banco de dados (PostgreSQL via SQLAlchemy)."""

from backend.database.db import get_engine, get_session, init_db, session_scope

__all__ = ["get_engine", "get_session", "init_db", "session_scope"]
