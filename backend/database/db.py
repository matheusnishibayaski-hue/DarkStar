"""Engine/sessão SQLAlchemy — usado pelo Intelligence Hub quando DATABASE_URL está definido."""

from __future__ import annotations

from contextlib import contextmanager
from typing import Generator

from sqlalchemy import create_engine
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from backend.config import DATABASE_URL

_engine: Engine | None = None
_SessionLocal: sessionmaker[Session] | None = None


def get_engine() -> Engine:
    """Retorna engine singleton. Raise se DATABASE_URL estiver vazio."""
    global _engine, _SessionLocal
    if not DATABASE_URL:
        raise RuntimeError("DATABASE_URL não configurado.")
    if _engine is None:
        _engine = create_engine(
            DATABASE_URL,
            pool_pre_ping=True,
            pool_size=5,
            max_overflow=10,
        )
        _SessionLocal = sessionmaker(bind=_engine, autoflush=False, autocommit=False)
    return _engine


def get_session() -> Session:
    get_engine()
    assert _SessionLocal is not None
    return _SessionLocal()


@contextmanager
def session_scope() -> Generator[Session, None, None]:
    """Context manager com commit/rollback."""
    session = get_session()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def init_db() -> None:
    """Cria tabelas do Intelligence Hub se ainda não existirem."""
    from backend.database.models_intelligence import Base

    engine = get_engine()
    Base.metadata.create_all(bind=engine)


def reset_engine_for_tests() -> None:
    """Reinicia singleton (apenas testes)."""
    global _engine, _SessionLocal
    if _engine is not None:
        _engine.dispose()
    _engine = None
    _SessionLocal = None
