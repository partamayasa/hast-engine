# backend/db/session.py
"""Factory engine/sesi. Backend adalah satu-satunya komponen yang membuka basis data."""
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from sqlalchemy import create_engine, event
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from backend.core.settings import get_settings

_ENGINES: dict[str, Engine] = {}


def _configure_sqlite(engine: Engine) -> None:
    @event.listens_for(engine, "connect")
    def _set_pragmas(dbapi_conn, _record):  # pragma: no cover - dijalankan secara implisit
        cur = dbapi_conn.cursor()
        # WAL memungkinkan API membaca saat penulisan sedang berlangsung (pemakaian DSS oleh banyak pengguna).
        cur.execute("PRAGMA journal_mode=WAL")
        cur.execute("PRAGMA foreign_keys=ON")
        cur.execute("PRAGMA busy_timeout=5000")
        cur.close()


def sqlite_url_for(path: str | Path) -> str:
    return f"sqlite:///{Path(path).resolve().as_posix()}"


def get_engine(url: str | None = None) -> Engine:
    url = url or get_settings().database_url
    if url not in _ENGINES:
        if url.startswith("sqlite"):
            db_file = url.replace("sqlite:///", "", 1)
            if db_file and db_file != ":memory:":
                Path(db_file).parent.mkdir(parents=True, exist_ok=True)
            engine = create_engine(url, connect_args={"check_same_thread": False}, future=True)
            _configure_sqlite(engine)
        else:
            engine = create_engine(url, pool_pre_ping=True, future=True)
        _ENGINES[url] = engine
    return _ENGINES[url]


def dispose_engine(url: str) -> None:
    engine = _ENGINES.pop(url, None)
    if engine is not None:
        engine.dispose()


def get_sessionmaker(url: str | None = None) -> sessionmaker[Session]:
    return sessionmaker(bind=get_engine(url), expire_on_commit=False, future=True)


@contextmanager
def session_scope(url: str | None = None) -> Iterator[Session]:
    """Cakupan transaksi untuk skrip/pipeline di luar FastAPI."""
    session = get_sessionmaker(url)()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
