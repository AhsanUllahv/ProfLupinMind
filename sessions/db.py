from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from sessions.models import Base


DEFAULT_DB_PATH = Path("sessions/proflupinmind.sqlite3")


def get_database_url(path: str | Path = DEFAULT_DB_PATH) -> str:
    db_path = Path(path)
    db_path.parent.mkdir(parents=True, exist_ok=True)
    return f"sqlite:///{db_path}"


def create_session_factory(path: str | Path = DEFAULT_DB_PATH):
    engine = create_engine(get_database_url(path), future=True)
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, expire_on_commit=False, future=True)
