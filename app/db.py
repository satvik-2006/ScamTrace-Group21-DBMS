import os
from pathlib import Path
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker
from .models import Base

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_SQLITE = 'sqlite:///' + str((ROOT / 'scamtrace_demo.db').resolve()).replace('\\','/')

def make_engine(url=None):
    url = url or os.environ.get('DATABASE_URL', DEFAULT_SQLITE)
    args = {'connect_args': {'check_same_thread': False}} if url.startswith('sqlite') else {'pool_pre_ping': True}
    engine = create_engine(url, **args)
    if url.startswith('sqlite'):
        @event.listens_for(engine, 'connect')
        def _foreign_keys(con, _record):
            cursor = con.cursor(); cursor.execute('PRAGMA foreign_keys=ON'); cursor.close()
    return engine

def make_sessionmaker(engine):
    return sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)

def initialize(engine):
    Base.metadata.create_all(engine)
