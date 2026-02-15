import pytest
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, event
from sqlalchemy.orm import declarative_base, sessionmaker
from sqlalchemy.pool import StaticPool

from viv_auth import init_auth, AuthConfig


@pytest.fixture
def db_setup():
    """Create an in-memory SQLite engine with shared connection for testing."""
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base = declarative_base()
    SessionLocal = sessionmaker(bind=engine)

    def get_db():
        db = SessionLocal()
        try:
            yield db
        finally:
            db.close()

    return engine, Base, get_db, SessionLocal


@pytest.fixture
def app_with_auth(db_setup):
    """Create a FastAPI app with viv-auth initialized."""
    engine, Base, get_db, SessionLocal = db_setup
    app = FastAPI()

    User, require_auth = init_auth(
        app,
        engine,
        Base,
        get_db,
        app_name="Test App",
        config=AuthConfig(token_expiry_minutes=15, allow_signup=True),
    )

    @app.get("/protected")
    async def protected(user=Depends(require_auth)):
        return {"email": user.email, "user_id": user.id}

    @app.get("/api/data")
    async def api_data(user=Depends(require_auth)):
        return {"data": "secret"}

    return app, User, engine, SessionLocal, require_auth


@pytest.fixture
def client(app_with_auth):
    app, *_ = app_with_auth
    return TestClient(app)


@pytest.fixture
def db_session(app_with_auth):
    _, _, _, SessionLocal, _ = app_with_auth
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
