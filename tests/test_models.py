from datetime import datetime, timedelta, timezone

from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

from viv_auth.models import create_auth_models


def test_create_user():
    engine = create_engine("sqlite:///:memory:")
    Base = declarative_base()
    User, MagicToken = create_auth_models(Base)
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine)
    db = Session()

    user = User(email="test@example.com")
    db.add(user)
    db.commit()
    db.refresh(user)

    assert user.id is not None
    assert user.email == "test@example.com"
    assert user.is_active is True
    assert user.created_at is not None
    db.close()


def test_user_email_uniqueness():
    engine = create_engine("sqlite:///:memory:")
    Base = declarative_base()
    User, MagicToken = create_auth_models(Base)
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine)
    db = Session()

    db.add(User(email="dup@example.com"))
    db.commit()

    db.add(User(email="dup@example.com"))
    try:
        db.commit()
        assert False, "Should have raised IntegrityError"
    except Exception:
        db.rollback()
    db.close()


def test_magic_token_create():
    engine = create_engine("sqlite:///:memory:")
    Base = declarative_base()
    User, MagicToken = create_auth_models(Base)
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine)
    db = Session()

    user = User(email="token@example.com")
    db.add(user)
    db.commit()
    db.refresh(user)

    token = MagicToken.create(user.id, expiry_minutes=15)
    db.add(token)
    db.commit()
    db.refresh(token)

    assert token.token is not None
    assert len(token.token) > 20
    assert token.user_id == user.id
    assert token.used is False
    assert token.is_valid() is True
    db.close()


def test_magic_token_expired():
    engine = create_engine("sqlite:///:memory:")
    Base = declarative_base()
    User, MagicToken = create_auth_models(Base)
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine)
    db = Session()

    user = User(email="expired@example.com")
    db.add(user)
    db.commit()
    db.refresh(user)

    token = MagicToken(
        user_id=user.id,
        expires_at=datetime.now(timezone.utc) - timedelta(minutes=1),
    )
    db.add(token)
    db.commit()
    db.refresh(token)

    assert token.is_valid() is False
    db.close()


def test_magic_token_used():
    engine = create_engine("sqlite:///:memory:")
    Base = declarative_base()
    User, MagicToken = create_auth_models(Base)
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine)
    db = Session()

    user = User(email="used@example.com")
    db.add(user)
    db.commit()
    db.refresh(user)

    token = MagicToken.create(user.id)
    token.used = True
    db.add(token)
    db.commit()
    db.refresh(token)

    assert token.is_valid() is False
    db.close()
