import hashlib
import secrets
from datetime import datetime, timedelta, timezone

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, String


def create_auth_models(Base):
    """Factory that creates User, MagicToken, and ApiKey models bound to the app's Base."""

    class User(Base):
        __tablename__ = "users"

        id = Column(Integer, primary_key=True, index=True)
        email = Column(String, unique=True, nullable=False, index=True)
        name = Column(String, nullable=True)
        is_active = Column(Boolean, default=True, nullable=False)
        created_at = Column(
            DateTime, default=lambda: datetime.now(timezone.utc), nullable=False
        )

    class MagicToken(Base):
        __tablename__ = "magic_tokens"

        id = Column(Integer, primary_key=True, index=True)
        token = Column(
            String, unique=True, nullable=False, index=True, default=lambda: secrets.token_urlsafe(32)
        )
        user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
        used = Column(Boolean, default=False, nullable=False)
        expires_at = Column(DateTime, nullable=False)
        created_at = Column(
            DateTime, default=lambda: datetime.now(timezone.utc), nullable=False
        )

        @classmethod
        def create(cls, user_id: int, expiry_minutes: int = 15):
            return cls(
                user_id=user_id,
                expires_at=datetime.now(timezone.utc) + timedelta(minutes=expiry_minutes),
            )

        def is_valid(self) -> bool:
            now = datetime.now(timezone.utc)
            expires = self.expires_at
            # SQLite strips timezone info — make both naive for comparison
            if expires.tzinfo is None:
                now = now.replace(tzinfo=None)
            return not self.used and now < expires

    class ApiKey(Base):
        __tablename__ = "api_keys"

        id = Column(Integer, primary_key=True, index=True)
        key_prefix = Column(String(16), nullable=False)
        key_hash = Column(String(128), unique=True, nullable=False, index=True)
        name = Column(String(128), nullable=False)
        user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
        created_at = Column(
            DateTime, default=lambda: datetime.now(timezone.utc), nullable=False
        )
        last_used_at = Column(DateTime, nullable=True)
        revoked_at = Column(DateTime, nullable=True)

        @classmethod
        def create(cls, user_id: int, name: str, raw_key: str):
            return cls(
                user_id=user_id,
                name=name,
                key_prefix=raw_key[:16],
                key_hash=hashlib.sha256(raw_key.encode()).hexdigest(),
            )

    return User, MagicToken, ApiKey
