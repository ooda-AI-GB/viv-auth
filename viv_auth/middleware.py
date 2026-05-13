import hashlib
import logging
import os
from datetime import datetime, timezone

from fastapi import Request

logger = logging.getLogger("viv_auth")

API_USER_EMAIL = "api@system.local"


class NotAuthenticated(Exception):
    """Raised when a user is not authenticated."""
    pass


def _check_api_token(request: Request) -> bool:
    """Check if request has a valid GDEV_API_TOKEN Bearer token."""
    token = os.environ.get("GDEV_API_TOKEN")
    if not token:
        return False
    auth_header = request.headers.get("authorization", "")
    if auth_header.startswith("Bearer "):
        return auth_header[7:] == token
    return False


def _get_or_create_api_user(db, User):
    """Get or create the system API user for token-based auth."""
    user = db.query(User).filter(User.email == API_USER_EMAIL).first()
    if not user:
        user = User(email=API_USER_EMAIL, is_active=True)
        db.add(user)
        db.commit()
        db.refresh(user)
        logger.info("[viv-auth] Created API system user (api@system.local)")
    return user


def _check_api_key_bearer(request, db, User, ApiKey):
    """Check if request has a valid per-user API key Bearer token.

    Returns User if valid, None otherwise.
    """
    auth_header = request.headers.get("authorization", "")
    if not auth_header.startswith("Bearer "):
        return None

    raw_key = auth_header[7:]
    if not raw_key.startswith("gbox_pk_"):
        return None

    key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
    api_key = (
        db.query(ApiKey)
        .filter(ApiKey.key_hash == key_hash, ApiKey.revoked_at.is_(None))
        .first()
    )
    if api_key is None:
        return None

    user = db.query(User).filter(User.id == api_key.user_id).first()
    if user is None or not user.is_active:
        return None

    # Update last_used_at
    api_key.last_used_at = datetime.now(timezone.utc)
    db.commit()

    # Refresh user so attributes survive session close (commit expires objects)
    db.refresh(user)
    return user


def create_require_auth(get_db, User, session_manager, ApiKey=None):
    """Factory that creates a require_auth FastAPI dependency."""
    from .session import COOKIE_NAME

    async def require_auth(request: Request):
        # 1. Check GDEV_API_TOKEN Bearer token (service-to-service)
        if _check_api_token(request):
            db = next(get_db())
            try:
                user = _get_or_create_api_user(db, User)
                request.state.api_token_auth = True
                return user
            finally:
                db.close()

        # 2. Per-user API key (if enabled)
        if ApiKey is not None:
            db = next(get_db())
            try:
                user = _check_api_key_bearer(request, db, User, ApiKey)
                if user:
                    request.state.api_token_auth = True
                    return user
            finally:
                db.close()

        # 3. Fall back to session cookie
        token = request.cookies.get(COOKIE_NAME)
        if not token:
            raise NotAuthenticated()

        user_id = session_manager.verify_session(token)
        if user_id is None:
            raise NotAuthenticated()

        db = next(get_db())
        try:
            user = db.query(User).filter(User.id == user_id).first()
            if user is None:
                raise NotAuthenticated()
            return user
        finally:
            db.close()

    return require_auth
