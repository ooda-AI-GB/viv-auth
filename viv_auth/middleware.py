import logging
import os

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


def create_require_auth(get_db, User, session_manager):
    """Factory that creates a require_auth FastAPI dependency."""
    from .session import COOKIE_NAME

    async def require_auth(request: Request):
        # 1. Check GDEV_API_TOKEN Bearer token
        if _check_api_token(request):
            db = next(get_db())
            try:
                user = _get_or_create_api_user(db, User)
                request.state.api_token_auth = True
                return user
            finally:
                db.close()

        # 2. Fall back to session cookie
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
