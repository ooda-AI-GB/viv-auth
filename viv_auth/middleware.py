from fastapi import Request


class NotAuthenticated(Exception):
    """Raised when a user is not authenticated."""
    pass


def create_require_auth(get_db, User, session_manager):
    """Factory that creates a require_auth FastAPI dependency."""
    from .session import COOKIE_NAME

    async def require_auth(request: Request):
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
