import logging
import os
import secrets

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, RedirectResponse
from sqlalchemy import Engine

from .config import AuthConfig
from .middleware import NotAuthenticated, create_require_auth
from .models import create_auth_models
from .routes import create_auth_router
from .session import SessionManager

logger = logging.getLogger("viv_auth")

__all__ = ["init_auth", "AuthConfig", "NotAuthenticated"]


def init_auth(
    app: FastAPI,
    engine: Engine,
    Base,
    get_db,
    app_name: str = "App",
    app_url: str | None = None,
    config: AuthConfig | None = None,
):
    """Initialize viv-auth on a FastAPI app.

    Returns (User, require_auth) — the User model and a FastAPI dependency.
    """
    config = config or AuthConfig()

    # Create models
    User, MagicToken = create_auth_models(Base)

    # Session manager
    secret = os.environ.get("SESSION_SECRET")
    if not secret:
        secret = secrets.token_hex(32)
        logger.warning("[viv-auth] SESSION_SECRET not set — using random key (sessions won't survive restart)")
    session_manager = SessionManager(secret, max_age=config.session_max_age)

    # Auth router
    router = create_auth_router(
        get_db=get_db,
        User=User,
        MagicToken=MagicToken,
        session_manager=session_manager,
        app_name=app_name,
        app_url=app_url,
        config=config,
    )
    app.include_router(router)

    # require_auth dependency
    require_auth = create_require_auth(get_db, User, session_manager)

    # Exception handler for NotAuthenticated
    @app.exception_handler(NotAuthenticated)
    async def not_authenticated_handler(request: Request, exc: NotAuthenticated):
        if request.url.path.startswith("/api/"):
            return JSONResponse(status_code=401, content={"detail": "Not authenticated"})
        return RedirectResponse(url="/auth/login", status_code=303)

    # Create tables
    Base.metadata.create_all(bind=engine)

    logger.info(f"[viv-auth] Initialized for '{app_name}' — signup={'on' if config.allow_signup else 'off'}")

    return User, require_auth
