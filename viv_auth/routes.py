import os
from pathlib import Path

from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from .config import AuthConfig
from .email import send_magic_link
from .session import COOKIE_NAME

TEMPLATES_DIR = Path(__file__).parent / "templates"


def create_auth_router(
    get_db,
    User,
    MagicToken,
    session_manager,
    app_name: str = "App",
    app_url: str | None = None,
    config: AuthConfig | None = None,
):
    """Factory that creates an auth router with login, verify, logout routes."""
    config = config or AuthConfig()
    templates = Jinja2Templates(directory=str(TEMPLATES_DIR))
    router = APIRouter(prefix="/auth", tags=["auth"])

    def _get_app_url(request: Request) -> str:
        if app_url:
            return app_url.rstrip("/")
        return str(request.base_url).rstrip("/")

    @router.get("/login", response_class=HTMLResponse)
    async def login_page(request: Request, error: str | None = None):
        return templates.TemplateResponse(
            "auth/login.html",
            {"request": request, "app_name": app_name, "error": error},
        )

    @router.post("/login", response_class=HTMLResponse)
    async def login_submit(request: Request, email: str = Form(...)):
        db = next(get_db())
        try:
            user = db.query(User).filter(User.email == email).first()

            if user is None:
                if not config.allow_signup:
                    return templates.TemplateResponse(
                        "auth/error.html",
                        {"request": request, "app_name": app_name, "message": "Account not found."},
                    )
                user = User(email=email)
                db.add(user)
                db.commit()
                db.refresh(user)

            token = MagicToken.create(user.id, config.token_expiry_minutes)
            db.add(token)
            db.commit()
            db.refresh(token)

            base_url = _get_app_url(request)
            magic_url = f"{base_url}/auth/verify?token={token.token}"

            from_email = os.environ.get("FROM_EMAIL")
            send_magic_link(email, magic_url, app_name, from_email)

            return templates.TemplateResponse(
                "auth/check_email.html",
                {"request": request, "app_name": app_name, "email": email},
            )
        finally:
            db.close()

    @router.get("/verify")
    async def verify_token(request: Request, token: str):
        db = next(get_db())
        try:
            magic_token = db.query(MagicToken).filter(MagicToken.token == token).first()

            if magic_token is None or not magic_token.is_valid():
                return templates.TemplateResponse(
                    "auth/error.html",
                    {
                        "request": request,
                        "app_name": app_name,
                        "message": "This link is invalid or has expired.",
                    },
                    status_code=400,
                )

            if config.require_active:
                user = db.query(User).filter(User.id == magic_token.user_id).first()
                if user and not user.is_active:
                    return templates.TemplateResponse(
                        "auth/error.html",
                        {
                            "request": request,
                            "app_name": app_name,
                            "message": "Account is deactivated.",
                        },
                        status_code=403,
                    )

            magic_token.used = True
            db.commit()

            session_token = session_manager.create_session(magic_token.user_id)
            response = RedirectResponse(url="/", status_code=303)
            response.set_cookie(
                key=COOKIE_NAME,
                value=session_token,
                max_age=session_manager.max_age,
                httponly=True,
                samesite="lax",
            )
            return response
        finally:
            db.close()

    @router.get("/logout")
    async def logout():
        response = RedirectResponse(url="/auth/login", status_code=303)
        response.delete_cookie(key=COOKIE_NAME)
        return response

    return router
