# viv-auth

Magic link authentication for FastAPI apps. No passwords — user enters email, gets a link, clicks it, logged in.

## Install

```bash
pip install git+https://github.com/ooda-AI-GB/axiom-monorepo.git#subdirectory=packages/viv-auth
```

## Usage

```python
from fastapi import FastAPI, Depends
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base
from viv_auth import init_auth

app = FastAPI()
engine = create_engine("sqlite:///app.db")
Base = declarative_base()
SessionLocal = sessionmaker(bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

User, require_auth = init_auth(app, engine, Base, get_db, app_name="My App")

@app.get("/")
async def home(user=Depends(require_auth)):
    return {"message": f"Hello {user.email}"}
```

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `RESEND_API_KEY` | No | Resend API key for sending emails. If unset, magic links are logged to stdout. |
| `FROM_EMAIL` | No | Sender email address. |
| `SESSION_SECRET` | No | Secret key for signing session cookies. Random key generated if unset (sessions won't survive restart). |

## Configuration

```python
from viv_auth import init_auth, AuthConfig

User, require_auth = init_auth(
    app, engine, Base, get_db,
    app_name="My App",
    app_url="https://myapp.example.com",
    config=AuthConfig(
        token_expiry_minutes=15,   # Magic link expiry
        session_max_age=604800,    # 7 days
        allow_signup=True,         # Auto-create accounts
        require_active=True,       # Check user.is_active
    ),
)
```

## Routes

| Method | Path | Description |
|--------|------|-------------|
| GET | `/auth/login` | Login page |
| POST | `/auth/login` | Submit email, send magic link |
| GET | `/auth/verify?token=...` | Verify magic link, set session cookie |
| GET | `/auth/logout` | Clear session, redirect to login |
