from datetime import datetime, timedelta, timezone

from viv_auth.models import create_auth_models


def test_login_page_renders(client):
    response = client.get("/auth/login")
    assert response.status_code == 200
    assert "Test App" in response.text
    assert "email" in response.text


def test_login_submit_creates_user(client, db_session, app_with_auth):
    _, User, *_ = app_with_auth
    response = client.post("/auth/login", data={"email": "new@example.com"})
    assert response.status_code == 200
    assert "Check your email" in response.text

    user = db_session.query(User).filter(User.email == "new@example.com").first()
    assert user is not None


def test_login_submit_existing_user(client, db_session, app_with_auth):
    _, User, *_ = app_with_auth

    # Create user first
    user = User(email="existing@example.com")
    db_session.add(user)
    db_session.commit()

    response = client.post("/auth/login", data={"email": "existing@example.com"})
    assert response.status_code == 200
    assert "Check your email" in response.text

    # Should not create duplicate
    count = db_session.query(User).filter(User.email == "existing@example.com").count()
    assert count == 1


def test_verify_valid_token(client, db_session, app_with_auth):
    _, User, engine, SessionLocal, _ = app_with_auth

    # Get MagicToken model from the same Base
    from sqlalchemy.orm import declarative_base
    # Access the MagicToken from the DB
    user = User(email="verify@example.com")
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)

    # Submit login to generate a token
    client.post("/auth/login", data={"email": "verify@example.com"})

    # Get the token from DB — query the magic_tokens table directly
    from sqlalchemy import text
    result = db_session.execute(text("SELECT token FROM magic_tokens WHERE user_id = :uid"), {"uid": user.id})
    row = result.fetchone()
    assert row is not None
    token_value = row[0]

    response = client.get(f"/auth/verify?token={token_value}", follow_redirects=False)
    assert response.status_code == 303
    assert response.headers["location"] == "/"
    assert "viv_session" in response.cookies


def test_verify_expired_token(client, db_session, app_with_auth):
    _, User, *_ = app_with_auth

    user = User(email="expired@example.com")
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)

    # Insert an expired token directly
    from sqlalchemy import text
    expired_time = datetime.now(timezone.utc) - timedelta(minutes=1)
    db_session.execute(
        text("INSERT INTO magic_tokens (token, user_id, used, expires_at, created_at) VALUES (:t, :u, 0, :e, :c)"),
        {"t": "expired-token-123", "u": user.id, "e": expired_time, "c": datetime.now(timezone.utc)},
    )
    db_session.commit()

    response = client.get("/auth/verify?token=expired-token-123")
    assert response.status_code == 400
    assert "expired" in response.text.lower()


def test_verify_used_token(client, db_session, app_with_auth):
    _, User, *_ = app_with_auth

    user = User(email="used@example.com")
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)

    from sqlalchemy import text
    future_time = datetime.now(timezone.utc) + timedelta(minutes=15)
    db_session.execute(
        text("INSERT INTO magic_tokens (token, user_id, used, expires_at, created_at) VALUES (:t, :u, 1, :e, :c)"),
        {"t": "used-token-123", "u": user.id, "e": future_time, "c": datetime.now(timezone.utc)},
    )
    db_session.commit()

    response = client.get("/auth/verify?token=used-token-123")
    assert response.status_code == 400


def test_verify_invalid_token(client):
    response = client.get("/auth/verify?token=nonexistent")
    assert response.status_code == 400


def test_logout_clears_cookie(client, db_session, app_with_auth):
    _, User, *_ = app_with_auth

    # First login and verify to get a session
    user = User(email="logout@example.com")
    db_session.add(user)
    db_session.commit()
    client.post("/auth/login", data={"email": "logout@example.com"})

    from sqlalchemy import text
    result = db_session.execute(text("SELECT token FROM magic_tokens WHERE user_id = :uid"), {"uid": user.id})
    token_value = result.fetchone()[0]
    client.get(f"/auth/verify?token={token_value}", follow_redirects=False)

    # Now logout
    response = client.get("/auth/logout", follow_redirects=False)
    assert response.status_code == 303
    assert response.headers["location"] == "/auth/login"
