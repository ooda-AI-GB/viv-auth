from viv_auth.middleware import NotAuthenticated


def test_no_cookie_raises_not_authenticated(client):
    response = client.get("/protected")
    # Should redirect to login (HTML route)
    assert response.status_code == 303 or response.status_code == 200  # follows redirect
    # If not following redirects:
    response = client.get("/protected", follow_redirects=False)
    assert response.status_code == 303
    assert response.headers["location"] == "/auth/login"


def test_api_route_returns_401_json(client):
    response = client.get("/api/data")
    assert response.status_code == 401
    assert response.json() == {"detail": "Not authenticated"}


def test_valid_cookie_returns_user(client, db_session, app_with_auth):
    _, User, *_ = app_with_auth

    user = User(email="authed@example.com")
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)

    # Login and verify to get session cookie
    client.post("/auth/login", data={"email": "authed@example.com"})
    from sqlalchemy import text
    result = db_session.execute(text("SELECT token FROM magic_tokens WHERE user_id = :uid"), {"uid": user.id})
    token_value = result.fetchone()[0]
    client.get(f"/auth/verify?token={token_value}", follow_redirects=False)

    # Now access protected route — client retains cookies
    response = client.get("/protected")
    assert response.status_code == 200
    assert response.json()["email"] == "authed@example.com"


def test_invalid_cookie_redirects(client):
    client.cookies.set("viv_session", "garbage-token")
    response = client.get("/protected", follow_redirects=False)
    assert response.status_code == 303
    assert response.headers["location"] == "/auth/login"


def test_api_route_invalid_cookie_returns_401(client):
    client.cookies.set("viv_session", "garbage-token")
    response = client.get("/api/data")
    assert response.status_code == 401
    assert response.json() == {"detail": "Not authenticated"}
