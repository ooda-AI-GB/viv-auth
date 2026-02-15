from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired


COOKIE_NAME = "viv_session"


class SessionManager:
    def __init__(self, secret_key: str, max_age: int = 604800):
        self.serializer = URLSafeTimedSerializer(secret_key)
        self.max_age = max_age

    def create_session(self, user_id: int) -> str:
        return self.serializer.dumps({"user_id": user_id})

    def verify_session(self, token: str) -> int | None:
        """Returns user_id if valid, None otherwise."""
        try:
            data = self.serializer.loads(token, max_age=self.max_age)
            return data.get("user_id")
        except (BadSignature, SignatureExpired):
            return None
