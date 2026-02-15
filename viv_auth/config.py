from dataclasses import dataclass


@dataclass
class AuthConfig:
    token_expiry_minutes: int = 15
    session_max_age: int = 604800  # 7 days
    allow_signup: bool = True
    require_active: bool = True
