import os
from dataclasses import dataclass, field


def _default_allow_signup() -> bool:
    return os.environ.get("ALLOW_SIGNUP", "true").lower() != "false"


@dataclass
class AuthConfig:
    token_expiry_minutes: int = 15
    session_max_age: int = 604800  # 7 days
    allow_signup: bool = field(default_factory=_default_allow_signup)
    require_active: bool = True
