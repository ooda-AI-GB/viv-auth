import logging
import os

from viv_auth.email import send_magic_link


def test_dev_mode_logs_to_stdout(caplog):
    """When RESEND_API_KEY is not set, magic link should be logged."""
    # Ensure no API key
    old_key = os.environ.pop("RESEND_API_KEY", None)
    try:
        with caplog.at_level(logging.INFO, logger="viv_auth"):
            result = send_magic_link(
                to_email="test@example.com",
                magic_url="http://localhost:8000/auth/verify?token=abc123",
                app_name="Test App",
            )
        assert result is True
        assert "test@example.com" in caplog.text
        assert "http://localhost:8000/auth/verify?token=abc123" in caplog.text
    finally:
        if old_key:
            os.environ["RESEND_API_KEY"] = old_key


def test_dev_mode_contains_url(caplog):
    """Verify the magic URL is present in the log output."""
    old_key = os.environ.pop("RESEND_API_KEY", None)
    try:
        with caplog.at_level(logging.INFO, logger="viv_auth"):
            send_magic_link(
                to_email="user@test.com",
                magic_url="https://myapp.com/auth/verify?token=xyz",
                app_name="My App",
            )
        assert "https://myapp.com/auth/verify?token=xyz" in caplog.text
    finally:
        if old_key:
            os.environ["RESEND_API_KEY"] = old_key
