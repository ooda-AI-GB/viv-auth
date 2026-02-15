import logging
import os

logger = logging.getLogger("viv_auth")


def send_magic_link(
    to_email: str,
    magic_url: str,
    app_name: str = "App",
    from_email: str | None = None,
) -> bool:
    """Send a magic link email. Uses Resend if RESEND_API_KEY is set, otherwise logs to stdout."""
    api_key = os.environ.get("RESEND_API_KEY")

    if not api_key:
        logger.info(f"[viv-auth] DEV MODE — Magic link for {to_email}: {magic_url}")
        return True

    sender = from_email or os.environ.get("FROM_EMAIL", f"auth@{app_name.lower().replace(' ', '')}.app")

    try:
        import resend

        resend.api_key = api_key
        resend.Emails.send(
            {
                "from": sender,
                "to": [to_email],
                "subject": f"Sign in to {app_name}",
                "html": (
                    f"<h2>Sign in to {app_name}</h2>"
                    f'<p>Click the link below to sign in:</p>'
                    f'<p><a href="{magic_url}" style="display:inline-block;padding:12px 24px;'
                    f'background:#4f46e5;color:#fff;text-decoration:none;border-radius:6px;">'
                    f"Sign In</a></p>"
                    f"<p>Or copy this URL: {magic_url}</p>"
                    f"<p>This link expires in 15 minutes.</p>"
                ),
            }
        )
        logger.info(f"[viv-auth] Magic link sent to {to_email}")
        return True
    except Exception as e:
        logger.error(f"[viv-auth] Failed to send magic link to {to_email}: {e}")
        return False
