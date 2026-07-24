import logging
import smtplib
from email.message import EmailMessage

from server.settings import (
    PASSWORD_RESET_URL_BASE,
    SMTP_FROM_EMAIL,
    SMTP_HOST,
    SMTP_PASSWORD,
    SMTP_PORT,
    SMTP_USERNAME,
    SMTP_USE_TLS,
)

logger = logging.getLogger("safemailx.mailer")


def smtp_configured() -> bool:
    return bool(SMTP_HOST and SMTP_FROM_EMAIL)


def build_password_reset_link(token: str) -> str:
    return f"{PASSWORD_RESET_URL_BASE}?token={token}"


def send_password_reset_email(to_email: str, token: str) -> bool:
    reset_link = build_password_reset_link(token)

    if not smtp_configured():
        logger.warning("SMTP is not configured; password reset delivery was skipped")
        return False

    message = EmailMessage()
    message["Subject"] = "SafeMail X password reset"
    message["From"] = SMTP_FROM_EMAIL
    message["To"] = to_email
    message.set_content(
        "A password reset was requested for your SafeMail X account.\n\n"
        f"Reset link: {reset_link}\n\n"
        "If you did not request this, you can ignore this email."
    )
    message.add_alternative(
        f"""
        <html>
          <body style="font-family:Segoe UI,Arial,sans-serif;background:#0b1320;color:#e8eef8;padding:24px;">
            <div style="max-width:560px;margin:0 auto;background:#101827;border:1px solid #223049;border-radius:16px;padding:24px;">
              <p style="margin:0 0 8px 0;color:#60a5fa;font-size:12px;font-weight:700;letter-spacing:2px;">SAFEMAILX AI</p>
              <h1 style="margin:0 0 12px 0;font-size:24px;color:#ffffff;">Reset your password</h1>
              <p style="margin:0 0 18px 0;color:#b6c2d2;line-height:1.6;">
                A password reset was requested for your SafeMail X account.
              </p>
              <p style="margin:0 0 22px 0;">
                <a href="{reset_link}" style="display:inline-block;background:#60a5fa;color:#08111d;text-decoration:none;padding:12px 18px;border-radius:12px;font-weight:700;">
                  Open reset link
                </a>
              </p>
              <p style="margin:0;color:#91a0b5;line-height:1.6;word-break:break-all;">{reset_link}</p>
            </div>
          </body>
        </html>
        """,
        subtype="html",
    )

    with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=10) as smtp:
        if SMTP_USE_TLS:
            smtp.starttls()
        if SMTP_USERNAME:
            smtp.login(SMTP_USERNAME, SMTP_PASSWORD)
        smtp.send_message(message)
    return True


def send_otp_email(to_email: str, otp: str) -> bool:
    if not smtp_configured():
        logger.warning("SMTP is not configured; registration code delivery was skipped")
        return False

    message = EmailMessage()
    message["Subject"] = "Your SafeMail X Registration Code"
    message["From"] = SMTP_FROM_EMAIL
    message["To"] = to_email
    message.set_content(
        f"Your SafeMail X registration code is: {otp}\n\n"
        "This code will expire in 10 minutes.\n"
        "If you did not request this, you can ignore this email."
    )
    message.add_alternative(
        f"""
        <html>
          <body style="font-family:Segoe UI,Arial,sans-serif;background:#0b1320;color:#e8eef8;padding:24px;">
            <div style="max-width:560px;margin:0 auto;background:#101827;border:1px solid #223049;border-radius:16px;padding:24px;text-align:center;">
              <p style="margin:0 0 8px 0;color:#60a5fa;font-size:12px;font-weight:700;letter-spacing:2px;">SAFEMAILX AI</p>
              <h1 style="margin:0 0 12px 0;font-size:24px;color:#ffffff;">Registration Code</h1>
              <p style="margin:0 0 18px 0;color:#b6c2d2;line-height:1.6;">
                Use the following 6-digit code to complete your account registration:
              </p>
              <div style="margin:20px 0;font-size:32px;font-weight:700;color:#6fd9b8;letter-spacing:4px;">
                {otp}
              </div>
              <p style="margin:0;color:#91a0b5;line-height:1.6;font-size:13px;">
                This code will expire in 10 minutes. If you did not request this code, you can safely ignore this email.
              </p>
            </div>
          </body>
        </html>
        """,
        subtype="html",
    )

    with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=10) as smtp:
        if SMTP_USE_TLS:
            smtp.starttls()
        if SMTP_USERNAME:
            smtp.login(SMTP_USERNAME, SMTP_PASSWORD)
        smtp.send_message(message)
    return True
