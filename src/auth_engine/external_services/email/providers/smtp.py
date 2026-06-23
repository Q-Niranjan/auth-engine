import asyncio
import logging
import smtplib
from email.message import EmailMessage

from auth_engine.external_services.email.base import EmailProvider, EmailProviderConfig

logger = logging.getLogger(__name__)


class SMTPEmailProvider(EmailProvider):
    """Generic SMTP email provider (used for Resend, Postmark, etc)."""

    def __init__(self, config: EmailProviderConfig) -> None:
        self.default_sender = config.from_email

        # Parse credentials from api_key format "username:password@host:port"
        # Example for Resend: "resend:re_123456789@smtp.resend.com:465"
        self.username = ""
        self.password = ""
        self.host = "smtp.resend.com"
        self.port = 465

        try:
            if config.api_key and "@" in config.api_key:
                creds, server = config.api_key.split("@", 1)
                if ":" in creds:
                    self.username, self.password = creds.split(":", 1)
                else:
                    self.username = creds

                if ":" in server:
                    self.host, port_str = server.split(":", 1)
                    self.port = int(port_str)
                else:
                    self.host = server
            else:
                # Default to Resend API key if just a key is passed
                self.username = "resend"
                self.password = config.api_key or ""

        except Exception as e:
            logger.error(f"Failed to parse SMTP credentials: {e}")

    def _send_sync(self, to_emails: list[str], subject: str, html_content: str) -> bool:
        msg = EmailMessage()
        msg["Subject"] = subject
        msg["From"] = self.default_sender
        msg["To"] = ", ".join(to_emails)
        msg.set_content(html_content, subtype="html")

        try:
            if self.port == 465:
                # SSL
                with smtplib.SMTP_SSL(self.host, self.port, timeout=10) as server:
                    server.login(self.username, self.password)
                    server.send_message(msg)
            else:
                # STARTTLS
                with smtplib.SMTP(self.host, self.port, timeout=10) as server:
                    server.starttls()
                    server.login(self.username, self.password)
                    server.send_message(msg)
            return True
        except Exception as e:
            logger.error(f"SMTP send failed: {e}")
            raise e

    async def send_email(self, to_emails: list[str], subject: str, html_content: str) -> bool:
        if not self.host or not self.password:
            logger.error("SMTP credentials not configured correctly.")
            return False

        try:
            await asyncio.to_thread(self._send_sync, to_emails, subject, html_content)
            logger.info(f"Email sent successfully via SMTP to {to_emails}")
            return True
        except Exception as e:
            logger.error(f"Unexpected error sending email via SMTP: {str(e)}")
            return False
