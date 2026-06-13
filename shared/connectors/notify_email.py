import logging
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

import aiosmtplib

from shared.config import settings

logger = logging.getLogger(__name__)


class EmailConnector:
    def __init__(self):
        self.host = settings.smtp_host
        self.port = settings.smtp_port
        self.username = settings.smtp_username
        self.password = settings.smtp_password.get_secret_value() if settings.smtp_password else ""
        self.use_tls = settings.smtp_use_tls
        self.from_addr = settings.smtp_from_address

    async def send(
        self,
        to: list[str],
        subject: str,
        body_html: str,
        body_text: str | None = None,
        cc: list[str] | None = None,
    ) -> dict:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = self.from_addr
        msg["To"] = ", ".join(to)
        if cc:
            msg["Cc"] = ", ".join(cc)

        if body_text:
            msg.attach(MIMEText(body_text, "plain"))
        msg.attach(MIMEText(body_html, "html"))

        recipients = to + (cc or [])

        try:
            await aiosmtplib.send(
                msg,
                hostname=self.host,
                port=self.port,
                username=self.username or None,
                password=self.password or None,
                use_tls=self.use_tls,
                recipients=recipients,
            )
            logger.info("Email sent to %s | subject=%s", recipients, subject)
            return {"success": True, "recipients": recipients}
        except Exception as e:
            logger.error("Email send failed: %s", e)
            return {"success": False, "error": str(e)}

    async def health(self) -> dict:
        try:
            smtp = aiosmtplib.SMTP(hostname=self.host, port=self.port, use_tls=self.use_tls)
            await smtp.connect()
            await smtp.quit()
            return {"connected": True, "host": self.host, "port": self.port}
        except Exception as e:
            return {"connected": False, "error": str(e)}
