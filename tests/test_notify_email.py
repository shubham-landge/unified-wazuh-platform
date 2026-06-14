import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from email import message_from_bytes

from shared.connectors.notify_email import EmailConnector


@pytest.mark.asyncio
async def test_email_attachment_uses_provided_mime_type():
    sent_messages = []

    async def capture_send(msg, **kwargs):
        sent_messages.append(msg)
        return None

    with patch("shared.connectors.notify_email.aiosmtplib.send", side_effect=capture_send):
        connector = EmailConnector()
        await connector.send(
            to=["user@example.com"],
            subject="Test",
            body_html="<p>Hello</p>",
            attachments=[
                {
                    "filename": "report.pdf",
                    "content": b"%PDF-1.4 fake",
                    "mime_type": "application/pdf",
                }
            ],
        )

    assert len(sent_messages) == 1
    raw = sent_messages[0].as_bytes()
    parsed = message_from_bytes(raw)

    attachment_parts = [part for part in parsed.walk() if part.get_content_disposition() == "attachment"]
    assert len(attachment_parts) == 1
    part = attachment_parts[0]
    assert part.get_content_type() == "application/pdf"
    assert part.get_filename() == "report.pdf"
    payload = part.get_payload(decode=True)
    assert payload == b"%PDF-1.4 fake"
