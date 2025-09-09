from .base_sender import NotificationSender
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import List, Dict, Any
import logging

logger = logging.getLogger(__name__)

class EmailNotificationSender(NotificationSender):
    """
    Email notification sender using SMTP.
    """

    def __init__(self, smtp_server: str, smtp_port: int, username: str, password: str, from_email: str):
        super().__init__()
        self.smtp_server = smtp_server
        self.smtp_port = smtp_port
        self.username = username
        self.password = password
        self.from_email = from_email

    async def _send_via_platform(self, rendered_content: str, recipients: List[str], notification_data: Dict[str, Any]) -> bool:
        """
        Send email via SMTP to multiple recipients (bulk support).
        """
        try:
            server = smtplib.SMTP(self.smtp_server, self.smtp_port)
            server.starttls()
            server.login(self.username, self.password)
            
            for recipient in recipients:
                msg = MIMEMultipart()
                msg['From'] = self.from_email
                msg['To'] = recipient
                msg['Subject'] = notification_data.get('subject', 'Notification')
                msg.attach(MIMEText(rendered_content, 'html'))
                
                server.send_message(msg)
                logger.info(f"Email sent to {recipient}")
            
            server.quit()
            return True
        except Exception as e:
            logger.error(f"SMTP send failed: {e}")
            raise

    async def send_bulk_email(self, template_name: str, context: Dict[str, Any], recipients: List[str], subject: str = "Notification") -> bool:
        """
        Public method for bulk email sending.
        """
        notification_data = {
            "template": template_name,
            "context": context,
            "recipients": recipients,
            "subject": subject
        }
        return await self.send_notification(notification_data)