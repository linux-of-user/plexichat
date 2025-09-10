
"""
PlexiChat Email Notification Service

Handles sending email notifications with templates and SMTP configuration.
"""

import asyncio
import logging
import smtplib
from dataclasses import dataclass
from datetime import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class EmailConfig:
    """Email service configuration."""

    smtp_server: str
    smtp_port: int
    smtp_username: str
    smtp_password: str
    from_email: str
    from_name: str
    use_tls: bool = True
    use_ssl: bool = False
    timeout: int = 30


@dataclass
class EmailTemplate:
    """Email notification template."""

    template_id: str
    subject_template: str
    html_template: str
    text_template: str
    variables: List[str]


class EmailService:
    """Email notification service with template support."""

    def __init__(self, config: EmailConfig):
        self.config = config
        self.templates: Dict[str, EmailTemplate] = {}
        self._load_default_templates()

    def _load_default_templates(self):
        """Load default email templates."""
        self.templates = {
            "message_notification": EmailTemplate(
                template_id="message_notification",
                subject_template="New message from {{sender_name}} in {{channel_name}}",
                html_template="""
<html>
<body>
    <h2>New Message Notification</h2>
    <p><strong>{{sender_name}}</strong> sent a message in <strong>{{channel_name}}</strong>:</p>
    <div style="background-color: #f5f5f5; padding: 10px; border-left: 4px solid #007bff; margin: 10px 0;">
        {{message_content}}
    </div>
    <p><a href="{{message_url}}" style="background-color: #007bff; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">View Message</a></p>
    <hr>
    <p style="color: #666; font-size: 12px;">You received this notification because you have notifications enabled for this channel.</p>
    <p style="color: #666; font-size: 12px;"><a href="{{unsubscribe_url}}">Unsubscribe from notifications</a></p>
</body>
</html>
""",
                text_template="""
New Message Notification

{{sender_name}} sent a message in {{channel_name}}:

{{message_content}}

View Message: {{message_url}}

---
You received this notification because you have notifications enabled for this channel.
Unsubscribe: {{unsubscribe_url}}
""",
                variables=[
                    "sender_name",
                    "channel_name",
                    "message_content",
                    "message_url",
                    "unsubscribe_url",
                ],
            ),
            "mention_notification": EmailTemplate(
                template_id="mention_notification",
                subject_template="You were mentioned by {{sender_name}} in {{channel_name}}",
                html_template="""
<html>
<body>
    <h2>You were mentioned!</h2>
    <p><strong>{{sender_name}}</strong> mentioned you in <strong>{{channel_name}}</strong>:</p>
    <div style="background-color: #f5f5f5; padding: 10px; border-left: 4px solid #dc3545; margin: 10px 0;">
        {{message_content}}
    </div>
    <p><a href="{{message_url}}" style="background-color: #dc3545; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">View Message</a></p>
    <hr>
    <p style="color: #666; font-size: 12px;">You received this notification because you were mentioned in a message.</p>
    <p style="color: #666; font-size: 12px;"><a href="{{unsubscribe_url}}">Unsubscribe from notifications</a></p>
</body>
</html>
""",
                text_template="""
You were mentioned!

{{sender_name}} mentioned you in {{channel_name}}:

{{message_content}}

View Message: {{message_url}}

---
You received this notification because you were mentioned in a message.
Unsubscribe: {{unsubscribe_url}}
""",
                variables=[
                    "sender_name",
                    "channel_name",
                    "message_content",
                    "message_url",
                    "unsubscribe_url",
                ],
            ),
            "system_notification": EmailTemplate(
                template_id="system_notification",
                subject_template="System Notification: {{title}}",
                html_template="""
<html>
<body>
    <h2>System Notification</h2>
    <h3>{{title}}</h3>
    <div style="background-color: #f5f5f5; padding: 10px