"""
PlexiChat Email Notification Service

Handles sending email notifications with templates and SMTP configuration.
"""

import asyncio
from dataclasses import dataclass
from datetime import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import logging
import smtplib
import ssl
from typing import Any

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
    variables: list[str]


@dataclass
class EmailMessage:
    """Email message data structure."""

    to_email: str
    subject: str
    html_content: str | None = None
    text_content: str | None = None
    template_id: str | None = None
    template_data: dict[str, Any] | None = None


class EmailDeliveryResult:
    """Result of email delivery attempt."""

    def __init__(self, success: bool, message: str, message_id: str | None = None):
        self.success: bool = success
        self.message: str = message
        self.message_id: str | None = message_id
        self.sent_at: datetime = datetime.now()


class EmailService:
    """Email notification service with template support."""

    def __init__(self, config: EmailConfig) -> None:
        self.config: EmailConfig = config
        self.templates: dict[str, EmailTemplate] = {}
        self._load_default_templates()

    def _load_default_templates(self) -> None:
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
    <div style="background-color: #f5f5f5; padding: 10px; border-left: 4px solid #28a745; margin: 10px 0;">
        {{message}}
    </div>
    {{#action_url}}
    <p><a href="{{action_url}}" style="background-color: #28a745; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">{{action_text}}</a></p>
    {{/action_url}}
    <hr>
    <p style="color: #666; font-size: 12px;">This is an automated system notification.</p>
</body>
</html>
""",
                text_template="""
System Notification: {{title}}

{{message}}

{{#action_url}}
{{action_text}}: {{action_url}}
{{/action_url}}

---
This is an automated system notification.
""",
                variables=[
                    "title",
                    "message",
                    "action_url",
                    "action_text",
                ],
            ),
        }

    def add_template(self, template: EmailTemplate) -> None:
        """Add a custom email template."""
        self.templates[template.template_id] = template

    def get_template(self, template_id: str) -> EmailTemplate | None:
        """Get email template by ID."""
        return self.templates.get(template_id)

    def _render_template(self, template: str, variables: dict[str, Any]) -> str:
        """Render template with variables using simple string replacement."""
        result = template
        for key, value in variables.items():
            placeholder = f"{{{{{key}}}}}"
            result = result.replace(placeholder, str(value))
        return result

    def render_email_content(
        self, template_id: str, variables: dict[str, Any]
    ) -> dict[str, str]:
        """
        Render email content from template.

        Returns:
            Dictionary with 'subject', 'html', and 'text' keys
        """
        template = self.get_template(template_id)
        if not template:
            raise ValueError(f"Template not found: {template_id}")

        # Validate required variables
        missing_vars = set(template.variables) - set(variables.keys())
        if missing_vars:
            logger.warning(
                f"Missing variables for template {template_id}: {missing_vars}"
            )

        return {
            "subject": self._render_template(template.subject_template, variables),
            "html": self._render_template(template.html_template, variables),
            "text": self._render_template(template.text_template, variables),
        }

    async def send_email(self, message: EmailMessage) -> EmailDeliveryResult:
        """
        Send email message.

        Args:
            message: Email message to send

        Returns:
            EmailDeliveryResult indicating success or failure
        """
        try:
            # Create MIME message
            mime_message = MIMEMultipart("alternative")
            mime_message["Subject"] = message.subject
            mime_message["From"] = f"{self.config.from_name} <{self.config.from_email}>"
            mime_message["To"] = message.to_email

            # Determine content
            html_content = message.html_content
            text_content = message.text_content

            # Render from template if specified
            if message.template_id and message.template_data:
                rendered = self.render_email_content(
                    message.template_id, message.template_data
                )
                mime_message["Subject"] = rendered["subject"]
                html_content = rendered["html"]
                text_content = rendered["text"]

            # Add text part
            if text_content:
                text_part = MIMEText(text_content, "plain")
                mime_message.attach(text_part)

            # Add HTML part
            if html_content:
                html_part = MIMEText(html_content, "html")
                mime_message.attach(html_part)

            # Send email
            await self._send_smtp_message(mime_message)

            return EmailDeliveryResult(
                success=True,
                message="Email sent successfully",
                message_id=mime_message.get("Message-ID"),
            )

        except Exception as e:
            logger.error(f"Failed to send email to {message.to_email}: {e}")
            return EmailDeliveryResult(success=False, message=str(e))

    async def _send_smtp_message(self, message: MIMEMultipart) -> None:
        """Send MIME message via SMTP."""

        def send_sync() -> None:
            # Create SMTP connection
            if self.config.use_ssl:
                context = ssl.create_default_context()
                server = smtplib.SMTP_SSL(
                    self.config.smtp_server,
                    self.config.smtp_port,
                    timeout=self.config.timeout,
                    context=context,
                )
            else:
                server = smtplib.SMTP(
                    self.config.smtp_server,
                    self.config.smtp_port,
                    timeout=self.config.timeout,
                )

                if self.config.use_tls:
                    context = ssl.create_default_context()
                    server.starttls(context=context)

            try:
                # Login
                server.login(self.config.smtp_username, self.config.smtp_password)

                # Send message
                server.send_message(message)

            finally:
                server.quit()

        # Run in thread pool to avoid blocking
        await asyncio.get_event_loop().run_in_executor(None, send_sync)

    async def send_notification_email(
        self, to_email: str, template_id: str, template_data: dict[str, Any]
    ) -> EmailDeliveryResult:
        """
        Send notification email using template.

        Args:
            to_email: Recipient email address
            template_id: Template ID to use
            template_data: Data for template rendering

        Returns:
            EmailDeliveryResult
        """
        message = EmailMessage(
            to_email=to_email,
            subject="",  # Will be set by template
            template_id=template_id,
            template_data=template_data,
        )

        return await self.send_email(message)

    async def send_bulk_emails(
        self, messages: list[EmailMessage]
    ) -> list[EmailDeliveryResult]:
        """
        Send multiple emails concurrently.

        Args:
            messages: List of email messages to send

        Returns:
            List of EmailDeliveryResult objects
        """
        tasks = [self.send_email(message) for message in messages]
        return await asyncio.gather(*tasks, return_exceptions=False)

    def validate_email_address(self, email: str) -> bool:
        """Basic email address validation."""
        import re

        pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
        return bool(re.match(pattern, email))

    async def test_connection(self) -> bool:
        """Test SMTP connection."""
        try:
            test_message = EmailMessage(
                to_email=self.config.from_email,
                subject="SMTP Connection Test",
                text_content="This is a test message to verify SMTP configuration.",
            )
            result = await self.send_email(test_message)
            return result.success
        except Exception as e:
            logger.error(f"SMTP connection test failed: {e}")
            return False


# Module-level function for backward compatibility
async def send_notification_email(
    email_service: EmailService,
    to_email: str,
    template_id: str,
    template_data: dict[str, Any],
) -> EmailDeliveryResult:
    """Send notification email (backward compatibility function)."""
    return await email_service.send_notification_email(
        to_email, template_id, template_data
    )
