"""
PlexiChat Email Notification Service

Handles sending email notifications with templates and SMTP configuration.
"""

import asyncio
import logging
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from datetime import datetime

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
                variables=["sender_name", "channel_name", "message_content", "message_url", "unsubscribe_url"]
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
                variables=["sender_name", "channel_name", "message_content", "message_url", "unsubscribe_url"]
            ),
            "system_notification": EmailTemplate(
                template_id="system_notification",
                subject_template="System Notification: {{title}}",
                html_template="""
                <html>
                <body>
                    <h2>System Notification</h2>
                    <h3>{{title}}</h3>
                    <div style="background-color: #f5f5f5; padding: 10px; border-left: 4px solid #ffc107; margin: 10px 0;">
                        {{message_content}}
                    </div>
                    <p><a href="{{action_url}}" style="background-color: #ffc107; color: black; padding: 10px 20px; text-decoration: none; border-radius: 5px;">View Details</a></p>
                    <hr>
                    <p style="color: #666; font-size: 12px;">This is an automated system notification.</p>
                </body>
                </html>
                """,
                text_template="""
                System Notification: {{title}}

                {{message_content}}

                View Details: {{action_url}}

                ---
                This is an automated system notification.
                """,
                variables=["title", "message_content", "action_url"]
            )
        }

    def add_template(self, template: EmailTemplate):
        """Add a custom email template."""
        self.templates[template.template_id] = template

    def _render_template(self, template: EmailTemplate, variables: Dict[str, Any]) -> tuple[str, str]:
        """Render email template with variables."""
        subject = template.subject_template
        html_body = template.html_template
        text_body = template.text_template

        for key, value in variables.items():
            placeholder = "{{" + key + "}}"
            subject = subject.replace(placeholder, str(value))
            html_body = html_body.replace(placeholder, str(value))
            text_body = text_body.replace(placeholder, str(value))

        return subject, html_body, text_body

    async def send_email(self, to_email: str, template_id: str,
                        variables: Dict[str, Any], cc: Optional[List[str]] = None,
                        bcc: Optional[List[str]] = None) -> bool:
        """
        Send email notification using template.

        Args:
            to_email: Recipient email address
            template_id: Template ID to use
            variables: Template variables
            cc: CC email addresses
            bcc: BCC email addresses

        Returns:
            bool: Success status
        """
        try:
            if template_id not in self.templates:
                logger.error(f"Email template '{template_id}' not found")
                return False

            template = self.templates[template_id]
            subject, html_body, text_body = self._render_template(template, variables)

            # Create message
            msg = MIMEMultipart('alternative')
            msg['Subject'] = subject
            msg['From'] = f"{self.config.from_name} <{self.config.from_email}>"
            msg['To'] = to_email

            if cc:
                msg['Cc'] = ', '.join(cc)

            # Attach both HTML and text versions
            text_part = MIMEText(text_body, 'plain')
            html_part = MIMEText(html_body, 'html')

            msg.attach(text_part)
            msg.attach(html_part)

            # Send email
            recipients = [to_email]
            if cc:
                recipients.extend(cc)
            if bcc:
                recipients.extend(bcc)

            await self._send_via_smtp(msg, recipients)

            logger.info(f"Email sent successfully to {to_email} using template '{template_id}'")
            return True

        except Exception as e:
            logger.error(f"Failed to send email to {to_email}: {e}")
            return False

    async def _send_via_smtp(self, msg: MIMEMultipart, recipients: List[str]):
        """Send email via SMTP."""
        try:
            if self.config.use_ssl:
                server = smtplib.SMTP_SSL(self.config.smtp_server, self.config.smtp_port,
                                        timeout=self.config.timeout)
            else:
                server = smtplib.SMTP(self.config.smtp_server, self.config.smtp_port,
                                    timeout=self.config.timeout)

            if self.config.use_tls and not self.config.use_ssl:
                server.starttls()

            if self.config.smtp_username and self.config.smtp_password:
                server.login(self.config.smtp_username, self.config.smtp_password)

            server.sendmail(self.config.from_email, recipients, msg.as_string())
            server.quit()

        except Exception as e:
            logger.error(f"SMTP error: {e}")
            raise

    async def send_bulk_emails(self, email_data: List[Dict[str, Any]]) -> Dict[str, bool]:
        """
        Send bulk email notifications.

        Args:
            email_data: List of email data dictionaries with keys:
                - to_email: str
                - template_id: str
                - variables: dict
                - cc: list (optional)
                - bcc: list (optional)

        Returns:
            Dict mapping email addresses to success status
        """
        results = {}

        # Send emails concurrently with rate limiting
        semaphore = asyncio.Semaphore(10)  # Limit concurrent sends

        async def send_single_email(data: Dict[str, Any]):
            async with semaphore:
                return await self.send_email(
                    data['to_email'],
                    data['template_id'],
                    data['variables'],
                    data.get('cc'),
                    data.get('bcc')
                )

        tasks = [send_single_email(data) for data in email_data]
        send_results = await asyncio.gather(*tasks, return_exceptions=True)

        for i, result in enumerate(send_results):
            email = email_data[i]['to_email']
            if isinstance(result, Exception):
                logger.error(f"Failed to send email to {email}: {result}")
                results[email] = False
            else:
                results[email] = result

        return results

    def get_available_templates(self) -> List[str]:
        """Get list of available email templates."""
        return list(self.templates.keys())

    def validate_template_variables(self, template_id: str, variables: Dict[str, Any]) -> List[str]:
        """Validate that all required template variables are provided."""
        if template_id not in self.templates:
            return [f"Template '{template_id}' not found"]

        template = self.templates[template_id]
        missing_vars = []

        for var in template.variables:
            if var not in variables:
                missing_vars.append(var)

        return missing_vars

# Global email service instance
_email_service: Optional[EmailService] = None

def get_email_service() -> Optional[EmailService]:
    """Get the global email service instance."""
    return _email_service

def initialize_email_service(config: EmailConfig) -> EmailService:
    """Initialize the global email service."""
    global _email_service
    _email_service = EmailService(config)
    return _email_service

async def send_notification_email(to_email: str, template_id: str,
                                variables: Dict[str, Any]) -> bool:
    """Send notification email using global service."""
    service = get_email_service()
    if not service:
        logger.warning("Email service not initialized")
        return False

    return await service.send_email(to_email, template_id, variables)