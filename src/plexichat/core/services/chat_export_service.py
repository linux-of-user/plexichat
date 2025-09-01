"""
Chat Export Service

Provides functionality to export chat messages in multiple formats (JSON, CSV, TXT, HTML)
with proper permission checks and date range filtering.
"""

import json
import csv
import io
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass

from plexichat.core.messaging.unified_messaging_system import get_messaging_system, Message


@dataclass
class ExportOptions:
    """Options for chat export."""
    format: str  # 'json', 'csv', 'txt', 'html'
    start_date: Optional[datetime] = None
    end_date: Optional[datetime] = None
    include_attachments: bool = False
    include_reactions: bool = True
    include_threads: bool = False


class ChatExportService:
    """
    Service for exporting chat messages in various formats.
    """

    def __init__(self):
        self.messaging_system = get_messaging_system()
        self.supported_formats = ['json', 'csv', 'txt', 'html']

    def check_channel_access(self, user_id: str, channel_id: str) -> bool:
        """
        Check if user has access to the channel.
        """
        # Get channel from messaging system
        channel_manager = self.messaging_system.channel_manager
        channel = channel_manager.channels.get(channel_id)

        if not channel:
            return False

        # Check if user is a member of the channel
        return user_id in channel.members

    def get_channel_messages(self, channel_id: str, options: ExportOptions) -> List[Message]:
        """
        Get messages from channel with filtering options.
        """
        # Get all messages from channel
        messages = self.messaging_system.get_channel_messages(channel_id, limit=10000)

        # Apply date filtering
        filtered_messages = []
        for message in messages:
            message_date = message.metadata.timestamp

            if options.start_date and message_date < options.start_date:
                continue
            if options.end_date and message_date > options.end_date:
                continue

            filtered_messages.append(message)

        return filtered_messages

    def export_json(self, messages: List[Message], options: ExportOptions) -> str:
        """
        Export messages to JSON format.
        """
        export_data = {
            "export_info": {
                "format": "json",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "message_count": len(messages),
                "options": {
                    "include_attachments": options.include_attachments,
                    "include_reactions": options.include_reactions,
                    "include_threads": options.include_threads
                }
            },
            "messages": []
        }

        for message in messages:
            message_data = {
                "message_id": message.metadata.message_id,
                "sender_id": message.metadata.sender_id,
                "channel_id": message.metadata.channel_id,
                "timestamp": message.metadata.timestamp.isoformat(),
                "content": message.content,
                "message_type": message.metadata.message_type.value,
                "status": message.status.value
            }

            if options.include_reactions and message.reactions:
                message_data["reactions"] = message.reactions

            if options.include_attachments and message.attachments:
                message_data["attachments"] = message.attachments

            if message.metadata.reply_to:
                message_data["reply_to"] = message.metadata.reply_to

            if message.metadata.thread_id:
                message_data["thread_id"] = message.metadata.thread_id

            export_data["messages"].append(message_data)

        return json.dumps(export_data, indent=2, ensure_ascii=False)

    def export_csv(self, messages: List[Message], options: ExportOptions) -> str:
        """
        Export messages to CSV format.
        """
        output = io.StringIO()
        writer = csv.writer(output)

        # Write header
        header = ["Message ID", "Sender ID", "Channel ID", "Timestamp", "Content", "Type", "Status"]
        if options.include_reactions:
            header.append("Reactions")
        if options.include_attachments:
            header.append("Attachments")
        writer.writerow(header)

        # Write messages
        for message in messages:
            row = [
                message.metadata.message_id,
                message.metadata.sender_id,
                message.metadata.channel_id,
                message.metadata.timestamp.isoformat(),
                message.content,
                message.metadata.message_type.value,
                message.status.value
            ]

            if options.include_reactions:
                reactions_str = json.dumps(message.reactions) if message.reactions else ""
                row.append(reactions_str)

            if options.include_attachments:
                attachments_str = json.dumps(message.attachments) if message.attachments else ""
                row.append(attachments_str)

            writer.writerow(row)

        return output.getvalue()

    def export_txt(self, messages: List[Message], options: ExportOptions) -> str:
        """
        Export messages to plain text format.
        """
        lines = []
        lines.append("Chat Export")
        lines.append("=" * 50)
        lines.append(f"Export Date: {datetime.now(timezone.utc).isoformat()}")
        lines.append(f"Message Count: {len(messages)}")
        lines.append("")

        for message in messages:
            timestamp = message.metadata.timestamp.strftime("%Y-%m-%d %H:%M:%S UTC")
            lines.append(f"[{timestamp}] {message.metadata.sender_id}: {message.content}")

            if options.include_reactions and message.reactions:
                reactions = []
                for emoji, users in message.reactions.items():
                    reactions.append(f"{emoji}({len(users)})")
                lines.append(f"  Reactions: {', '.join(reactions)}")

            if options.include_attachments and message.attachments:
                lines.append(f"  Attachments: {len(message.attachments)} files")

            lines.append("")

        return "\n".join(lines)

    def export_html(self, messages: List[Message], options: ExportOptions) -> str:
        """
        Export messages to HTML format.
        """
        html_parts = []
        html_parts.append("<!DOCTYPE html>")
        html_parts.append("<html lang='en'>")
        html_parts.append("<head>")
        html_parts.append("    <meta charset='UTF-8'>")
        html_parts.append("    <meta name='viewport' content='width=device-width, initial-scale=1.0'>")
        html_parts.append("    <title>Chat Export</title>")
        html_parts.append("    <style>")
        html_parts.append("        body { font-family: Arial, sans-serif; margin: 20px; }")
        html_parts.append("        .message { margin-bottom: 15px; padding: 10px; border-left: 3px solid #007bff; }")
        html_parts.append("        .timestamp { color: #666; font-size: 0.9em; }")
        html_parts.append("        .sender { font-weight: bold; color: #007bff; }")
        html_parts.append("        .content { margin: 5px 0; }")
        html_parts.append("        .reactions { font-size: 0.9em; color: #666; }")
        html_parts.append("        .attachments { font-size: 0.9em; color: #666; }")
        html_parts.append("        .header { background: #f8f9fa; padding: 15px; margin-bottom: 20px; border-radius: 5px; }")
        html_parts.append("    </style>")
        html_parts.append("</head>")
        html_parts.append("<body>")
        html_parts.append("    <div class='header'>")
        html_parts.append("        <h1>Chat Export</h1>")
        html_parts.append(f"        <p>Export Date: {datetime.now(timezone.utc).isoformat()}</p>")
        html_parts.append(f"        <p>Message Count: {len(messages)}</p>")
        html_parts.append("    </div>")

        for message in messages:
            html_parts.append("    <div class='message'>")
            timestamp = message.metadata.timestamp.strftime("%Y-%m-%d %H:%M:%S UTC")
            html_parts.append(f"        <div class='timestamp'>{timestamp}</div>")
            html_parts.append(f"        <div class='sender'>{message.metadata.sender_id}</div>")
            html_parts.append(f"        <div class='content'>{message.content}</div>")

            if options.include_reactions and message.reactions:
                reactions = []
                for emoji, users in message.reactions.items():
                    reactions.append(f"{emoji} ({len(users)})")
                html_parts.append(f"        <div class='reactions'>Reactions: {', '.join(reactions)}</div>")

            if options.include_attachments and message.attachments:
                html_parts.append(f"        <div class='attachments'>Attachments: {len(message.attachments)} files</div>")

            html_parts.append("    </div>")

        html_parts.append("</body>")
        html_parts.append("</html>")

        return "\n".join(html_parts)

    def export_messages(self, channel_id: str, user_id: str, options: ExportOptions) -> Tuple[bool, str, Optional[str]]:
        """
        Export messages from a channel.

        Returns:
            Tuple of (success, error_message, export_data)
        """
        try:
            # Check permissions
            if not self.check_channel_access(user_id, channel_id):
                return False, "Access denied: You do not have permission to access this channel", None

            # Get messages
            messages = self.get_channel_messages(channel_id, options)

            if not messages:
                return False, "No messages found in the specified date range", None

            # Export based on format
            if options.format == 'json':
                export_data = self.export_json(messages, options)
            elif options.format == 'csv':
                export_data = self.export_csv(messages, options)
            elif options.format == 'txt':
                export_data = self.export_txt(messages, options)
            elif options.format == 'html':
                export_data = self.export_html(messages, options)
            else:
                return False, f"Unsupported format: {options.format}", None

            return True, "", export_data

        except Exception as e:
            return False, f"Export failed: {str(e)}", None


# Global instance
chat_export_service = ChatExportService()

def get_chat_export_service() -> ChatExportService:
    """Get the global chat export service instance."""
    return chat_export_service