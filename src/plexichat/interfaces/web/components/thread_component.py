"""
Thread Component for PlexiChat

Provides frontend components for thread management and navigation.
"""

import json
from typing import Dict, List, Optional
from datetime import datetime

class ThreadComponent:
    """Thread component for managing thread UI elements."""

    def __init__(self):
        self.active_threads: Dict[str, Dict] = {}
        self.current_thread: Optional[str] = None

    def render_thread_list(self, threads: List[Dict]) -> str:
        """Render the thread list sidebar."""
        html = """
        <div class="thread-sidebar">
            <div class="thread-header">
                <h3>Threads</h3>
                <button class="create-thread-btn" onclick="showCreateThreadModal()">
                    <i class="fas fa-plus"></i>
                </button>
            </div>
            <div class="thread-list">
        """

        for thread in threads:
            active_class = "active" if thread['thread_id'] == self.current_thread else ""
            html += f"""
                <div class="thread-item {active_class}" onclick="selectThread('{thread['thread_id']}')">
                    <div class="thread-info">
                        <div class="thread-title">{thread['title']}</div>
                        <div class="thread-meta">
                            <span class="thread-participants">{thread['participant_count']} participants</span>
                            <span class="thread-messages">{thread['message_count']} messages</span>
                        </div>
                    </div>
                    <div class="thread-status">
                        {"<span class='resolved-badge'>✓</span>" if thread['is_resolved'] else ""}
                    </div>
                </div>
            """

        html += """
            </div>
        </div>
        """
        return html

    def render_thread_view(self, thread: Dict, messages: List[Dict]) -> str:
        """Render the main thread view."""
        html = f"""
        <div class="thread-view" id="thread-{thread['thread_id']}">
            <div class="thread-header">
                <div class="thread-info">
                    <h2>{thread['title']}</h2>
                    <div class="thread-details">
                        <span class="thread-creator">Created by {thread['creator_id']}</span>
                        <span class="thread-participants">{thread['participant_count']} participants</span>
                        <span class="thread-messages">{thread['message_count']} messages</span>
                    </div>
                </div>
                <div class="thread-actions">
                    <button class="thread-action-btn" onclick="toggleThreadResolved('{thread['thread_id']}')">
                        {"Mark Resolved" if not thread['is_resolved'] else "Reopen Thread"}
                    </button>
                    <button class="thread-action-btn" onclick="leaveThread('{thread['thread_id']}')">
                        Leave Thread
                    </button>
                </div>
            </div>

            <div class="thread-messages" id="thread-messages-{thread['thread_id']}">
        """

        for message in messages:
            html += self.render_thread_message(message)

        html += """
            </div>

            <div class="thread-input">
                <div class="message-input-container">
                    <textarea
                        id="thread-message-input"
                        placeholder="Reply to this thread..."
                        rows="3"
                    ></textarea>
                    <button class="send-btn" onclick="sendThreadMessage()">
                        <i class="fas fa-paper-plane"></i>
                    </button>
                </div>
            </div>
        </div>
        """
        return html

    def render_thread_message(self, message: Dict) -> str:
        """Render a single thread message."""
        timestamp = datetime.fromisoformat(message['timestamp'].replace('Z', '+00:00'))
        formatted_time = timestamp.strftime("%H:%M")

        html = f"""
        <div class="thread-message" data-message-id="{message['message_id']}">
            <div class="message-avatar">
                <img src="/api/v1/users/{message['sender_id']}/avatar" alt="Avatar">
            </div>
            <div class="message-content">
                <div class="message-header">
                    <span class="message-author">{message['sender_id']}</span>
                    <span class="message-time">{formatted_time}</span>
                </div>
                <div class="message-text">{message['content']}</div>
                {self.render_message_reactions(message.get('reactions', {}))}
            </div>
        </div>
        """
        return html

    def render_message_reactions(self, reactions: Dict[str, List[str]]) -> str:
        """Render message reactions."""
        if not reactions:
            return ""

        html = '<div class="message-reactions">'
        for emoji, users in reactions.items():
            count = len(users)
            html += f"""
                <span class="reaction" onclick="toggleReaction('{emoji}')">
                    {emoji} {count}
                </span>
            """
        html += '</div>'
        return html

    def render_create_thread_modal(self) -> str:
        """Render the create thread modal."""
        html = """
        <div class="modal" id="create-thread-modal">
            <div class="modal-content">
                <div class="modal-header">
                    <h3>Create New Thread</h3>
                    <button class="close-btn" onclick="closeCreateThreadModal()">
                        <i class="fas fa-times"></i>
                    </button>
                </div>
                <div class="modal-body">
                    <form id="create-thread-form">
                        <div class="form-group">
                            <label for="thread-title">Thread Title</label>
                            <input
                                type="text"
                                id="thread-title"
                                placeholder="Enter thread title..."
                                required
                            >
                        </div>
                        <div class="form-group">
                            <label for="thread-channel">Channel</label>
                            <select id="thread-channel" required>
                                <option value="">Select a channel...</option>
                            </select>
                        </div>
                        <div class="form-group">
                            <label for="thread-message">Initial Message (Optional)</label>
                            <textarea
                                id="thread-message"
                                placeholder="Start the conversation..."
                                rows="4"
                            ></textarea>
                        </div>
                    </form>
                </div>
                <div class="modal-footer">
                    <button class="cancel-btn" onclick="closeCreateThreadModal()">Cancel</button>
                    <button class="create-btn" onclick="createThread()">Create Thread</button>
                </div>
            </div>
        </div>
        """
        return html

    def get_javascript(self) -> str:
        """Get JavaScript code for thread functionality."""
        return """
        // Thread management functions
        let currentThread = null;
        let activeThreads = [];

        async function loadThreads(channelId) {
            try {
                const response = await fetch(`/api/v1/threads/channel/${channelId}`);
                const threads = await response.json();

                activeThreads = threads;
                renderThreadList(threads);
            } catch (error) {
                console.error('Error loading threads:', error);
            }
        }

        async function selectThread(threadId) {
            try {
                currentThread = threadId;

                // Load thread details
                const threadResponse = await fetch(`/api/v1/threads/${threadId}`);
                const thread = await threadResponse.json();

                // Load thread messages
                const messagesResponse = await fetch(`/api/v1/threads/${threadId}/messages`);
                const messages = await messagesResponse.json();

                renderThreadView(thread, messages);

                // Join thread for real-time updates
                joinThreadWebSocket(threadId);
            } catch (error) {
                console.error('Error selecting thread:', error);
            }
        }

        async function createThread() {
            const title = document.getElementById('thread-title').value;
            const channelId = document.getElementById('thread-channel').value;
            const initialMessage = document.getElementById('thread-message').value;

            try {
                const response = await fetch('/api/v1/threads/', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({
                        title: title,
                        channel_id: channelId
                    })
                });

                const thread = await response.json();

                if (initialMessage) {
                    await sendThreadMessage(thread.thread_id, initialMessage);
                }

                closeCreateThreadModal();
                loadThreads(channelId);
                selectThread(thread.thread_id);
            } catch (error) {
                console.error('Error creating thread:', error);
            }
        }

        async function sendThreadMessage(threadId = currentThread, content = null) {
            if (!threadId) return;

            const messageContent = content || document.getElementById('thread-message-input').value;
            if (!messageContent.trim()) return;

            try {
                const response = await fetch(`/api/v1/threads/${threadId}/messages`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({
                        content: messageContent
                    })
                });

                const result = await response.json();

                // Clear input
                document.getElementById('thread-message-input').value = '';

                // Refresh thread messages
                await selectThread(threadId);
            } catch (error) {
                console.error('Error sending thread message:', error);
            }
        }

        async function toggleThreadResolved(threadId) {
            try {
                await fetch(`/api/v1/threads/${threadId}/resolve`, {
                    method: 'POST'
                });

                // Refresh thread
                await selectThread(threadId);
            } catch (error) {
                console.error('Error toggling thread resolution:', error);
            }
        }

        function showCreateThreadModal() {
            document.getElementById('create-thread-modal').style.display = 'block';
        }

        function closeCreateThreadModal() {
            document.getElementById('create-thread-modal').style.display = 'none';
            document.getElementById('create-thread-form').reset();
        }

        // WebSocket integration
        function joinThreadWebSocket(threadId) {
            if (window.ws) {
                window.ws.send(JSON.stringify({
                    type: 'join_thread',
                    thread_id: threadId
                }));
            }
        }

        function leaveThreadWebSocket(threadId) {
            if (window.ws) {
                window.ws.send(JSON.stringify({
                    type: 'leave_thread',
                    thread_id: threadId
                }));
            }
        }

        // Message reactions
        async function toggleReaction(emoji) {
            // Implementation for reaction toggling
            console.log('Toggle reaction:', emoji);
        }

        // Render functions
        function renderThreadList(threads) {
            const threadList = document.querySelector('.thread-list');
            if (!threadList) return;

            threadList.innerHTML = threads.map(thread => `
                <div class="thread-item ${thread.thread_id === currentThread ? 'active' : ''}"
                     onclick="selectThread('${thread.thread_id}')">
                    <div class="thread-info">
                        <div class="thread-title">${thread.title}</div>
                        <div class="thread-meta">
                            <span class="thread-participants">${thread.participant_count} participants</span>
                            <span class="thread-messages">${thread.message_count} messages</span>
                        </div>
                    </div>
                    <div class="thread-status">
                        ${thread.is_resolved ? '<span class="resolved-badge">✓</span>' : ''}
                    </div>
                </div>
            `).join('');
        }

        function renderThreadView(thread, messages) {
            const threadView = document.querySelector('.thread-view') || document.createElement('div');
            threadView.className = 'thread-view';
            threadView.id = `thread-${thread.thread_id}`;

            threadView.innerHTML = `
                <div class="thread-header">
                    <div class="thread-info">
                        <h2>${thread.title}</h2>
                        <div class="thread-details">
                            <span class="thread-creator">Created by ${thread.creator_id}</span>
                            <span class="thread-participants">${thread.participant_count} participants</span>
                            <span class="thread-messages">${thread.message_count} messages</span>
                        </div>
                    </div>
                    <div class="thread-actions">
                        <button class="thread-action-btn" onclick="toggleThreadResolved('${thread.thread_id}')">
                            ${thread.is_resolved ? 'Reopen Thread' : 'Mark Resolved'}
                        </button>
                        <button class="thread-action-btn" onclick="leaveThread('${thread.thread_id}')">
                            Leave Thread
                        </button>
                    </div>
                </div>

                <div class="thread-messages" id="thread-messages-${thread.thread_id}">
                    ${messages.map(msg => renderThreadMessage(msg)).join('')}
                </div>

                <div class="thread-input">
                    <div class="message-input-container">
                        <textarea
                            id="thread-message-input"
                            placeholder="Reply to this thread..."
                            rows="3"
                        ></textarea>
                        <button class="send-btn" onclick="sendThreadMessage()">
                            <i class="fas fa-paper-plane"></i>
                        </button>
                    </div>
                </div>
            `;

            const container = document.querySelector('.main-content') || document.body;
            container.appendChild(threadView);
        }

        function renderThreadMessage(message) {
            const timestamp = new Date(message.timestamp);
            const formattedTime = timestamp.toLocaleTimeString([], {hour: '2-digit', minute:'2-digit'});

            return `
                <div class="thread-message" data-message-id="${message.message_id}">
                    <div class="message-avatar">
                        <img src="/api/v1/users/${message.sender_id}/avatar" alt="Avatar" onerror="this.src='/static/default-avatar.png'">
                    </div>
                    <div class="message-content">
                        <div class="message-header">
                            <span class="message-author">${message.sender_id}</span>
                            <span class="message-time">${formattedTime}</span>
                        </div>
                        <div class="message-text">${message.content}</div>
                        ${renderMessageReactions(message.reactions || {})}
                    </div>
                </div>
            `;
        }

        function renderMessageReactions(reactions) {
            if (!Object.keys(reactions).length) return '';

            return `
                <div class="message-reactions">
                    ${Object.entries(reactions).map(([emoji, users]) =>
                        `<span class="reaction" onclick="toggleReaction('${emoji}')">
                            ${emoji} ${users.length}
                        </span>`
                    ).join('')}
                </div>
            `;
        }
        """

    def get_css(self) -> str:
        """Get CSS styles for thread components."""
        return """
        /* Thread Components Styles */
        .thread-sidebar {
            width: 300px;
            background: #f8f9fa;
            border-right: 1px solid #e9ecef;
            display: flex;
            flex-direction: column;
        }

        .thread-header {
            padding: 16px;
            border-bottom: 1px solid #e9ecef;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .thread-header h3 {
            margin: 0;
            font-size: 18px;
            font-weight: 600;
        }

        .create-thread-btn {
            background: #007bff;
            color: white;
            border: none;
            border-radius: 50%;
            width: 32px;
            height: 32px;
            display: flex;
            align-items: center;
            justify-content: center;
            cursor: pointer;
            transition: background-color 0.2s;
        }

        .create-thread-btn:hover {
            background: #0056b3;
        }

        .thread-list {
            flex: 1;
            overflow-y: auto;
        }

        .thread-item {
            padding: 12px 16px;
            border-bottom: 1px solid #e9ecef;
            cursor: pointer;
            transition: background-color 0.2s;
        }

        .thread-item:hover {
            background: #e9ecef;
        }

        .thread-item.active {
            background: #007bff;
            color: white;
        }

        .thread-item.active .thread-title {
            color: white;
        }

        .thread-title {
            font-weight: 500;
            margin-bottom: 4px;
        }

        .thread-meta {
            font-size: 12px;
            color: #6c757d;
        }

        .thread-item.active .thread-meta {
            color: rgba(255, 255, 255, 0.8);
        }

        .thread-status {
            margin-top: 4px;
        }

        .resolved-badge {
            background: #28a745;
            color: white;
            padding: 2px 6px;
            border-radius: 10px;
            font-size: 10px;
        }

        .thread-view {
            flex: 1;
            display: flex;
            flex-direction: column;
        }

        .thread-view .thread-header {
            padding: 16px;
            border-bottom: 1px solid #e9ecef;
            background: white;
        }

        .thread-view .thread-info h2 {
            margin: 0 0 8px 0;
            font-size: 20px;
            font-weight: 600;
        }

        .thread-details {
            display: flex;
            gap: 16px;
            font-size: 14px;
            color: #6c757d;
        }

        .thread-actions {
            display: flex;
            gap: 8px;
        }

        .thread-action-btn {
            padding: 6px 12px;
            border: 1px solid #007bff;
            background: white;
            color: #007bff;
            border-radius: 4px;
            cursor: pointer;
            font-size: 12px;
            transition: all 0.2s;
        }

        .thread-action-btn:hover {
            background: #007bff;
            color: white;
        }

        .thread-messages {
            flex: 1;
            overflow-y: auto;
            padding: 16px;
        }

        .thread-message {
            display: flex;
            margin-bottom: 16px;
        }

        .message-avatar {
            width: 32px;
            height: 32px;
            border-radius: 50%;
            margin-right: 12px;
            flex-shrink: 0;
        }

        .message-avatar img {
            width: 100%;
            height: 100%;
            border-radius: 50%;
            object-fit: cover;
        }

        .message-content {
            flex: 1;
        }

        .message-header {
            display: flex;
            align-items: center;
            margin-bottom: 4px;
        }

        .message-author {
            font-weight: 500;
            margin-right: 8px;
        }

        .message-time {
            font-size: 12px;
            color: #6c757d;
        }

        .message-text {
            line-height: 1.4;
        }

        .message-reactions {
            margin-top: 8px;
            display: flex;
            flex-wrap: wrap;
            gap: 4px;
        }

        .reaction {
            background: #f8f9fa;
            border: 1px solid #e9ecef;
            border-radius: 12px;
            padding: 2px 8px;
            font-size: 12px;
            cursor: pointer;
            transition: all 0.2s;
        }

        .reaction:hover {
            background: #e9ecef;
        }

        .thread-input {
            padding: 16px;
            border-top: 1px solid #e9ecef;
            background: white;
        }

        .message-input-container {
            display: flex;
            gap: 8px;
            align-items: flex-end;
        }

        #thread-message-input {
            flex: 1;
            border: 1px solid #e9ecef;
            border-radius: 4px;
            padding: 8px 12px;
            resize: vertical;
            font-family: inherit;
        }

        .send-btn {
            background: #007bff;
            color: white;
            border: none;
            border-radius: 4px;
            padding: 8px 16px;
            cursor: pointer;
            transition: background-color 0.2s;
        }

        .send-btn:hover {
            background: #0056b3;
        }

        /* Modal Styles */
        .modal {
            display: none;
            position: fixed;
            z-index: 1000;
            left: 0;
            top: 0;
            width: 100%;
            height: 100%;
            background-color: rgba(0, 0, 0, 0.5);
        }

        .modal-content {
            background-color: white;
            margin: 10% auto;
            padding: 0;
            border-radius: 8px;
            width: 90%;
            max-width: 500px;
        }

        .modal-header {
            padding: 16px 20px;
            border-bottom: 1px solid #e9ecef;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .modal-header h3 {
            margin: 0;
        }

        .close-btn {
            background: none;
            border: none;
            font-size: 20px;
            cursor: pointer;
            color: #6c757d;
        }

        .modal-body {
            padding: 20px;
        }

        .form-group {
            margin-bottom: 16px;
        }

        .form-group label {
            display: block;
            margin-bottom: 4px;
            font-weight: 500;
        }

        .form-group input,
        .form-group select,
        .form-group textarea {
            width: 100%;
            padding: 8px 12px;
            border: 1px solid #e9ecef;
            border-radius: 4px;
            font-family: inherit;
        }

        .modal-footer {
            padding: 16px 20px;
            border-top: 1px solid #e9ecef;
            display: flex;
            justify-content: flex-end;
            gap: 8px;
        }

        .cancel-btn {
            padding: 8px 16px;
            border: 1px solid #6c757d;
            background: white;
            color: #6c757d;
            border-radius: 4px;
            cursor: pointer;
        }

        .create-btn {
            padding: 8px 16px;
            border: none;
            background: #007bff;
            color: white;
            border-radius: 4px;
            cursor: pointer;
        }

        .create-btn:hover {
            background: #0056b3;
        }

        /* Responsive Design */
        @media (max-width: 768px) {
            .thread-sidebar {
                width: 100%;
                position: fixed;
                top: 0;
                left: -100%;
                height: 100%;
                z-index: 100;
                transition: left 0.3s;
            }

            .thread-sidebar.open {
                left: 0;
            }

            .thread-view {
                width: 100%;
            }
        }
        """


# Global thread component instance
thread_component = ThreadComponent()