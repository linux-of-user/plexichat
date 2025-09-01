/**
 * Chat Application for PlexiChat
 * Handles real-time messaging and typing indicators
 */

class ChatApp {
    constructor(channelId, currentUserId) {
        this.channelId = channelId;
        this.currentUserId = currentUserId;
        this.messages = [];
        this.members = [];
        this.typingIndicator = null;
        this.typingInputHandler = null;

        this.init();
    }

    async init() {
        this.bindElements();
        this.setupTypingIndicator();
        this.loadMessages();
        this.loadMembers();
        this.bindEvents();
        this.connectWebSocket();
    }

    bindElements() {
        this.messagesContainer = document.getElementById('messages-container');
        this.messagesList = document.getElementById('messages-list');
        this.messageForm = document.getElementById('message-form');
        this.messageInput = document.getElementById('message-input');
        this.sendButton = document.getElementById('send-button');
        this.typingIndicatorContainer = document.getElementById('typing-indicator-container');
        this.membersList = document.getElementById('members-list');
        this.memberCount = document.getElementById('member-count');
    }

    setupTypingIndicator() {
        // Initialize typing indicator
        this.typingIndicator = new TypingIndicator(
            this.typingIndicatorContainer,
            this.channelId,
            this.currentUserId
        );

        // Initialize typing input handler
        this.typingInputHandler = new TypingInputHandler(
            this.messageInput,
            this.typingIndicator
        );
    }

    bindEvents() {
        // Message form submission
        this.messageForm.addEventListener('submit', (e) => {
            e.preventDefault();
            this.sendMessage();
        });

        // Enter key handling
        this.messageInput.addEventListener('keydown', (e) => {
            if (e.key === 'Enter' && !e.shiftKey) {
                e.preventDefault();
                this.sendMessage();
            }
        });

        // Auto-resize textarea
        this.messageInput.addEventListener('input', () => {
            this.autoResizeTextarea();
        });
    }

    connectWebSocket() {
        // WebSocket connection will be handled by WebSocketManager
        // Listen for incoming messages
        if (window.WebSocketManager) {
            window.WebSocketManager.on('message', (data) => {
                if (data.channel_id === this.channelId) {
                    this.addMessage(data);
                }
            });

            window.WebSocketManager.on('typing_start', (data) => {
                if (data.channel_id === this.channelId && data.user_id !== this.currentUserId) {
                    this.typingIndicator.addTypingUser(data.user_id);
                }
            });

            window.WebSocketManager.on('typing_stop', (data) => {
                if (data.channel_id === this.channelId) {
                    this.typingIndicator.removeTypingUser(data.user_id);
                }
            });
        }
    }

    async loadMessages() {
        try {
            const response = await fetch(`/collaboration/chat/messages?channel_id=${this.channelId}`);
            const data = await response.json();

            if (data.messages) {
                this.messages = data.messages;
                this.renderMessages();
            }
        } catch (error) {
            console.error('Error loading messages:', error);
        }
    }

    async loadMembers() {
        // For now, just show current user
        this.members = [{
            id: this.currentUserId,
            name: 'You',
            status: 'online'
        }];
        this.renderMembers();
    }

    async sendMessage() {
        const content = this.messageInput.value.trim();
        if (!content) return;

        // Stop typing indicator
        this.typingInputHandler.stopTyping();

        try {
            const response = await fetch('/collaboration/chat/messages/send', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    user_id: this.currentUserId.toString(),
                    channel_id: this.channelId,
                    content: content,
                    message_type: 'text'
                })
            });

            const data = await response.json();

            if (data.status === 'success') {
                // Clear input
                this.messageInput.value = '';
                this.autoResizeTextarea();

                // Add message to UI immediately
                this.addMessage({
                    id: data.message_id,
                    sender_id: this.currentUserId,
                    content: content,
                    timestamp: new Date().toISOString(),
                    message_type: 'text'
                });
            } else {
                console.error('Error sending message:', data);
            }
        } catch (error) {
            console.error('Error sending message:', error);
        }
    }

    addMessage(message) {
        // Check if message already exists
        if (this.messages.find(m => m.metadata?.message_id === message.id || m.id === message.id)) {
            return;
        }

        this.messages.push(message);
        this.renderMessages();

        // Scroll to bottom
        this.scrollToBottom();
    }

    renderMessages() {
        this.messagesList.innerHTML = '';

        this.messages.forEach(message => {
            const messageElement = this.createMessageElement(message);
            this.messagesList.appendChild(messageElement);
        });
    }

    createMessageElement(message) {
        const messageDiv = document.createElement('div');
        messageDiv.className = `message ${message.sender_id == this.currentUserId ? 'own' : 'other'}`;

        const content = message.content || message.metadata?.content || '';
        const timestamp = message.timestamp || message.metadata?.timestamp || new Date().toISOString();
        const senderId = message.sender_id || message.metadata?.sender_id || 'Unknown';

        messageDiv.innerHTML = `
            <div class="message-avatar">
                <div class="avatar-placeholder">${senderId[0].toUpperCase()}</div>
            </div>
            <div class="message-content">
                <div class="message-header">
                    <span class="message-sender">User ${senderId}</span>
                    <span class="message-time">${this.formatTime(timestamp)}</span>
                </div>
                <div class="message-text">${this.escapeHtml(content)}</div>
            </div>
        `;

        return messageDiv;
    }

    renderMembers() {
        this.membersList.innerHTML = '';
        this.memberCount.textContent = this.members.length;

        this.members.forEach(member => {
            const memberElement = document.createElement('div');
            memberElement.className = 'member-item';

            memberElement.innerHTML = `
                <div class="member-avatar">
                    <div class="avatar-placeholder">${member.name[0].toUpperCase()}</div>
                </div>
                <div class="member-info">
                    <div class="member-name">${member.name}</div>
                    <div class="member-status ${member.status}"></div>
                </div>
            `;

            this.membersList.appendChild(memberElement);
        });
    }

    autoResizeTextarea() {
        this.messageInput.style.height = 'auto';
        this.messageInput.style.height = Math.min(this.messageInput.scrollHeight, 120) + 'px';
    }

    scrollToBottom() {
        this.messagesContainer.scrollTop = this.messagesContainer.scrollHeight;
    }

    formatTime(timestamp) {
        const date = new Date(timestamp);
        return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    }

    escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    destroy() {
        if (this.typingIndicator) {
            this.typingIndicator.destroy();
        }
        if (this.typingInputHandler) {
            this.typingInputHandler.destroy();
        }
    }
}

// Export for global use
window.ChatApp = ChatApp;