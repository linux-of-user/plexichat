/**
 * Typing Indicator Component for PlexiChat
 * Handles real-time typing indicators in chat channels
 */

class TypingIndicator {
    constructor(container, channelId, currentUserId) {
        this.container = container;
        this.channelId = channelId;
        this.currentUserId = currentUserId;
        this.typingUsers = new Set();
        this.typingTimeout = 3000; // 3 seconds
        this.typingTimeouts = new Map();

        this.init();
    }

    init() {
        this.createIndicatorElement();
        this.bindEvents();
    }

    createIndicatorElement() {
        this.indicatorElement = document.createElement('div');
        this.indicatorElement.className = 'typing-indicator';
        this.indicatorElement.style.cssText = `
            display: none;
            padding: 8px 16px;
            font-size: 0.875rem;
            color: #666;
            font-style: italic;
            border-top: 1px solid #e0e0e0;
            background: #f8f9fa;
        `;

        const typingDots = document.createElement('div');
        typingDots.className = 'typing-dots';
        typingDots.style.cssText = `
            display: inline-block;
            margin-right: 8px;
        `;

        for (let i = 0; i < 3; i++) {
            const dot = document.createElement('span');
            dot.className = 'typing-dot';
            dot.style.cssText = `
                display: inline-block;
                width: 4px;
                height: 4px;
                border-radius: 50%;
                background: #666;
                margin: 0 2px;
                animation: typing-bounce 1.4s infinite ease-in-out;
                animation-delay: ${i * 0.16}s;
            `;
            typingDots.appendChild(dot);
        }

        this.textElement = document.createElement('span');
        this.textElement.className = 'typing-text';

        this.indicatorElement.appendChild(typingDots);
        this.indicatorElement.appendChild(this.textElement);

        this.container.appendChild(this.indicatorElement);

        // Add CSS animation
        if (!document.getElementById('typing-indicator-styles')) {
            const style = document.createElement('style');
            style.id = 'typing-indicator-styles';
            style.textContent = `
                @keyframes typing-bounce {
                    0%, 80%, 100% {
                        transform: scale(0);
                        opacity: 0.5;
                    }
                    40% {
                        transform: scale(1);
                        opacity: 1;
                    }
                }
            `;
            document.head.appendChild(style);
        }
    }

    bindEvents() {
        // Listen for WebSocket typing events
        if (window.WebSocketManager) {
            window.WebSocketManager.on('typing_start', (data) => {
                if (data.channel_id === this.channelId && data.user_id !== this.currentUserId) {
                    this.addTypingUser(data.user_id);
                }
            });

            window.WebSocketManager.on('typing_stop', (data) => {
                if (data.channel_id === this.channelId) {
                    this.removeTypingUser(data.user_id);
                }
            });
        }
    }

    addTypingUser(userId) {
        this.typingUsers.add(userId);
        this.updateDisplay();

        // Clear existing timeout for this user
        if (this.typingTimeouts.has(userId)) {
            clearTimeout(this.typingTimeouts.get(userId));
        }

        // Set timeout to auto-remove typing indicator
        const timeout = setTimeout(() => {
            this.removeTypingUser(userId);
        }, this.typingTimeout);

        this.typingTimeouts.set(userId, timeout);
    }

    removeTypingUser(userId) {
        this.typingUsers.delete(userId);

        // Clear timeout
        if (this.typingTimeouts.has(userId)) {
            clearTimeout(this.typingTimeouts.get(userId));
            this.typingTimeouts.delete(userId);
        }

        this.updateDisplay();
    }

    updateDisplay() {
        if (this.typingUsers.size === 0) {
            this.indicatorElement.style.display = 'none';
            return;
        }

        this.indicatorElement.style.display = 'block';

        const userNames = Array.from(this.typingUsers).map(userId => {
            // In a real app, you'd look up the username
            return `User ${userId}`;
        });

        let text;
        if (userNames.length === 1) {
            text = `${userNames[0]} is typing...`;
        } else if (userNames.length === 2) {
            text = `${userNames[0]} and ${userNames[1]} are typing...`;
        } else {
            text = `${userNames[0]} and ${userNames.length - 1} others are typing...`;
        }

        this.textElement.textContent = text;
    }

    startTyping() {
        this.sendTypingEvent('start');
    }

    stopTyping() {
        this.sendTypingEvent('stop');
    }

    sendTypingEvent(action) {
        if (!this.currentUserId) return;

        const endpoint = `/collaboration/chat/typing/${action}`;
        const data = {
            user_id: this.currentUserId.toString(),
            channel_id: this.channelId
        };

        fetch(endpoint, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(data)
        }).catch(error => {
            console.error('Error sending typing event:', error);
        });
    }

    destroy() {
        // Clear all timeouts
        this.typingTimeouts.forEach(timeout => clearTimeout(timeout));
        this.typingTimeouts.clear();

        // Remove element
        if (this.indicatorElement && this.indicatorElement.parentNode) {
            this.indicatorElement.parentNode.removeChild(this.indicatorElement);
        }
    }
}

// Input handler for typing events
class TypingInputHandler {
    constructor(inputElement, typingIndicator, delay = 1000) {
        this.inputElement = inputElement;
        this.typingIndicator = typingIndicator;
        this.delay = delay;
        this.typingTimeout = null;
        this.isTyping = false;

        this.bindEvents();
    }

    bindEvents() {
        this.inputElement.addEventListener('input', () => {
            this.handleInput();
        });

        this.inputElement.addEventListener('keydown', (e) => {
            if (e.key === 'Enter' && !e.shiftKey) {
                this.stopTyping();
            }
        });

        this.inputElement.addEventListener('blur', () => {
            this.stopTyping();
        });
    }

    handleInput() {
        if (!this.isTyping) {
            this.startTyping();
        }

        // Reset the timeout
        if (this.typingTimeout) {
            clearTimeout(this.typingTimeout);
        }

        this.typingTimeout = setTimeout(() => {
            this.stopTyping();
        }, this.delay);
    }

    startTyping() {
        this.isTyping = true;
        this.typingIndicator.startTyping();
    }

    stopTyping() {
        if (this.isTyping) {
            this.isTyping = false;
            this.typingIndicator.stopTyping();

            if (this.typingTimeout) {
                clearTimeout(this.typingTimeout);
                this.typingTimeout = null;
            }
        }
    }

    destroy() {
        if (this.typingTimeout) {
            clearTimeout(this.typingTimeout);
        }
        this.stopTyping();
    }
}

// Export for global use
window.TypingIndicator = TypingIndicator;
window.TypingInputHandler = TypingInputHandler;