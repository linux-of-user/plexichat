/**
 * PlexiChat WebSocket Client
 * Handles real-time communication with enhanced keyboard shortcut support
 */

class WebSocketClient {
    constructor() {
        this.socket = null;
        this.reconnectAttempts = 0;
        this.maxReconnectAttempts = 5;
        this.reconnectDelay = 1000;
        this.isConnected = false;
        this.messageHandlers = new Map();
        this.eventQueue = [];
        this.heartbeatInterval = null;

        // Initialize message handlers
        this.setupMessageHandlers();

        // Connect on initialization
        this.connect();
    }

    setupMessageHandlers() {
        // Standard message types
        this.messageHandlers.set('message', this.handleMessage.bind(this));
        this.messageHandlers.set('user_joined', this.handleUserJoined.bind(this));
        this.messageHandlers.set('user_left', this.handleUserLeft.bind(this));
        this.messageHandlers.set('typing_start', this.handleTypingStart.bind(this));
        this.messageHandlers.set('typing_stop', this.handleTypingStop.bind(this));
        this.messageHandlers.set('error', this.handleError.bind(this));

        // Keyboard shortcut specific handlers
        this.messageHandlers.set('keyboard_shortcut_update', this.handleKeyboardShortcutUpdate.bind(this));
        this.messageHandlers.set('keyboard_shortcut_conflict', this.handleKeyboardShortcutConflict.bind(this));
        this.messageHandlers.set('keyboard_shortcut_registered', this.handleKeyboardShortcutRegistered.bind(this));
    }

    connect() {
        try {
            const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
            const wsUrl = `${protocol}//${window.location.host}/ws`;

            this.socket = new WebSocket(wsUrl);

            this.socket.onopen = this.onOpen.bind(this);
            this.socket.onmessage = this.onMessage.bind(this);
            this.socket.onclose = this.onClose.bind(this);
            this.socket.onerror = this.onError.bind(this);

        } catch (error) {
            console.error('WebSocket connection failed:', error);
            this.handleReconnect();
        }
    }

    onOpen(event) {
        console.log('WebSocket connected');
        this.isConnected = true;
        this.reconnectAttempts = 0;

        // Send authentication if available
        const sessionId = this.getSessionId();
        if (sessionId) {
            this.send({
                type: 'authenticate',
                session_id: sessionId
            });
        }

        // Start heartbeat
        this.startHeartbeat();

        // Process queued events
        this.processEventQueue();

        // Emit connection event
        this.emit('connected', { event });
    }

    onMessage(event) {
        try {
            const data = JSON.parse(event.data);
            this.handleMessage(data);
        } catch (error) {
            console.error('Failed to parse WebSocket message:', error);
        }
    }

    onClose(event) {
        console.log('WebSocket disconnected:', event.code, event.reason);
        this.isConnected = false;
        this.stopHeartbeat();

        if (!event.wasClean) {
            this.handleReconnect();
        }

        this.emit('disconnected', { event });
    }

    onError(event) {
        console.error('WebSocket error:', event);
        this.emit('error', { event });
    }

    handleReconnect() {
        if (this.reconnectAttempts < this.maxReconnectAttempts) {
            this.reconnectAttempts++;
            const delay = this.reconnectDelay * Math.pow(2, this.reconnectAttempts - 1);

            console.log(`Attempting to reconnect (${this.reconnectAttempts}/${this.maxReconnectAttempts}) in ${delay}ms`);

            setTimeout(() => {
                this.connect();
            }, delay);
        } else {
            console.error('Max reconnection attempts reached');
            this.emit('maxReconnectAttemptsReached');
        }
    }

    send(data) {
        if (this.isConnected && this.socket) {
            try {
                this.socket.send(JSON.stringify(data));
            } catch (error) {
                console.error('Failed to send WebSocket message:', error);
                // Queue the message for retry
                this.eventQueue.push(data);
            }
        } else {
            // Queue the message for when connection is restored
            this.eventQueue.push(data);
        }
    }

    processEventQueue() {
        while (this.eventQueue.length > 0 && this.isConnected) {
            const event = this.eventQueue.shift();
            this.send(event);
        }
    }

    startHeartbeat() {
        this.heartbeatInterval = setInterval(() => {
            if (this.isConnected) {
                this.send({ type: 'heartbeat' });
            }
        }, 30000); // 30 seconds
    }

    stopHeartbeat() {
        if (this.heartbeatInterval) {
            clearInterval(this.heartbeatInterval);
            this.heartbeatInterval = null;
        }
    }

    getSessionId() {
        return localStorage.getItem('plexichat_session') ||
               document.cookie.split('; ')
                   .find(row => row.startsWith('plexichat_session='))
                   ?.split('=')[1];
    }

    // Message handlers
    handleMessage(data) {
        const handler = this.messageHandlers.get(data.type);
        if (handler) {
            handler(data);
        } else {
            console.warn('No handler for message type:', data.type);
        }
    }

    handleUserJoined(data) {
        this.emit('userJoined', data);
    }

    handleUserLeft(data) {
        this.emit('userLeft', data);
    }

    handleTypingStart(data) {
        this.emit('typingStart', data);
    }

    handleTypingStop(data) {
        this.emit('typingStop', data);
    }

    handleError(data) {
        console.error('WebSocket error:', data.message);
        this.emit('error', data);
    }

    // Keyboard shortcut specific handlers
    handleKeyboardShortcutUpdate(data) {
        console.log('Keyboard shortcut update:', data);
        this.emit('keyboardShortcutUpdate', data);
    }

    handleKeyboardShortcutConflict(data) {
        console.warn('Keyboard shortcut conflict:', data);
        this.emit('keyboardShortcutConflict', data);
    }

    handleKeyboardShortcutRegistered(data) {
        console.log('Keyboard shortcut registered:', data);
        this.emit('keyboardShortcutRegistered', data);
    }

    // Event system
    emit(eventName, data = {}) {
        const event = new CustomEvent('websocket:' + eventName, {
            detail: data,
            bubbles: true
        });
        document.dispatchEvent(event);
    }

    on(eventName, callback) {
        document.addEventListener('websocket:' + eventName, (e) => {
            callback(e.detail);
        });
    }

    // Cleanup
    disconnect() {
        if (this.socket) {
            this.socket.close(1000, 'Client disconnecting');
        }
        this.stopHeartbeat();
    }
}

// Create global WebSocket client instance
const websocketClient = new WebSocketClient();

// Export for global access
window.websocketClient = websocketClient;