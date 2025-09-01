/**
 * PlexiChat WebSocket Manager
 * Handles real-time communication and events
 */

class WebSocketManager {
  constructor() {
    this.socket = null;
    this.reconnectAttempts = 0;
    this.maxReconnectAttempts = 5;
    this.reconnectDelay = 1000;
    this.heartbeatInterval = null;
    this.heartbeatTimeout = 30000; // 30 seconds
    this.isConnected = false;
    this.messageQueue = [];
    this.eventListeners = new Map();
    this.typingTimeouts = new Map();
     this.typingUsers = new Map(); // Track typing users per channel

    this.setupEventListeners();
  }

  /**
   * Setup global event listeners
   */
  setupEventListeners() {
    // Handle page visibility changes
    document.addEventListener('visibilitychange', () => {
      if (document.hidden) {
        this.pauseHeartbeat();
      } else {
        this.resumeHeartbeat();
      }
    });

    // Handle before unload
    window.addEventListener('beforeunload', () => {
      this.disconnect();
    });

    // Handle network changes
    window.addEventListener('online', () => {
      if (!this.isConnected) {
        this.connect();
      }
    });

    window.addEventListener('offline', () => {
      this.handleDisconnect();
    });
  }

  /**
   * Connect to WebSocket server
   * @returns {Promise}
   */
  async connect() {
    if (this.socket && this.socket.readyState === WebSocket.OPEN) {
      return Promise.resolve();
    }

    return new Promise((resolve, reject) => {
      try {
        const wsUrl = this.buildWebSocketUrl();
        this.socket = new WebSocket(wsUrl);

        this.socket.onopen = () => {
          console.log('WebSocket connected');
          this.isConnected = true;
          this.reconnectAttempts = 0;
          this.startHeartbeat();
          this.processMessageQueue();
          this.emit('connected');
          resolve();
        };

        this.socket.onmessage = (event) => {
          this.handleMessage(event);
        };

        this.socket.onclose = (event) => {
          console.log('WebSocket disconnected:', event.code, event.reason);
          this.handleDisconnect();
          if (!event.wasClean) {
            this.attemptReconnect();
          }
        };

        this.socket.onerror = (error) => {
          console.error('WebSocket error:', error);
          this.emit('error', error);
          reject(error);
        };

        // Connection timeout
        setTimeout(() => {
          if (this.socket.readyState === WebSocket.CONNECTING) {
            this.socket.close();
            reject(new Error('WebSocket connection timeout'));
          }
        }, 10000);

      } catch (error) {
        console.error('WebSocket connection error:', error);
        reject(error);
      }
    });
  }

  /**
   * Build WebSocket URL with authentication
   * @returns {string}
   */
  buildWebSocketUrl() {
    const baseUrl = window.ChatAPI?.wsUrl || 'ws://localhost:8000/ws';
    const token = this.getAuthToken();

    if (token) {
      return `${baseUrl}?token=${token}`;
    }

    return baseUrl;
  }

  /**
   * Get authentication token
   * @returns {string|null}
   */
  getAuthToken() {
    // Try to get token from various sources
    return (
      Utils.storage.get('auth_token') ||
      document.cookie.split(';').find(c => c.trim().startsWith('auth_token='))?.split('=')[1] ||
      null
    );
  }

  /**
   * Handle incoming WebSocket messages
   * @param {MessageEvent} event - WebSocket message event
   */
  handleMessage(event) {
    try {
      const data = JSON.parse(event.data);
      this.emit('message', data);

      // Handle different message types
      switch (data.type) {
        case 'heartbeat':
          this.handleHeartbeat(data);
          break;
        case 'message':
          this.handleChatMessage(data);
          break;
        case 'presence':
          this.handlePresenceUpdate(data);
          break;
        case 'typing':
           this.handleTypingIndicator(data);
           break;
         case 'typing_start':
           this.handleTypingStart(data);
           break;
         case 'typing_stop':
           this.handleTypingStop(data);
           break;
        case 'reaction':
          this.handleReaction(data);
          break;
        case 'notification':
          this.handleNotification(data);
          break;
        case 'guild_update':
          this.handleGuildUpdate(data);
          break;
        case 'channel_update':
          this.handleChannelUpdate(data);
          break;
        case 'user_update':
          this.handleUserUpdate(data);
          break;
        case 'error':
          this.handleError(data);
          break;
        default:
          console.warn('Unknown message type:', data.type);
      }
    } catch (error) {
      console.error('WebSocket message parse error:', error);
      this.emit('parse_error', error);
    }
  }

  /**
   * Handle heartbeat messages
   * @param {Object} data - Heartbeat data
   */
  handleHeartbeat(data) {
    // Send heartbeat response
    this.send({ type: 'heartbeat_ack', timestamp: data.timestamp });
  }

  /**
   * Handle chat messages
   * @param {Object} data - Message data
   */
  handleChatMessage(data) {
    this.emit('chat_message', data);

    // Update UI if message container exists
    if (data.channel_id) {
      this.updateMessageUI(data);
    }

    // Play notification sound for mentions
    if (this.isMentioned(data)) {
      this.playNotificationSound();
    }
  }

  /**
   * Handle presence updates
   * @param {Object} data - Presence data
   */
  handlePresenceUpdate(data) {
    this.emit('presence_update', data);
    this.updatePresenceUI(data);
  }

  /**
    * Handle typing indicators
    * @param {Object} data - Typing data
    */
   handleTypingIndicator(data) {
     this.emit('typing', data);

     const key = `${data.channel_id}-${data.user_id}`;
     const timeout = this.typingTimeouts.get(key);

     if (timeout) {
       clearTimeout(timeout);
     }

     // Show typing indicator
     this.showTypingIndicator(data);

     // Hide after 3 seconds
     this.typingTimeouts.set(key, setTimeout(() => {
       this.hideTypingIndicator(data);
       this.typingTimeouts.delete(key);
     }, 3000));
   }

   /**
    * Handle typing start event
    * @param {Object} data - Typing start data
    */
   handleTypingStart(data) {
     this.emit('typing_start', data);

     const channelId = data.channel_id;
     const userId = data.user_id;

     if (!this.typingUsers.has(channelId)) {
       this.typingUsers.set(channelId, new Set());
     }

     this.typingUsers.get(channelId).add(userId);

     const key = `${channelId}-${userId}`;
     const timeout = this.typingTimeouts.get(key);

     if (timeout) {
       clearTimeout(timeout);
     }

     // Show typing indicator
     this.showTypingIndicator(data);

     // Auto-hide after 5 seconds if no stop received
     this.typingTimeouts.set(key, setTimeout(() => {
       this.hideTypingIndicator(data);
       this.typingTimeouts.delete(key);
       // Remove user from typing users
       if (this.typingUsers.has(channelId)) {
         this.typingUsers.get(channelId).delete(userId);
         if (this.typingUsers.get(channelId).size === 0) {
           this.typingUsers.delete(channelId);
         }
       }
     }, 5000));
   }

   /**
    * Handle typing stop event
    * @param {Object} data - Typing stop data
    */
   handleTypingStop(data) {
     this.emit('typing_stop', data);

     const channelId = data.channel_id;
     const userId = data.user_id;

     const key = `${channelId}-${userId}`;
     const timeout = this.typingTimeouts.get(key);

     if (timeout) {
       clearTimeout(timeout);
       this.typingTimeouts.delete(key);
     }

     // Remove user from typing users
     if (this.typingUsers.has(channelId)) {
       this.typingUsers.get(channelId).delete(userId);
       if (this.typingUsers.get(channelId).size === 0) {
         this.typingUsers.delete(channelId);
       }
     }

     // Hide typing indicator
     this.hideTypingIndicator(data);
   }

  /**
   * Handle reactions
   * @param {Object} data - Reaction data
   */
  handleReaction(data) {
    this.emit('reaction', data);
    this.updateReactionUI(data);
  }

  /**
   * Handle notifications
   * @param {Object} data - Notification data
   */
  handleNotification(data) {
    this.emit('notification', data);
    this.showNotification(data);
  }

  /**
   * Handle guild updates
   * @param {Object} data - Guild data
   */
  handleGuildUpdate(data) {
    this.emit('guild_update', data);
    this.updateGuildUI(data);
  }

  /**
   * Handle channel updates
   * @param {Object} data - Channel data
   */
  handleChannelUpdate(data) {
    this.emit('channel_update', data);
    this.updateChannelUI(data);
  }

  /**
   * Handle user updates
   * @param {Object} data - User data
   */
  handleUserUpdate(data) {
    this.emit('user_update', data);
    this.updateUserUI(data);
  }

  /**
   * Handle WebSocket errors
   * @param {Object} data - Error data
   */
  handleError(data) {
    console.error('WebSocket error:', data);
    this.emit('ws_error', data);
  }

  /**
   * Send message via WebSocket
   * @param {Object} data - Message data
   * @returns {boolean} - Success status
   */
  send(data) {
    if (!this.isConnected || !this.socket) {
      console.warn('WebSocket not connected, queuing message');
      this.messageQueue.push(data);
      return false;
    }

    try {
      this.socket.send(JSON.stringify(data));
      return true;
    } catch (error) {
      console.error('WebSocket send error:', error);
      this.messageQueue.push(data);
      return false;
    }
  }

  /**
   * Send chat message
   * @param {string} channelId - Channel ID
   * @param {string} content - Message content
   * @param {Object} options - Additional options
   */
  sendMessage(channelId, content, options = {}) {
    const message = {
      type: 'message',
      channel_id: channelId,
      content: content,
      timestamp: new Date().toISOString(),
      ...options
    };

    return this.send(message);
  }

  /**
   * Send typing indicator
   * @param {string} channelId - Channel ID
   */
  sendTyping(channelId) {
    this.send({
      type: 'typing',
      channel_id: channelId,
      timestamp: new Date().toISOString()
    });
  }
   /**
    * Send typing start event
    * @param {string} channelId - Channel ID
    */
   sendTypingStart(channelId) {
     this.send({
       type: 'typing_start',
       channel_id: channelId,
       user_id: window.ChatAPI?.currentUser?.id,
       timestamp: new Date().toISOString()
     });
   }

   /**
    * Send typing stop event
    * @param {string} channelId - Channel ID
    */
   sendTypingStop(channelId) {
     this.send({
       type: 'typing_stop',
       channel_id: channelId,
       user_id: window.ChatAPI?.currentUser?.id,
       timestamp: new Date().toISOString()
     });
   }

  /**
   * Update user presence
   * @param {string} status - User status
   * @param {string} activity - User activity
   */
  updatePresence(status, activity = null) {
    this.send({
      type: 'presence',
      status: status,
      activity: activity,
      timestamp: new Date().toISOString()
    });
  }

  /**
   * Add reaction to message
   * @param {string} messageId - Message ID
   * @param {string} emoji - Emoji
   */
  addReaction(messageId, emoji) {
    this.send({
      type: 'reaction',
      action: 'add',
      message_id: messageId,
      emoji: emoji,
      timestamp: new Date().toISOString()
    });
  }

  /**
   * Remove reaction from message
   * @param {string} messageId - Message ID
   * @param {string} emoji - Emoji
   */
  removeReaction(messageId, emoji) {
    this.send({
      type: 'reaction',
      action: 'remove',
      message_id: messageId,
      emoji: emoji,
      timestamp: new Date().toISOString()
    });
  }

  /**
   * Join channel
   * @param {string} channelId - Channel ID
   */
  joinChannel(channelId) {
    this.send({
      type: 'join_channel',
      channel_id: channelId,
      timestamp: new Date().toISOString()
    });
  }

  /**
   * Leave channel
   * @param {string} channelId - Channel ID
   */
  leaveChannel(channelId) {
    this.send({
      type: 'leave_channel',
      channel_id: channelId,
      timestamp: new Date().toISOString()
    });
  }

  /**
   * Get typing users for a channel
   * @param {string} channelId - Channel ID
   * @returns {Set} - Set of typing user IDs
   */
  getTypingUsers(channelId) {
    return this.typingUsers.get(channelId) || new Set();
  }

  /**
   * Start heartbeat
   */
  startHeartbeat() {
    this.stopHeartbeat();
    this.heartbeatInterval = setInterval(() => {
      if (this.isConnected) {
        this.send({
          type: 'heartbeat',
          timestamp: Date.now()
        });
      }
    }, this.heartbeatTimeout / 2);
  }

  /**
   * Stop heartbeat
   */
  stopHeartbeat() {
    if (this.heartbeatInterval) {
      clearInterval(this.heartbeatInterval);
      this.heartbeatInterval = null;
    }
  }

  /**
   * Pause heartbeat (when page is hidden)
   */
  pauseHeartbeat() {
    this.stopHeartbeat();
  }

  /**
   * Resume heartbeat (when page is visible)
   */
  resumeHeartbeat() {
    if (this.isConnected) {
      this.startHeartbeat();
    }
  }

  /**
   * Handle disconnection
   */
  handleDisconnect() {
    this.isConnected = false;
    this.stopHeartbeat();
    this.clearTypingTimeouts();
    this.emit('disconnected');
  }

  /**
   * Attempt to reconnect
   */
  attemptReconnect() {
    if (this.reconnectAttempts >= this.maxReconnectAttempts) {
      console.error('Max WebSocket reconnect attempts reached');
      this.emit('max_reconnect_attempts_reached');
      return;
    }

    this.reconnectAttempts++;
    const delay = this.reconnectDelay * Math.pow(2, this.reconnectAttempts - 1);

    console.log(`Attempting WebSocket reconnect (${this.reconnectAttempts}/${this.maxReconnectAttempts}) in ${delay}ms`);

    setTimeout(() => {
      this.connect().catch(error => {
        console.error('Reconnect failed:', error);
      });
    }, delay);
  }

  /**
   * Process queued messages
   */
  processMessageQueue() {
    while (this.messageQueue.length > 0 && this.isConnected) {
      const message = this.messageQueue.shift();
      this.send(message);
    }
  }

  /**
   * Clear typing timeouts
   */
  clearTypingTimeouts() {
    this.typingTimeouts.forEach(timeout => clearTimeout(timeout));
    this.typingTimeouts.clear();
  }

  /**
   * Disconnect from WebSocket
   */
  disconnect() {
    this.isConnected = false;
    this.stopHeartbeat();
    this.clearTypingTimeouts();

    if (this.socket) {
      this.socket.close(1000, 'Client disconnect');
      this.socket = null;
    }

    this.emit('disconnected');
  }

  /**
   * Add event listener
   * @param {string} event - Event name
   * @param {Function} callback - Event callback
   */
  on(event, callback) {
    if (!this.eventListeners.has(event)) {
      this.eventListeners.set(event, []);
    }
    this.eventListeners.get(event).push(callback);
  }

  /**
   * Remove event listener
   * @param {string} event - Event name
   * @param {Function} callback - Event callback
   */
  off(event, callback) {
    if (this.eventListeners.has(event)) {
      const listeners = this.eventListeners.get(event);
      const index = listeners.indexOf(callback);
      if (index > -1) {
        listeners.splice(index, 1);
      }
    }
  }

  /**
   * Emit event
   * @param {string} event - Event name
   * @param {*} data - Event data
   */
  emit(event, data) {
    if (this.eventListeners.has(event)) {
      this.eventListeners.get(event).forEach(callback => {
        try {
          callback(data);
        } catch (error) {
          console.error('Event callback error:', error);
        }
      });
    }

    // Also emit to global Utils events
    Utils.events.emit(`websocket:${event}`, data);
  }

  // UI Update Methods (to be implemented by specific UI components)

  /**
   * Update message UI
   * @param {Object} data - Message data
   */
  updateMessageUI(data) {
    // Implementation depends on UI framework
    this.emit('ui_update_message', data);
  }

  /**
   * Update presence UI
   * @param {Object} data - Presence data
   */
  updatePresenceUI(data) {
    this.emit('ui_update_presence', data);
  }

  /**
   * Show typing indicator
   * @param {Object} data - Typing data
   */
  showTypingIndicator(data) {
    this.emit('ui_show_typing', data);
  }

  /**
   * Hide typing indicator
   * @param {Object} data - Typing data
   */
  hideTypingIndicator(data) {
    this.emit('ui_hide_typing', data);
  }

  /**
   * Update reaction UI
   * @param {Object} data - Reaction data
   */
  updateReactionUI(data) {
    this.emit('ui_update_reaction', data);
  }

  /**
   * Show notification
   * @param {Object} data - Notification data
   */
  showNotification(data) {
    this.emit('ui_show_notification', data);
  }

  /**
   * Update guild UI
   * @param {Object} data - Guild data
   */
  updateGuildUI(data) {
    this.emit('ui_update_guild', data);
  }

  /**
   * Update channel UI
   * @param {Object} data - Channel data
   */
  updateChannelUI(data) {
    this.emit('ui_update_channel', data);
  }

  /**
   * Update user UI
   * @param {Object} data - User data
   */
  updateUserUI(data) {
    this.emit('ui_update_user', data);
  }

  /**
   * Check if user is mentioned in message
   * @param {Object} data - Message data
   * @returns {boolean}
   */
  isMentioned(data) {
    const currentUser = window.ChatAPI?.currentUser;
    if (!currentUser || !data.content) return false;

    const mentionPatterns = [
      `@${currentUser.username}`,
      `@${currentUser.display_name || currentUser.username}`,
      `<@${currentUser.id}>`
    ];

    return mentionPatterns.some(pattern =>
      data.content.toLowerCase().includes(pattern.toLowerCase())
    );
  }

  /**
   * Play notification sound
   */
  playNotificationSound() {
    // Create audio context if supported
    if (typeof Audio !== 'undefined') {
      try {
        const audio = new Audio('/static/sounds/notification.mp3');
        audio.volume = 0.3;
        audio.play().catch(() => {
          // Fallback: create beep sound
          this.createBeepSound();
        });
      } catch (error) {
        this.createBeepSound();
      }
    }
  }

  /**
   * Create beep sound as fallback
   */
  createBeepSound() {
    if (typeof AudioContext !== 'undefined' || typeof webkitAudioContext !== 'undefined') {
      try {
        const AudioCtx = AudioContext || webkitAudioContext;
        const audioContext = new AudioCtx();
        const oscillator = audioContext.createOscillator();
        const gainNode = audioContext.createGain();

        oscillator.connect(gainNode);
        gainNode.connect(audioContext.destination);

        oscillator.frequency.setValueAtTime(800, audioContext.currentTime);
        oscillator.frequency.setValueAtTime(600, audioContext.currentTime + 0.1);

        gainNode.gain.setValueAtTime(0.3, audioContext.currentTime);
        gainNode.gain.exponentialRampToValueAtTime(0.01, audioContext.currentTime + 0.2);

        oscillator.start(audioContext.currentTime);
        oscillator.stop(audioContext.currentTime + 0.2);
      } catch (error) {
        // Silent fallback
      }
    }
  }

  /**
   * Get connection status
   * @returns {Object}
   */
  getStatus() {
    return {
      connected: this.isConnected,
      reconnectAttempts: this.reconnectAttempts,
      maxReconnectAttempts: this.maxReconnectAttempts,
      messageQueueLength: this.messageQueue.length
    };
  }
}

// Create global WebSocket instance
window.WebSocketManager = new WebSocketManager();