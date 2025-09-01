/**
 * PlexiChat API Client
 * Handles all API interactions with the backend
 */

class APIClient {
  constructor() {
    this.baseUrl = window.ChatAPI?.apiUrl || '/api/v1';
    this.csrfToken = window.ChatAPI?.csrfToken || '';
    this.requestQueue = [];
    this.isOnline = navigator.onLine;
    this.retryDelay = 1000;
    this.maxRetries = 3;

    this.setupNetworkListeners();
  }

  /**
   * Setup network status listeners
   */
  setupNetworkListeners() {
    window.addEventListener('online', () => {
      this.isOnline = true;
      this.processQueue();
      Utils.events.emit('network:online');
    });

    window.addEventListener('offline', () => {
      this.isOnline = false;
      Utils.events.emit('network:offline');
    });
  }

  /**
   * Make HTTP request with error handling and retries
   * @param {string} endpoint - API endpoint
   * @param {Object} options - Request options
   * @returns {Promise}
   */
  async request(endpoint, options = {}) {
    const url = `${this.baseUrl}${endpoint}`;
    const config = {
      headers: {
        'Content-Type': 'application/json',
        'X-CSRF-Token': this.csrfToken,
        ...options.headers
      },
      ...options
    };

    // Add body if provided
    if (options.body && typeof options.body === 'object') {
      config.body = JSON.stringify(options.body);
    }

    // Handle offline state
    if (!this.isOnline && options.method !== 'GET') {
      return this.queueRequest(endpoint, config);
    }

    let retries = 0;
    while (retries <= this.maxRetries) {
      try {
        const response = await fetch(url, config);

        // Handle different response types
        let data;
        const contentType = response.headers.get('content-type');

        if (contentType && contentType.includes('application/json')) {
          data = await response.json();
        } else {
          data = await response.text();
        }

        // Handle HTTP errors
        if (!response.ok) {
          throw new APIError(response.status, data.message || response.statusText, data);
        }

        // Emit success event
        Utils.events.emit('api:success', { endpoint, data });

        return { data, status: response.status, headers: response.headers };

      } catch (error) {
        retries++;

        if (error.name === 'TypeError' && error.message.includes('fetch')) {
          // Network error
          if (retries <= this.maxRetries) {
            await this.delay(this.retryDelay * retries);
            continue;
          }
          throw new APIError(0, 'Network error', error);
        }

        if (error instanceof APIError) {
          // Handle specific API errors
          this.handleAPIError(error, endpoint);
          throw error;
        }

        // Other errors
        if (retries <= this.maxRetries) {
          await this.delay(this.retryDelay * retries);
          continue;
        }

        throw error;
      }
    }
  }

  /**
   * Queue request for offline handling
   * @param {string} endpoint - API endpoint
   * @param {Object} config - Request config
   * @returns {Promise}
   */
  queueRequest(endpoint, config) {
    return new Promise((resolve, reject) => {
      this.requestQueue.push({
        endpoint,
        config,
        resolve,
        reject,
        timestamp: Date.now()
      });

      Utils.events.emit('api:queued', { endpoint });
    });
  }

  /**
   * Process queued requests when back online
   */
  async processQueue() {
    while (this.requestQueue.length > 0) {
      const request = this.requestQueue.shift();
      try {
        const result = await this.request(request.endpoint, request.config);
        request.resolve(result);
      } catch (error) {
        request.reject(error);
      }
    }
  }

  /**
   * Handle API errors
   * @param {APIError} error - API error
   * @param {string} endpoint - API endpoint
   */
  handleAPIError(error, endpoint) {
    Utils.events.emit('api:error', { error, endpoint });

    switch (error.status) {
      case 401:
        // Unauthorized - redirect to login
        if (window.location.pathname !== '/auth/login') {
          window.location.href = '/auth/login';
        }
        break;
      case 403:
        // Forbidden
        Utils.events.emit('api:forbidden', { endpoint });
        break;
      case 429:
        // Rate limited
        Utils.events.emit('api:rate-limited', { endpoint });
        break;
      case 500:
        // Server error
        Utils.events.emit('api:server-error', { endpoint, error });
        break;
    }
  }

  /**
   * Delay helper
   * @param {number} ms - Milliseconds to delay
   * @returns {Promise}
   */
  delay(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  // Authentication endpoints
  auth = {
    /**
     * Login user
     * @param {string} username - Username
     * @param {string} password - Password
     * @returns {Promise}
     */
    login: (username, password) => {
      return this.request('/auth/login', {
        method: 'POST',
        body: { username, password }
      });
    },

    /**
     * Logout user
     * @returns {Promise}
     */
    logout: () => {
      return this.request('/auth/logout', {
        method: 'POST'
      });
    },

    /**
     * Register new user
     * @param {Object} userData - User registration data
     * @returns {Promise}
     */
    register: (userData) => {
      return this.request('/auth/register', {
        method: 'POST',
        body: userData
      });
    },

    /**
     * Get current user profile
     * @returns {Promise}
     */
    getProfile: () => {
      return this.request('/auth/profile');
    },

    /**
     * Update user profile
     * @param {Object} profileData - Profile data
     * @returns {Promise}
     */
    updateProfile: (profileData) => {
      return this.request('/auth/profile', {
        method: 'PUT',
        body: profileData
      });
    }
  };

  // Chat endpoints
  chat = {
    /**
     * Get channels/guilds
     * @param {Object} params - Query parameters
     * @returns {Promise}
     */
    getChannels: (params = {}) => {
      const query = new URLSearchParams(params).toString();
      return this.request(`/chat/channels?${query}`);
    },

    /**
     * Get channel messages
     * @param {string} channelId - Channel ID
     * @param {Object} params - Query parameters
     * @returns {Promise}
     */
    getMessages: (channelId, params = {}) => {
      const query = new URLSearchParams(params).toString();
      return this.request(`/chat/channels/${channelId}/messages?${query}`);
    },

    /**
     * Send message
     * @param {string} channelId - Channel ID
     * @param {string} content - Message content
     * @param {Object} options - Additional options
     * @returns {Promise}
     */
    sendMessage: (channelId, content, options = {}) => {
      return this.request(`/chat/channels/${channelId}/messages`, {
        method: 'POST',
        body: { content, ...options }
      });
    },

    /**
     * Edit message
     * @param {string} messageId - Message ID
     * @param {string} content - New content
     * @returns {Promise}
     */
    editMessage: (messageId, content) => {
      return this.request(`/chat/messages/${messageId}`, {
        method: 'PUT',
        body: { content }
      });
    },

    /**
     * Delete message
     * @param {string} messageId - Message ID
     * @returns {Promise}
     */
    deleteMessage: (messageId) => {
      return this.request(`/chat/messages/${messageId}`, {
        method: 'DELETE'
      });
    },

    /**
     * Add reaction to message
     * @param {string} messageId - Message ID
     * @param {string} emoji - Emoji
     * @returns {Promise}
     */
    addReaction: (messageId, emoji) => {
      return this.request(`/chat/messages/${messageId}/reactions`, {
        method: 'POST',
        body: { emoji }
      });
    },

    /**
     * Remove reaction from message
     * @param {string} messageId - Message ID
     * @param {string} emoji - Emoji
     * @returns {Promise}
     */
    removeReaction: (messageId, emoji) => {
      return this.request(`/chat/messages/${messageId}/reactions`, {
        method: 'DELETE',
        body: { emoji }
      });
    }
  };

  // User endpoints
  users = {
    /**
     * Get user by ID
     * @param {string} userId - User ID
     * @returns {Promise}
     */
    getUser: (userId) => {
      return this.request(`/users/${userId}`);
    },

    /**
     * Get user presence/status
     * @param {string} userId - User ID
     * @returns {Promise}
     */
    getPresence: (userId) => {
      return this.request(`/users/${userId}/presence`);
    },

    /**
     * Update user presence
     * @param {string} status - Status
     * @param {string} activity - Activity
     * @returns {Promise}
     */
    updatePresence: (status, activity = null) => {
      return this.request('/users/@me/presence', {
        method: 'PUT',
        body: { status, activity }
      });
    },

    /**
     * Get user relationships
     * @returns {Promise}
     */
    getRelationships: () => {
      return this.request('/users/@me/relationships');
    },

    /**
     * Send friend request
     * @param {string} username - Username
     * @returns {Promise}
     */
    sendFriendRequest: (username) => {
      return this.request('/users/@me/relationships', {
        method: 'POST',
        body: { username }
      });
    }
  };

  // File endpoints
  files = {
    /**
     * Upload file
     * @param {FormData} formData - File data
     * @param {Object} options - Upload options
     * @returns {Promise}
     */
    upload: (formData, options = {}) => {
      return this.request('/files/upload', {
        method: 'POST',
        body: formData,
        headers: {
          // Don't set Content-Type for FormData
          ...options.headers
        }
      });
    },

    /**
     * Get file info
     * @param {string} fileId - File ID
     * @returns {Promise}
     */
    getFile: (fileId) => {
      return this.request(`/files/${fileId}`);
    },

    /**
     * Delete file
     * @param {string} fileId - File ID
     * @returns {Promise}
     */
    deleteFile: (fileId) => {
      return this.request(`/files/${fileId}`, {
        method: 'DELETE'
      });
    },

    /**
     * Get file download URL
     * @param {string} fileId - File ID
     * @returns {string}
     */
    getDownloadUrl: (fileId) => {
      return `${this.baseUrl}/files/${fileId}/download`;
    }
  };

  // Guild/Server endpoints
  guilds = {
    /**
     * Get user's guilds
     * @returns {Promise}
     */
    getGuilds: () => {
      return this.request('/guilds');
    },

    /**
     * Get guild by ID
     * @param {string} guildId - Guild ID
     * @returns {Promise}
     */
    getGuild: (guildId) => {
      return this.request(`/guilds/${guildId}`);
    },

    /**
     * Create guild
     * @param {Object} guildData - Guild data
     * @returns {Promise}
     */
    createGuild: (guildData) => {
      return this.request('/guilds', {
        method: 'POST',
        body: guildData
      });
    },

    /**
     * Update guild
     * @param {string} guildId - Guild ID
     * @param {Object} guildData - Guild data
     * @returns {Promise}
     */
    updateGuild: (guildId, guildData) => {
      return this.request(`/guilds/${guildId}`, {
        method: 'PUT',
        body: guildData
      });
    },

    /**
     * Delete guild
     * @param {string} guildId - Guild ID
     * @returns {Promise}
     */
    deleteGuild: (guildId) => {
      return this.request(`/guilds/${guildId}`, {
        method: 'DELETE'
      });
    },

    /**
     * Get guild members
     * @param {string} guildId - Guild ID
     * @returns {Promise}
     */
    getMembers: (guildId) => {
      return this.request(`/guilds/${guildId}/members`);
    },

    /**
     * Add member to guild
     * @param {string} guildId - Guild ID
     * @param {string} userId - User ID
     * @returns {Promise}
     */
    addMember: (guildId, userId) => {
      return this.request(`/guilds/${guildId}/members`, {
        method: 'POST',
        body: { user_id: userId }
      });
    },

    /**
     * Remove member from guild
     * @param {string} guildId - Guild ID
     * @param {string} userId - User ID
     * @returns {Promise}
     */
    removeMember: (guildId, userId) => {
      return this.request(`/guilds/${guildId}/members/${userId}`, {
        method: 'DELETE'
      });
    }
  };

  // Admin endpoints
  admin = {
    /**
     * Get system stats
     * @returns {Promise}
     */
    getStats: () => {
      return this.request('/admin/stats');
    },

    /**
     * Get system logs
     * @param {Object} params - Query parameters
     * @returns {Promise}
     */
    getLogs: (params = {}) => {
      const query = new URLSearchParams(params).toString();
      return this.request(`/admin/logs?${query}`);
    },

    /**
     * Get users list
     * @param {Object} params - Query parameters
     * @returns {Promise}
     */
    getUsers: (params = {}) => {
      const query = new URLSearchParams(params).toString();
      return this.request(`/admin/users?${query}`);
    },

    /**
     * Update user
     * @param {string} userId - User ID
     * @param {Object} userData - User data
     * @returns {Promise}
     */
    updateUser: (userId, userData) => {
      return this.request(`/admin/users/${userId}`, {
        method: 'PUT',
        body: userData
      });
    },

    /**
     * Delete user
     * @param {string} userId - User ID
     * @returns {Promise}
     */
    deleteUser: (userId) => {
      return this.request(`/admin/users/${userId}`, {
        method: 'DELETE'
      });
    },

    /**
     * Get system settings
     * @returns {Promise}
     */
    getSettings: () => {
      return this.request('/admin/settings');
    },

    /**
     * Update system settings
     * @param {Object} settings - Settings data
     * @returns {Promise}
     */
    updateSettings: (settings) => {
      return this.request('/admin/settings', {
        method: 'PUT',
        body: settings
      });
    }
  };

  // WebSocket connection for real-time updates
  websocket = {
    socket: null,
    reconnectAttempts: 0,
    maxReconnectAttempts: 5,
    reconnectDelay: 1000,

    /**
     * Connect to WebSocket
     * @returns {Promise}
     */
    connect: () => {
      return new Promise((resolve, reject) => {
        if (this.socket && this.socket.readyState === WebSocket.OPEN) {
          resolve(this.socket);
          return;
        }

        const wsUrl = window.ChatAPI?.wsUrl || 'ws://localhost:8000/ws';
        this.socket = new WebSocket(wsUrl);

        this.socket.onopen = () => {
          console.log('WebSocket connected');
          this.reconnectAttempts = 0;
          Utils.events.emit('websocket:connected');
          resolve(this.socket);
        };

        this.socket.onmessage = (event) => {
          try {
            const data = JSON.parse(event.data);
            this.handleMessage(data);
          } catch (error) {
            console.error('WebSocket message parse error:', error);
          }
        };

        this.socket.onclose = () => {
          console.log('WebSocket disconnected');
          Utils.events.emit('websocket:disconnected');
          this.attemptReconnect();
        };

        this.socket.onerror = (error) => {
          console.error('WebSocket error:', error);
          Utils.events.emit('websocket:error', error);
          reject(error);
        };
      });
    },

    /**
     * Handle incoming WebSocket messages
     * @param {Object} data - Message data
     */
    handleMessage: (data) => {
      Utils.events.emit('websocket:message', data);

      switch (data.type) {
        case 'message':
          Utils.events.emit('chat:message', data);
          break;
        case 'presence':
          Utils.events.emit('user:presence', data);
          break;
        case 'typing':
          Utils.events.emit('chat:typing', data);
          break;
        case 'reaction':
          Utils.events.emit('chat:reaction', data);
          break;
        case 'notification':
          Utils.events.emit('notification:new', data);
          break;
      }
    },

    /**
     * Send message via WebSocket
     * @param {Object} data - Message data
     */
    send: (data) => {
      if (this.socket && this.socket.readyState === WebSocket.OPEN) {
        this.socket.send(JSON.stringify(data));
      } else {
        console.warn('WebSocket not connected');
      }
    },

    /**
     * Attempt to reconnect WebSocket
     */
    attemptReconnect: () => {
      if (this.reconnectAttempts >= this.maxReconnectAttempts) {
        console.error('Max WebSocket reconnect attempts reached');
        return;
      }

      this.reconnectAttempts++;
      const delay = this.reconnectDelay * Math.pow(2, this.reconnectAttempts - 1);

      setTimeout(() => {
        console.log(`Attempting WebSocket reconnect (${this.reconnectAttempts}/${this.maxReconnectAttempts})`);
        this.connect();
      }, delay);
    },

    /**
     * Disconnect WebSocket
     */
    disconnect: () => {
      if (this.socket) {
        this.socket.close();
        this.socket = null;
      }
    }
  };
}

/**
 * Custom API Error class
 */
class APIError extends Error {
  constructor(status, message, data = null) {
    super(message);
    this.name = 'APIError';
    this.status = status;
    this.data = data;
  }
}

// Create global API instance
window.API = new APIClient();