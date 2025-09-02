/**
 * PlexiChat Main Application
 * Initializes and coordinates all application components
 */

class PlexiChatApp {
  constructor() {
    this.initialized = false;
    this.components = new Map();
    this.services = new Map();
    this.currentUser = null;
    this.currentChannel = null;
    this.init();
  }

  /**
   * Initialize the application
   */
  async init() {
    if (this.initialized) return;

    try {
      console.log('Initializing PlexiChat...');

      // Initialize core services
      await this.initServices();

      // Initialize UI components
      this.initComponents();

      // Setup event listeners
      this.setupEventListeners();

      // Load initial data
      await this.loadInitialData();

      // Setup real-time connections
      this.setupRealTime();

      // Mark as initialized
      this.initialized = true;

      console.log('PlexiChat initialized successfully');

      // Emit ready event
      Utils.events.emit('app:ready');

    } catch (error) {
      console.error('Failed to initialize PlexiChat:', error);
      this.showError('Failed to initialize application');
    }
  }

  /**
   * Initialize core services
   */
  async initServices() {
    // API service is already initialized globally
    this.services.set('api', window.API);

    // WebSocket service
    this.services.set('websocket', window.WebSocketManager);

    // Notification service
    this.services.set('notifications', window.NotificationManager);

    // UI service
    this.services.set('ui', window.UI);

    // Enhanced UI service
    this.services.set('enhancedUI', window.EnhancedUI);

    // Components service
    this.services.set('components', window.UIComponents);

    // Authenticate user if token exists
    const token = Utils.storage.get('auth_token');
    if (token) {
      try {
        const response = await this.services.get('api').auth.getProfile();
        if (response.data) {
          this.setCurrentUser(response.data);
        }
      } catch (error) {
        console.warn('Failed to authenticate user:', error);
        Utils.storage.remove('auth_token');
      }
    }
  }

  /**
   * Initialize UI components
   */
  initComponents() {
    // Initialize theme
    const theme = Utils.storage.get('theme', 'dark');
    document.documentElement.setAttribute('data-theme', theme);

    // Setup loading screen
    this.setupLoadingScreen();

    // Setup navigation
    this.setupNavigation();

    // Setup theme toggle
    this.setupThemeToggle();

    // Setup search
    this.setupSearch();

    // Setup shortcuts
    this.setupKeyboardShortcuts();
  }

  /**
   * Setup loading screen
   */
  setupLoadingScreen() {
    const loadingScreen = Utils.dom.$('#loading-screen');
    if (loadingScreen) {
      // Hide loading screen after initialization
      setTimeout(() => {
        loadingScreen.classList.add('fade-out');
        setTimeout(() => {
          loadingScreen.style.display = 'none';
        }, 300);
      }, 1000);
    }
  }

  /**
   * Setup navigation
   */
  setupNavigation() {
    // Mobile menu toggle
    Utils.dom.on('#mobile-menu-toggle', 'click', () => {
      const navbar = Utils.dom.$('.navbar-enhanced');
      const nav = Utils.dom.$('.navbar-nav');

      if (navbar && nav) {
        nav.classList.toggle('show');
        navbar.classList.toggle('mobile-menu-open');
      }
    });

    // Navigation links
    Utils.dom.on('.nav-link', 'click', (e) => {
      const link = e.target.closest('.nav-link');
      if (link) {
        // Close mobile menu
        Utils.dom.$('.navbar-nav')?.classList.remove('show');
        Utils.dom.$('.navbar-enhanced')?.classList.remove('mobile-menu-open');

        // Update active state
        Utils.dom.$$('.nav-link').forEach(navLink => {
          navLink.classList.remove('active');
        });
        link.classList.add('active');
      }
    });

    // User menu
    this.setupUserMenu();
  }

  /**
   * Setup user menu
   */
  setupUserMenu() {
    const userMenuToggle = Utils.dom.$('#user-menu-toggle');
    const userMenu = Utils.dom.$('#user-menu-dropdown');

    if (userMenuToggle && userMenu) {
      Utils.dom.on(userMenuToggle, 'click', (e) => {
        e.stopPropagation();
        userMenu.classList.toggle('show');
        userMenuToggle.setAttribute('aria-expanded',
          userMenu.classList.contains('show'));
      });

      // Theme toggle in user menu
      Utils.dom.on('#theme-toggle', 'click', () => {
        if (window.EnhancedUI) {
          window.EnhancedUI.toggleTheme();
        }
      });

      // Logout
      Utils.dom.on('#logout-btn', 'click', (e) => {
        e.preventDefault();
        this.logout();
      });
    }
  }

  /**
   * Setup theme toggle
   */
  setupThemeToggle() {
    const themeToggle = Utils.dom.$('#theme-toggle');
    if (themeToggle) {
      Utils.dom.on(themeToggle, 'click', () => {
        if (window.EnhancedUI) {
          window.EnhancedUI.toggleTheme();
        }
      });
    }
  }

  /**
   * Setup search functionality
   */
  setupSearch() {
    const searchInput = Utils.dom.$('#global-search');
    if (searchInput) {
      let searchTimeout;

      Utils.dom.on(searchInput, 'input', (e) => {
        clearTimeout(searchTimeout);
        searchTimeout = setTimeout(() => {
          this.performSearch(e.target.value);
        }, 300);
      });

      Utils.dom.on(searchInput, 'keydown', (e) => {
        if (e.key === 'Enter') {
          e.preventDefault();
          this.performSearch(e.target.value);
        }
      });
    }
  }

  /**
   * Perform search
   * @param {string} query - Search query
   */
  async performSearch(query) {
    if (!query.trim()) return;

    try {
      // Show loading state
      this.showSearchLoading();

      // Perform search (implement based on backend API)
      const response = await this.services.get('api').request(`/search?q=${encodeURIComponent(query)}`);

      // Display results
      this.displaySearchResults(response.data);

    } catch (error) {
      console.error('Search error:', error);
      this.showSearchError();
    } finally {
      this.hideSearchLoading();
    }
  }

  /**
   * Setup keyboard shortcuts
   */
  setupKeyboardShortcuts() {
    // Initialize Keyboard Shortcuts Manager if available
    if (window.KeyboardShortcutsManager) {
      this.shortcutsManager = window.KeyboardShortcutsManager;

      // Listen for shortcut events
      this.shortcutsManager.on('shortcut_executed', (data) => {
        console.log('Shortcut executed:', data.action);
      });

      this.shortcutsManager.on('shortcut_conflict', (data) => {
        this.showShortcutConflict(data);
      });

      this.shortcutsManager.on('recording_started', () => {
        this.showRecordingIndicator();
      });

      this.shortcutsManager.on('recording_stopped', () => {
        this.hideRecordingIndicator();
      });

      // Setup additional global shortcuts not handled by manager
      document.addEventListener('keydown', (e) => {
        // Escape: Close modals/dropdowns (handled by manager but also here for compatibility)
        if (e.key === 'Escape' && !this.shortcutsManager.isRecordingActive()) {
          this.closeAllOverlays();
        }
      });

      console.log('Keyboard shortcuts manager initialized');
    } else {
      // Fallback to basic shortcuts if manager not available
      console.warn('KeyboardShortcutsManager not available, using fallback');
      this.setupFallbackShortcuts();
    }
  }

  /**
   * Setup fallback keyboard shortcuts
   */
  setupFallbackShortcuts() {
    document.addEventListener('keydown', (e) => {
      // Ignore if typing in input
      if (e.target.matches('input, textarea')) return;

      // Ctrl/Cmd + K: Focus search
      if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
        e.preventDefault();
        const searchInput = Utils.dom.$('#global-search');
        if (searchInput) {
          searchInput.focus();
        }
      }

      // Ctrl/Cmd + /: Focus message input
      if ((e.ctrlKey || e.metaKey) && e.key === '/') {
        e.preventDefault();
        const messageInput = Utils.dom.$('.chat-input-textarea');
        if (messageInput) {
          messageInput.focus();
        }
      }

      // Escape: Close modals/dropdowns
      if (e.key === 'Escape') {
        this.closeAllOverlays();
      }
    });
  }

  /**
   * Show shortcut conflict notification
   * @param {Object} data - Conflict data
   */
  showShortcutConflict(data) {
    const message = `Shortcut "${this.formatShortcutForDisplay(data.shortcut)}" conflicts with existing shortcut for "${data.conflict}". Please choose a different shortcut.`;
    this.showError(message);
  }

  /**
   * Format shortcut for display
   * @param {Object} shortcut - Shortcut object
   * @returns {string}
   */
  formatShortcutForDisplay(shortcut) {
    if (window.KeyboardShortcutsManager) {
      return window.KeyboardShortcutsManager.formatShortcut(shortcut);
    }
    return shortcut.key;
  }

  /**
   * Show recording indicator
   */
  showRecordingIndicator() {
    let indicator = Utils.dom.$('#shortcut-recording-indicator');
    if (!indicator) {
      indicator = Utils.dom.createElement('div', {
        id: 'shortcut-recording-indicator',
        className: 'shortcut-recording-indicator',
        textContent: 'Recording shortcut... Press any key combination'
      });
      document.body.appendChild(indicator);
    }
    indicator.style.display = 'block';
  }

  /**
   * Hide recording indicator
   */
  hideRecordingIndicator() {
    const indicator = Utils.dom.$('#shortcut-recording-indicator');
    if (indicator) {
      indicator.style.display = 'none';
    }
  }

  /**
   * Setup event listeners
   */
  setupEventListeners() {
    // Theme change
    Utils.events.on('theme:changed', (data) => {
      this.updateTheme(data.theme);
    });

    // WebSocket events
    Utils.events.on('websocket:connected', () => {
      this.onWebSocketConnected();
    });

    Utils.events.on('websocket:disconnected', () => {
      this.onWebSocketDisconnected();
    });

    Utils.events.on('websocket:chat_message', (data) => {
      this.onNewMessage(data);
    });

    // API events
    Utils.events.on('api:error', (error) => {
      this.handleAPIError(error);
    });

    // Window events
    window.addEventListener('beforeunload', () => {
      this.cleanup();
    });

    window.addEventListener('online', () => {
      this.onNetworkOnline();
    });

    window.addEventListener('offline', () => {
      this.onNetworkOffline();
    });
  }

  /**
   * Load initial data
   */
  async loadInitialData() {
    if (!this.currentUser) return;

    try {
      // Load user guilds/channels
      const guildsResponse = await this.services.get('api').guilds.getGuilds();
      this.userGuilds = guildsResponse.data || [];

      // Load user settings
      const settingsResponse = await this.services.get('api').request('/users/@me/settings');
      this.userSettings = settingsResponse.data || {};

      // Update UI with loaded data
      this.updateGuildsList();
      this.applyUserSettings();

    } catch (error) {
      console.error('Failed to load initial data:', error);
    }
  }

  /**
   * Setup real-time connections
   */
  setupRealTime() {
    const ws = this.services.get('websocket');
    if (ws) {
      ws.connect().catch(error => {
        console.warn('WebSocket connection failed:', error);
      });
    }
  }

  /**
   * Set current user
   * @param {Object} user - User data
   */
  setCurrentUser(user) {
    this.currentUser = user;
    Utils.storage.set('current_user', user);

    // Update UI
    this.updateUserUI(user);

    // Emit event
    Utils.events.emit('user:changed', user);
  }

  /**
   * Update user UI
   * @param {Object} user - User data
   */
  updateUserUI(user) {
    // Update user menu
    const userName = Utils.dom.$('.user-name');
    const userAvatar = Utils.dom.$('.user-avatar');

    if (userName) {
      userName.textContent = user.display_name || user.username;
    }

    if (userAvatar) {
      userAvatar.src = user.avatar_url || '/static/images/default-avatar.png';
      userAvatar.alt = user.display_name || user.username;
    }

    // Update navigation based on user role
    this.updateNavigationForUser(user);
  }

  /**
   * Update navigation for user
   * @param {Object} user - User data
   */
  updateNavigationForUser(user) {
    // Show/hide admin links
    const adminLinks = Utils.dom.$$('.admin-only');
    adminLinks.forEach(link => {
      link.style.display = user.is_admin ? 'block' : 'none';
    });

    // Update user status
    this.updateUserStatus(user.status || 'online');
  }

  /**
   * Update user status
   * @param {string} status - User status
   */
  updateUserStatus(status) {
    const statusIndicator = Utils.dom.$('.user-status-indicator');
    if (statusIndicator) {
      statusIndicator.className = `user-status-indicator ${status}`;
    }

    // Update WebSocket presence
    const ws = this.services.get('websocket');
    if (ws) {
      ws.updatePresence(status);
    }
  }

  /**
   * Update guilds list
   */
  updateGuildsList() {
    const guildsContainer = Utils.dom.$('#guilds-list');
    if (!guildsContainer || !this.userGuilds) return;

    guildsContainer.innerHTML = '';

    this.userGuilds.forEach(guild => {
      const guildElement = Utils.dom.createElement('div', {
        className: 'guild-item',
        'data-guild-id': guild.id
      });

      const guildIcon = Utils.dom.createElement('img', {
        className: 'guild-icon',
        src: guild.icon_url || '/static/images/default-guild-icon.png',
        alt: guild.name
      });

      const guildName = Utils.dom.createElement('span', {
        className: 'guild-name',
        textContent: guild.name
      });

      guildElement.appendChild(guildIcon);
      guildElement.appendChild(guildName);

      // Click handler
      guildElement.addEventListener('click', () => {
        this.selectGuild(guild);
      });

      guildsContainer.appendChild(guildElement);
    });
  }

  /**
   * Select guild
   * @param {Object} guild - Guild data
   */
  selectGuild(guild) {
    this.currentGuild = guild;

    // Update UI
    Utils.dom.$$('.guild-item').forEach(item => {
      item.classList.remove('active');
    });

    const selectedItem = Utils.dom.$(`[data-guild-id="${guild.id}"]`);
    if (selectedItem) {
      selectedItem.classList.add('active');
    }

    // Load guild channels
    this.loadGuildChannels(guild.id);

    Utils.events.emit('guild:selected', guild);
  }

  /**
   * Load guild channels
   * @param {string} guildId - Guild ID
   */
  async loadGuildChannels(guildId) {
    try {
      const response = await this.services.get('api').guilds.getGuild(guildId);
      const channels = response.data.channels || [];

      this.updateChannelsList(channels);
    } catch (error) {
      console.error('Failed to load guild channels:', error);
    }
  }

  /**
   * Update channels list
   * @param {Array} channels - Channels data
   */
  updateChannelsList(channels) {
    const channelsContainer = Utils.dom.$('#channels-list');
    if (!channelsContainer) return;

    channelsContainer.innerHTML = '';

    channels.forEach(channel => {
      const channelElement = Utils.dom.createElement('div', {
        className: `channel-item ${channel.type}`,
        'data-channel-id': channel.id
      });

      const channelIcon = Utils.dom.createElement('i', {
        className: `fas fa-${channel.type === 'text' ? 'hashtag' : 'volume-up'}`
      });

      const channelName = Utils.dom.createElement('span', {
        className: 'channel-name',
        textContent: channel.name
      });

      channelElement.appendChild(channelIcon);
      channelElement.appendChild(channelName);

      // Click handler
      channelElement.addEventListener('click', () => {
        this.selectChannel(channel);
      });

      channelsContainer.appendChild(channelElement);
    });
  }

  /**
   * Select channel
   * @param {Object} channel - Channel data
   */
  selectChannel(channel) {
    this.currentChannel = channel;

    // Update UI
    Utils.dom.$$('.channel-item').forEach(item => {
      item.classList.remove('active');
    });

    const selectedItem = Utils.dom.$(`[data-channel-id="${channel.id}"]`);
    if (selectedItem) {
      selectedItem.classList.add('active');
    }

    // Load channel messages
    this.loadChannelMessages(channel.id);

    // Join WebSocket channel
    const ws = this.services.get('websocket');
    if (ws) {
      ws.joinChannel(channel.id);
    }

    Utils.events.emit('channel:selected', channel);
  }

  /**
   * Load channel messages
   * @param {string} channelId - Channel ID
   */
  async loadChannelMessages(channelId) {
    try {
      const response = await this.services.get('api').chat.getMessages(channelId);
      const messages = response.data || [];

      this.displayMessages(messages);
    } catch (error) {
      console.error('Failed to load channel messages:', error);
    }
  }

  /**
   * Display messages
   * @param {Array} messages - Messages data
   */
  displayMessages(messages) {
    const messagesContainer = Utils.dom.$('#messages-container');
    if (!messagesContainer) return;

    messagesContainer.innerHTML = '';

    messages.forEach(message => {
      const messageElement = this.createMessageElement(message);
      messagesContainer.appendChild(messageElement);
    });

    // Scroll to bottom
    this.scrollMessagesToBottom();
  }

  /**
   * Create message element
   * @param {Object} message - Message data
   * @returns {Element}
   */
  createMessageElement(message) {
    const messageDiv = Utils.dom.createElement('div', {
      className: `message ${message.author.id === this.currentUser?.id ? 'own' : ''}`,
      'data-message-id': message.id
    });

    const avatar = Utils.dom.createElement('img', {
      className: 'message-avatar',
      src: message.author.avatar_url || '/static/images/default-avatar.png',
      alt: message.author.display_name
    });

    const content = Utils.dom.createElement('div', { className: 'message-content' });

    const header = Utils.dom.createElement('div', { className: 'message-header' });

    const author = Utils.dom.createElement('span', {
      className: 'message-author',
      textContent: message.author.display_name || message.author.username
    });

    const timestamp = Utils.dom.createElement('span', {
      className: 'message-timestamp',
      textContent: Utils.date.relativeTime(message.timestamp)
    });

    header.appendChild(author);
    header.appendChild(timestamp);

    const bubble = Utils.dom.createElement('div', {
      className: 'message-bubble',
      textContent: message.content
    });

    content.appendChild(header);
    content.appendChild(bubble);

    if (message.author.id === this.currentUser?.id) {
      messageDiv.appendChild(content);
      messageDiv.appendChild(avatar);
    } else {
      messageDiv.appendChild(avatar);
      messageDiv.appendChild(content);
    }

    return messageDiv;
  }

  /**
   * Scroll messages to bottom
   */
  scrollMessagesToBottom() {
    const container = Utils.dom.$('#messages-container');
    if (container) {
      container.scrollTop = container.scrollHeight;
    }
  }

  /**
   * Apply user settings
   */
  applyUserSettings() {
    if (!this.userSettings) return;

    // Apply theme
    if (this.userSettings.theme) {
      document.documentElement.setAttribute('data-theme', this.userSettings.theme);
    }

    // Apply notification settings
    if (this.userSettings.notifications !== undefined) {
      const notifications = this.services.get('notifications');
      if (notifications) {
        if (this.userSettings.notifications) {
          notifications.enable();
        } else {
          notifications.disable();
        }
      }
    }
  }

  /**
   * Handle new message
   * @param {Object} data - Message data
   */
  onNewMessage(data) {
    if (data.channel_id === this.currentChannel?.id) {
      const messageElement = this.createMessageElement(data);
      const container = Utils.dom.$('#messages-container');

      if (container) {
        container.appendChild(messageElement);
        this.scrollMessagesToBottom();
      }
    }
  }

  /**
   * Handle WebSocket connected
   */
  onWebSocketConnected() {
    console.log('WebSocket connected');
    Utils.events.emit('connection:online');

    // Update connection status
    this.updateConnectionStatus(true);
  }

  /**
   * Handle WebSocket disconnected
   */
  onWebSocketDisconnected() {
    console.log('WebSocket disconnected');
    Utils.events.emit('connection:offline');

    // Update connection status
    this.updateConnectionStatus(false);
  }

  /**
   * Update connection status
   * @param {boolean} connected - Connection status
   */
  updateConnectionStatus(connected) {
    const statusIndicator = Utils.dom.$('#connection-status .status-dot');
    const statusText = Utils.dom.$('#connection-status .status-text');

    if (statusIndicator) {
      statusIndicator.classList.toggle('connected', connected);
      statusIndicator.classList.toggle('disconnected', !connected);
    }

    if (statusText) {
      statusText.textContent = connected ? 'Connected' : 'Disconnected';
    }
  }

  /**
   * Handle API error
   * @param {Object} error - Error data
   */
  handleAPIError(error) {
    console.error('API Error:', error);

    // Show user-friendly error message
    let message = 'An error occurred. Please try again.';

    if (error.status === 401) {
      message = 'Please log in to continue.';
    } else if (error.status === 403) {
      message = 'You do not have permission to perform this action.';
    } else if (error.status === 404) {
      message = 'The requested resource was not found.';
    } else if (error.status >= 500) {
      message = 'Server error. Please try again later.';
    }

    this.showError(message);
  }

  /**
   * Handle network online
   */
  onNetworkOnline() {
    console.log('Network online');
    Utils.events.emit('network:online');

    // Retry failed requests
    const ws = this.services.get('websocket');
    if (ws && !ws.isConnected) {
      ws.connect();
    }
  }

  /**
   * Handle network offline
   */
  onNetworkOffline() {
    console.log('Network offline');
    Utils.events.emit('network:offline');
  }

  /**
   * Logout user
   */
  async logout() {
    try {
      await this.services.get('api').auth.logout();
    } catch (error) {
      console.warn('Logout API call failed:', error);
    }

    // Clear local data
    Utils.storage.remove('auth_token');
    Utils.storage.remove('current_user');
    this.currentUser = null;

    // Disconnect WebSocket
    const ws = this.services.get('websocket');
    if (ws) {
      ws.disconnect();
    }

    // Redirect to login
    window.location.href = '/auth/login';
  }

  /**
   * Show error message
   * @param {string} message - Error message
   */
  showError(message) {
    const ui = this.services.get('ui');
    if (ui) {
      ui.showToast(message, 'error');
    }
  }

  /**
   * Show search loading
   */
  showSearchLoading() {
    const searchResults = Utils.dom.$('#search-results');
    if (searchResults) {
      searchResults.innerHTML = '<div class="search-loading">Searching...</div>';
    }
  }

  /**
   * Hide search loading
   */
  hideSearchLoading() {
    const loading = Utils.dom.$('.search-loading');
    if (loading) {
      loading.remove();
    }
  }

  /**
   * Display search results
   * @param {Object} data - Search results data
   */
  displaySearchResults(data) {
    const searchResults = Utils.dom.$('#search-results');
    if (!searchResults) return;

    searchResults.innerHTML = '';

    if (!data.results || data.results.length === 0) {
      searchResults.innerHTML = '<div class="no-results">No results found</div>';
      return;
    }

    data.results.forEach(result => {
      const resultElement = Utils.dom.createElement('div', {
        className: 'search-result-item'
      });

      const title = Utils.dom.createElement('div', {
        className: 'search-result-title',
        textContent: result.title
      });

      const snippet = Utils.dom.createElement('div', {
        className: 'search-result-snippet',
        textContent: result.snippet
      });

      resultElement.appendChild(title);
      resultElement.appendChild(snippet);

      resultElement.addEventListener('click', () => {
        this.handleSearchResultClick(result);
      });

      searchResults.appendChild(resultElement);
    });
  }

  /**
   * Show search error
   */
  showSearchError() {
    const searchResults = Utils.dom.$('#search-results');
    if (searchResults) {
      searchResults.innerHTML = '<div class="search-error">Search failed. Please try again.</div>';
    }
  }

  /**
   * Handle search result click
   * @param {Object} result - Search result data
   */
  handleSearchResultClick(result) {
    // Navigate to result
    if (result.type === 'channel') {
      // Switch to channel
      this.selectChannel(result);
    } else if (result.type === 'message') {
      // Switch to channel and scroll to message
      this.selectChannel({ id: result.channel_id });
      // Scroll to message after loading
      setTimeout(() => {
        const messageElement = Utils.dom.$(`[data-message-id="${result.id}"]`);
        if (messageElement) {
          messageElement.scrollIntoView({ behavior: 'smooth' });
        }
      }, 1000);
    }
  }

  /**
   * Close all overlays
   */
  closeAllOverlays() {
    // Close modals
    const modals = Utils.dom.$$('.modal-overlay');
    modals.forEach(modal => modal.remove());

    // Close dropdowns
    Utils.dom.$$('.dropdown-menu.show').forEach(menu => {
      menu.classList.remove('show');
    });

    // Close popovers
    Utils.dom.$$('.popover.show').forEach(popover => {
      popover.classList.remove('show');
    });
  }

  /**
   * Update theme
   * @param {string} theme - New theme
   */
  updateTheme(theme) {
    document.documentElement.setAttribute('data-theme', theme);
    Utils.storage.set('theme', theme);
  }

  /**
   * Cleanup on page unload
   */
  cleanup() {
    // Disconnect WebSocket
    const ws = this.services.get('websocket');
    if (ws) {
      ws.disconnect();
    }

    // Clear intervals/timeouts
    // (Add any cleanup needed)

    console.log('PlexiChat cleaned up');
  }

  /**
   * Get service instance
   * @param {string} name - Service name
   * @returns {Object|null}
   */
  getService(name) {
    return this.services.get(name) || null;
  }

  /**
   * Check if user is authenticated
   * @returns {boolean}
   */
  isAuthenticated() {
    return !!this.currentUser;
  }

  /**
   * Get current user
   * @returns {Object|null}
   */
  getCurrentUser() {
    return this.currentUser;
  }

  /**
   * Get current channel
   * @returns {Object|null}
   */
  getCurrentChannel() {
    return this.currentChannel;
  }

  /**
   * Get current guild
   * @returns {Object|null}
   */
  getCurrentGuild() {
    return this.currentGuild;
  }
}

// Initialize application when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
  window.PlexiChat = new PlexiChatApp();
});

// Export for module usage
if (typeof module !== 'undefined' && module.exports) {
  module.exports = PlexiChatApp;
}