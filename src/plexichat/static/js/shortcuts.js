/**
 * Keyboard Shortcuts Manager
 * Manages keyboard shortcuts with platform detection and conflict resolution
 */

class KeyboardShortcutsManager {
  constructor() {
    this.shortcuts = new Map();
    this.platform = this.detectPlatform();
    this.isRecording = false;
    this.recordingCallback = null;
    this.eventListeners = new Map();
    this.conflicts = new Set();

    this.defaultShortcuts = {
      'send_message': { key: 'Enter', ctrl: false, alt: false, shift: false, meta: false },
      'new_line': { key: 'Enter', ctrl: false, alt: false, shift: true, meta: false },
      'focus_search': { key: 'k', ctrl: true, alt: false, shift: false, meta: true },
      'focus_input': { key: '/', ctrl: true, alt: false, shift: false, meta: true },
      'toggle_theme': { key: 't', ctrl: true, alt: false, shift: true, meta: true },
      'show_help': { key: '/', ctrl: false, alt: false, shift: true, meta: false },
      'channel_1': { key: '1', ctrl: false, alt: true, shift: false, meta: false },
      'channel_2': { key: '2', ctrl: false, alt: true, shift: false, meta: false },
      'channel_3': { key: '3', ctrl: false, alt: true, shift: false, meta: false },
      'channel_4': { key: '4', ctrl: false, alt: true, shift: false, meta: false },
      'channel_5': { key: '5', ctrl: false, alt: true, shift: false, meta: false },
      'channel_6': { key: '6', ctrl: false, alt: true, shift: false, meta: false },
      'channel_7': { key: '7', ctrl: false, alt: true, shift: false, meta: false },
      'channel_8': { key: '8', ctrl: false, alt: true, shift: false, meta: false },
      'channel_9': { key: '9', ctrl: false, alt: true, shift: false, meta: false },
      'next_channel': { key: 'Tab', ctrl: false, alt: false, shift: false, meta: false },
      'prev_channel': { key: 'Tab', ctrl: false, alt: false, shift: true, meta: false },
      'scroll_up': { key: 'ArrowUp', ctrl: false, alt: false, shift: false, meta: false },
      'scroll_down': { key: 'ArrowDown', ctrl: false, alt: false, shift: false, meta: false },
      'page_up': { key: 'PageUp', ctrl: false, alt: false, shift: false, meta: false },
      'page_down': { key: 'PageDown', ctrl: false, alt: false, shift: false, meta: false }
    };

    this.init();
  }

  /**
   * Initialize the shortcuts manager
   */
  init() {
    this.loadShortcuts();
    this.setupEventListeners();
    this.registerDefaultShortcuts();
  }

  /**
   * Detect the user's platform
   * @returns {string} - 'mac', 'windows', 'linux', or 'unknown'
   */
  detectPlatform() {
    const userAgent = navigator.userAgent.toLowerCase();

    if (userAgent.includes('mac')) {
      return 'mac';
    } else if (userAgent.includes('win')) {
      return 'windows';
    } else if (userAgent.includes('linux')) {
      return 'linux';
    }

    return 'unknown';
  }

  /**
   * Setup global event listeners
   */
  setupEventListeners() {
    document.addEventListener('keydown', this.handleKeydown.bind(this));
    document.addEventListener('keyup', this.handleKeyup.bind(this));

    // Listen for WebSocket events
    if (window.WebSocketManager) {
      window.WebSocketManager.on('keyboard_shortcut_update', this.handleShortcutUpdate.bind(this));
      window.WebSocketManager.on('keyboard_shortcut_conflict', this.handleShortcutConflict.bind(this));
      window.WebSocketManager.on('keyboard_shortcut_registered', this.handleShortcutRegistered.bind(this));
    }
  }

  /**
   * Handle keydown events
   * @param {KeyboardEvent} event - Keydown event
   */
  handleKeydown(event) {
    // Skip if recording a shortcut
    if (this.isRecording && this.recordingCallback) {
      event.preventDefault();
      const shortcut = this.parseKeyEvent(event);
      this.recordingCallback(shortcut);
      this.stopRecording();
      return;
    }

    // Skip if typing in input fields (except when explicitly allowed)
    if (this.shouldSkipEvent(event)) {
      return;
    }

    const shortcut = this.parseKeyEvent(event);
    const action = this.findShortcutAction(shortcut);

    if (action) {
      event.preventDefault();
      this.executeAction(action, event);
    }
  }

  /**
   * Handle keyup events
   * @param {KeyboardEvent} event - Keyup event
   */
  handleKeyup(event) {
    // Handle any keyup-specific logic if needed
  }

  /**
   * Check if event should be skipped
   * @param {KeyboardEvent} event - Keyboard event
   * @returns {boolean}
   */
  shouldSkipEvent(event) {
    const target = event.target;

    // Skip if target is an input, textarea, or contenteditable
    if (target.tagName === 'INPUT' ||
        target.tagName === 'TEXTAREA' ||
        target.contentEditable === 'true') {
      return true;
    }

    // Skip if target has specific classes that should allow shortcuts
    if (target.closest('.allow-shortcuts')) {
      return false;
    }

    return false;
  }

  /**
   * Parse keyboard event into shortcut object
   * @param {KeyboardEvent} event - Keyboard event
   * @returns {Object} - Shortcut object
   */
  parseKeyEvent(event) {
    return {
      key: event.key,
      ctrl: event.ctrlKey,
      alt: event.altKey,
      shift: event.shiftKey,
      meta: event.metaKey || event.cmdKey,
      code: event.code
    };
  }

  /**
   * Find action for shortcut
   * @param {Object} shortcut - Shortcut object
   * @returns {string|null} - Action name or null
   */
  findShortcutAction(shortcut) {
    for (const [action, actionShortcut] of this.shortcuts) {
      if (this.shortcutsMatch(shortcut, actionShortcut)) {
        return action;
      }
    }
    return null;
  }

  /**
   * Check if two shortcuts match
   * @param {Object} shortcut1 - First shortcut
   * @param {Object} shortcut2 - Second shortcut
   * @returns {boolean}
   */
  shortcutsMatch(shortcut1, shortcut2) {
    return shortcut1.key === shortcut2.key &&
           shortcut1.ctrl === shortcut2.ctrl &&
           shortcut1.alt === shortcut2.alt &&
           shortcut1.shift === shortcut2.shift &&
           shortcut1.meta === shortcut2.meta;
  }

  /**
   * Execute shortcut action
   * @param {string} action - Action name
   * @param {KeyboardEvent} event - Original keyboard event
   */
  executeAction(action, event) {
    this.emit('shortcut_executed', { action, event });

    switch (action) {
      case 'send_message':
        this.sendMessage();
        break;
      case 'new_line':
        this.insertNewLine();
        break;
      case 'focus_search':
        this.focusSearch();
        break;
      case 'focus_input':
        this.focusInput();
        break;
      case 'toggle_theme':
        this.toggleTheme();
        break;
      case 'show_help':
        this.showHelp();
        break;
      case 'channel_1':
      case 'channel_2':
      case 'channel_3':
      case 'channel_4':
      case 'channel_5':
      case 'channel_6':
      case 'channel_7':
      case 'channel_8':
      case 'channel_9':
        const channelNum = parseInt(action.split('_')[1]);
        this.switchToChannel(channelNum);
        break;
      case 'next_channel':
        this.nextChannel();
        break;
      case 'prev_channel':
        this.prevChannel();
        break;
      case 'scroll_up':
        this.scrollUp();
        break;
      case 'scroll_down':
        this.scrollDown();
        break;
      case 'page_up':
        this.pageUp();
        break;
      case 'page_down':
        this.pageDown();
        break;
      default:
        console.warn('Unknown shortcut action:', action);
    }
  }

  /**
   * Register a shortcut
   * @param {string} action - Action name
   * @param {Object} shortcut - Shortcut object
   * @param {Object} options - Registration options
   */
  registerShortcut(action, shortcut, options = {}) {
    // Check for conflicts
    const conflict = this.checkConflict(shortcut, action);
    if (conflict) {
      this.emit('conflict_detected', { action, shortcut, conflict });
      if (!options.force) {
        return false;
      }
    }

    this.shortcuts.set(action, shortcut);
    this.saveShortcuts();

    // Notify server
    this.notifyServer('register', action, shortcut);

    this.emit('shortcut_registered', { action, shortcut });
    return true;
  }

  /**
   * Unregister a shortcut
   * @param {string} action - Action name
   */
  unregisterShortcut(action) {
    if (this.shortcuts.has(action)) {
      this.shortcuts.delete(action);
      this.saveShortcuts();

      // Notify server
      this.notifyServer('unregister', action);

      this.emit('shortcut_unregistered', { action });
    }
  }

  /**
   * Check for shortcut conflicts
   * @param {Object} shortcut - Shortcut to check
   * @param {string} excludeAction - Action to exclude from check
   * @returns {string|null} - Conflicting action or null
   */
  checkConflict(shortcut, excludeAction = null) {
    for (const [action, actionShortcut] of this.shortcuts) {
      if (action !== excludeAction && this.shortcutsMatch(shortcut, actionShortcut)) {
        return action;
      }
    }
    return null;
  }

  /**
   * Start recording a shortcut
   * @param {Function} callback - Callback function for recorded shortcut
   */
  startRecording(callback) {
    this.isRecording = true;
    this.recordingCallback = callback;
    this.emit('recording_started');
  }

  /**
   * Stop recording
   */
  stopRecording() {
    this.isRecording = false;
    this.recordingCallback = null;
    this.emit('recording_stopped');
  }

  /**
   * Load shortcuts from storage
   */
  loadShortcuts() {
    const stored = Utils.storage.get('keyboard_shortcuts');
    if (stored) {
      try {
        const parsed = JSON.parse(stored);
        this.shortcuts = new Map(Object.entries(parsed));
      } catch (error) {
        console.error('Failed to load shortcuts:', error);
      }
    }
  }

  /**
   * Save shortcuts to storage
   */
  saveShortcuts() {
    const shortcutsObj = Object.fromEntries(this.shortcuts);
    Utils.storage.set('keyboard_shortcuts', JSON.stringify(shortcutsObj));
  }

  /**
   * Register default shortcuts
   */
  registerDefaultShortcuts() {
    Object.entries(this.defaultShortcuts).forEach(([action, shortcut]) => {
      if (!this.shortcuts.has(action)) {
        this.shortcuts.set(action, shortcut);
      }
    });
    this.saveShortcuts();
  }

  /**
   * Notify server about shortcut changes
   * @param {string} type - Notification type
   * @param {string} action - Action name
   * @param {Object} shortcut - Shortcut object
   */
  notifyServer(type, action, shortcut = null) {
    if (window.WebSocketManager) {
      window.WebSocketManager.send({
        type: 'keyboard_shortcut_' + type,
        action: action,
        shortcut: shortcut,
        timestamp: new Date().toISOString()
      });
    }
  }

  /**
   * Handle shortcut update from server
   * @param {Object} data - Update data
   */
  handleShortcutUpdate(data) {
    if (data.action && data.shortcut) {
      this.shortcuts.set(data.action, data.shortcut);
      this.saveShortcuts();
      this.emit('shortcut_updated', data);
    }
  }

  /**
   * Handle shortcut conflict from server
   * @param {Object} data - Conflict data
   */
  handleShortcutConflict(data) {
    this.conflicts.add(data.shortcut);
    this.emit('shortcut_conflict', data);
  }

  /**
   * Handle shortcut registration from server
   * @param {Object} data - Registration data
   */
  handleShortcutRegistered(data) {
    this.emit('shortcut_registered_server', data);
  }

  // Action implementations

  sendMessage() {
    const input = document.querySelector('.chat-input-textarea');
    if (input && input.value.trim()) {
      // Trigger form submission
      const form = input.closest('form');
      if (form) {
        const submitEvent = new Event('submit', { cancelable: true });
        form.dispatchEvent(submitEvent);
      }
    }
  }

  insertNewLine() {
    const input = document.querySelector('.chat-input-textarea');
    if (input) {
      const start = input.selectionStart;
      const end = input.selectionEnd;
      const value = input.value;
      input.value = value.substring(0, start) + '\n' + value.substring(end);
      input.selectionStart = input.selectionEnd = start + 1;
      input.dispatchEvent(new Event('input', { bubbles: true }));
    }
  }

  focusSearch() {
    const searchInput = document.querySelector('#global-search, .search-input');
    if (searchInput) {
      searchInput.focus();
    }
  }

  focusInput() {
    const messageInput = document.querySelector('.chat-input-textarea');
    if (messageInput) {
      messageInput.focus();
    }
  }

  toggleTheme() {
    if (window.EnhancedUI) {
      window.EnhancedUI.toggleTheme();
    }
  }

  showHelp() {
    if (window.UIComponents) {
      const helpModal = window.UIComponents.create('ShortcutsHelpModal');
      helpModal.show();
    }
  }

  switchToChannel(channelNum) {
    // Find channel by index
    const channels = document.querySelectorAll('.channel-item');
    if (channels[channelNum - 1]) {
      channels[channelNum - 1].click();
    }
  }

  nextChannel() {
    const activeChannel = document.querySelector('.channel-item.active');
    if (activeChannel) {
      const nextChannel = activeChannel.nextElementSibling;
      if (nextChannel && nextChannel.classList.contains('channel-item')) {
        nextChannel.click();
      }
    }
  }

  prevChannel() {
    const activeChannel = document.querySelector('.channel-item.active');
    if (activeChannel) {
      const prevChannel = activeChannel.previousElementSibling;
      if (prevChannel && prevChannel.classList.contains('channel-item')) {
        prevChannel.click();
      }
    }
  }

  scrollUp() {
    const messagesContainer = document.querySelector('.chat-messages');
    if (messagesContainer) {
      messagesContainer.scrollBy(0, -50);
    }
  }

  scrollDown() {
    const messagesContainer = document.querySelector('.chat-messages');
    if (messagesContainer) {
      messagesContainer.scrollBy(0, 50);
    }
  }

  pageUp() {
    const messagesContainer = document.querySelector('.chat-messages');
    if (messagesContainer) {
      messagesContainer.scrollBy(0, -messagesContainer.clientHeight);
    }
  }

  pageDown() {
    const messagesContainer = document.querySelector('.chat-messages');
    if (messagesContainer) {
      messagesContainer.scrollBy(0, messagesContainer.clientHeight);
    }
  }

  /**
   * Format shortcut for display
   * @param {Object} shortcut - Shortcut object
   * @returns {string} - Formatted shortcut string
   */
  formatShortcut(shortcut) {
    const parts = [];

    if (shortcut.ctrl) parts.push(this.platform === 'mac' ? '⌘' : 'Ctrl');
    if (shortcut.alt) parts.push(this.platform === 'mac' ? '⌥' : 'Alt');
    if (shortcut.shift) parts.push('⇧');
    if (shortcut.meta && this.platform !== 'mac') parts.push('Meta');

    parts.push(shortcut.key.toUpperCase());

    return parts.join(this.platform === 'mac' ? '' : '+');
  }

  /**
   * Get all registered shortcuts
   * @returns {Map} - Map of shortcuts
   */
  getAllShortcuts() {
    return new Map(this.shortcuts);
  }

  /**
   * Get shortcut for action
   * @param {string} action - Action name
   * @returns {Object|null} - Shortcut object or null
   */
  getShortcut(action) {
    return this.shortcuts.get(action) || null;
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
          console.error('Shortcut event callback error:', error);
        }
      });
    }

    // Also emit to global Utils events
    Utils.events.emit(`shortcuts:${event}`, data);
  }

  /**
   * Get platform-specific modifier key name
   * @returns {string}
   */
  getModifierKeyName() {
    return this.platform === 'mac' ? 'Cmd' : 'Ctrl';
  }

  /**
   * Check if recording is active
   * @returns {boolean}
   */
  isRecordingActive() {
    return this.isRecording;
  }

  /**
   * Get conflicts
   * @returns {Set}
   */
  getConflicts() {
    return new Set(this.conflicts);
  }

  /**
   * Clear conflicts
   */
  clearConflicts() {
    this.conflicts.clear();
  }
}

// Create global instance
window.KeyboardShortcutsManager = new KeyboardShortcutsManager();