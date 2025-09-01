/**
 * PlexiChat Notification System
 * Real-time notifications and alerts
 */

class NotificationManager {
  constructor() {
    this.notifications = new Map();
    this.permission = 'default';
    this.enabled = Utils.storage.get('notifications_enabled', true);
    this.soundEnabled = Utils.storage.get('notification_sound', true);
    this.desktopEnabled = Utils.storage.get('desktop_notifications', false);
    this.queue = [];
    this.maxVisible = 5;
    this.init();
  }

  /**
   * Initialize notification system
   */
  async init() {
    this.checkPermission();
    this.setupEventListeners();
    this.loadNotificationHistory();
  }

  /**
   * Check notification permission
   */
  async checkPermission() {
    if ('Notification' in window) {
      this.permission = Notification.permission;

      if (this.permission === 'default' && this.desktopEnabled) {
        this.permission = await Notification.requestPermission();
      }
    }
  }

  /**
   * Setup event listeners
   */
  setupEventListeners() {
    // WebSocket events
    Utils.events.on('websocket:notification', (data) => {
      this.handleNotification(data);
    });

    Utils.events.on('websocket:chat_message', (data) => {
      this.handleMessageNotification(data);
    });

    Utils.events.on('websocket:mention', (data) => {
      this.handleMentionNotification(data);
    });

    // API events
    Utils.events.on('api:success', (data) => {
      if (data.showNotification !== false) {
        this.showSuccess('Operation completed successfully');
      }
    });

    Utils.events.on('api:error', (error) => {
      this.showError(error.message || 'An error occurred');
    });

    // User activity events
    document.addEventListener('visibilitychange', () => {
      if (document.hidden) {
        this.pause();
      } else {
        this.resume();
      }
    });
  }

  /**
   * Handle incoming notification
   * @param {Object} data - Notification data
   */
  handleNotification(data) {
    const notification = {
      id: Utils.string.random(),
      type: data.type || 'info',
      title: data.title || 'Notification',
      message: data.message || '',
      icon: data.icon,
      sound: data.sound,
      duration: data.duration || 5000,
      actions: data.actions || [],
      timestamp: new Date(),
      read: false,
      ...data
    };

    this.add(notification);
    this.show(notification);
  }

  /**
   * Handle message notification
   * @param {Object} data - Message data
   */
  handleMessageNotification(data) {
    if (document.hidden && data.channel_id) {
      const notification = {
        id: Utils.string.random(),
        type: 'message',
        title: `New message in ${data.channel_name || '#' + data.channel_id}`,
        message: `${data.author.display_name}: ${Utils.string.truncate(data.content, 100)}`,
        icon: data.author.avatar_url,
        channelId: data.channel_id,
        messageId: data.id,
        sound: 'message',
        duration: 10000
      };

      this.add(notification);
      this.show(notification);
    }
  }

  /**
   * Handle mention notification
   * @param {Object} data - Mention data
   */
  handleMentionNotification(data) {
    const notification = {
      id: Utils.string.random(),
      type: 'mention',
      title: 'You were mentioned',
      message: `${data.author.display_name} mentioned you in ${data.channel_name}`,
      icon: data.author.avatar_url,
      channelId: data.channel_id,
      messageId: data.id,
      sound: 'mention',
      duration: 0, // Persistent
      urgent: true
    };

    this.add(notification);
    this.show(notification);
  }

  /**
   * Add notification to collection
   * @param {Object} notification - Notification object
   */
  add(notification) {
    this.notifications.set(notification.id, notification);

    // Limit stored notifications
    if (this.notifications.size > 100) {
      const oldest = this.notifications.keys().next().value;
      this.notifications.delete(oldest);
    }

    this.saveNotificationHistory();
    Utils.events.emit('notification:added', notification);
  }

  /**
   * Show notification
   * @param {Object} notification - Notification to show
   */
  show(notification) {
    if (!this.enabled) return;

    // Show in-app notification
    this.showInApp(notification);

    // Show desktop notification
    if (this.desktopEnabled && this.permission === 'granted') {
      this.showDesktop(notification);
    }

    // Play sound
    if (this.soundEnabled && notification.sound) {
      this.playSound(notification.sound);
    }

    // Auto-remove after duration
    if (notification.duration > 0) {
      setTimeout(() => {
        this.remove(notification.id);
      }, notification.duration);
    }
  }

  /**
   * Show in-app notification
   * @param {Object} notification - Notification to show
   */
  showInApp(notification) {
    const container = this.getContainer();

    // Create notification element
    const element = Utils.dom.createElement('div', {
      className: `notification ${notification.type} ${notification.urgent ? 'urgent' : ''}`,
      'data-id': notification.id
    });

    // Icon
    if (notification.icon) {
      const icon = Utils.dom.createElement('img', {
        className: 'notification-icon',
        src: notification.icon,
        alt: ''
      });
      element.appendChild(icon);
    } else {
      const icon = Utils.dom.createElement('i', {
        className: `fas fa-${this.getIconClass(notification.type)} notification-icon`
      });
      element.appendChild(icon);
    }

    // Content
    const content = Utils.dom.createElement('div', { className: 'notification-content' });

    const title = Utils.dom.createElement('div', {
      className: 'notification-title',
      textContent: notification.title
    });
    content.appendChild(title);

    if (notification.message) {
      const message = Utils.dom.createElement('div', {
        className: 'notification-message',
        textContent: notification.message
      });
      content.appendChild(message);
    }

    element.appendChild(content);

    // Actions
    if (notification.actions && notification.actions.length > 0) {
      const actions = Utils.dom.createElement('div', { className: 'notification-actions' });

      notification.actions.forEach(action => {
        const button = Utils.dom.createElement('button', {
          className: 'notification-action',
          textContent: action.label
        });

        button.addEventListener('click', () => {
          action.handler(notification);
          this.remove(notification.id);
        });

        actions.appendChild(button);
      });

      element.appendChild(actions);
    }

    // Close button
    const closeBtn = Utils.dom.createElement('button', {
      className: 'notification-close',
      'aria-label': 'Close notification'
    });

    const closeIcon = Utils.dom.createElement('i', { className: 'fas fa-times' });
    closeBtn.appendChild(closeIcon);

    closeBtn.addEventListener('click', () => {
      this.remove(notification.id);
    });

    element.appendChild(closeBtn);

    // Add click handler for main action
    element.addEventListener('click', (e) => {
      if (!e.target.closest('.notification-action, .notification-close')) {
        this.handleNotificationClick(notification);
        this.remove(notification.id);
      }
    });

    // Add to container
    container.appendChild(element);

    // Animate in
    setTimeout(() => {
      element.classList.add('show');
    }, 10);

    // Limit visible notifications
    this.limitVisibleNotifications();
  }

  /**
   * Show desktop notification
   * @param {Object} notification - Notification to show
   */
  showDesktop(notification) {
    if (this.permission !== 'granted') return;

    const desktopNotification = new Notification(notification.title, {
      body: notification.message,
      icon: notification.icon || '/static/images/notification-icon.png',
      tag: notification.id,
      requireInteraction: notification.urgent || false
    });

    desktopNotification.onclick = () => {
      this.handleNotificationClick(notification);
      desktopNotification.close();
      window.focus();
    };

    // Auto-close after duration
    if (notification.duration > 0) {
      setTimeout(() => {
        desktopNotification.close();
      }, notification.duration);
    }
  }

  /**
   * Play notification sound
   * @param {string} sound - Sound type
   */
  playSound(sound) {
    if (!this.soundEnabled) return;

    const audio = new Audio(`/static/sounds/${sound}.mp3`);
    audio.volume = 0.3;

    audio.play().catch(() => {
      // Fallback: create beep
      this.createBeep(sound);
    });
  }

  /**
   * Create beep sound
   * @param {string} type - Sound type
   */
  createBeep(type) {
    if (typeof AudioContext === 'undefined' && typeof webkitAudioContext === 'undefined') return;

    const AudioCtx = AudioContext || webkitAudioContext;
    const audioContext = new AudioCtx();
    const oscillator = audioContext.createOscillator();
    const gainNode = audioContext.createGain();

    oscillator.connect(gainNode);
    gainNode.connect(audioContext.destination);

    // Different frequencies for different types
    const frequencies = {
      message: 800,
      mention: 1000,
      error: 600,
      success: 900
    };

    oscillator.frequency.setValueAtTime(frequencies[type] || 800, audioContext.currentTime);
    oscillator.frequency.setValueAtTime((frequencies[type] || 800) * 1.2, audioContext.currentTime + 0.1);

    gainNode.gain.setValueAtTime(0.1, audioContext.currentTime);
    gainNode.gain.exponentialRampToValueAtTime(0.01, audioContext.currentTime + 0.2);

    oscillator.start(audioContext.currentTime);
    oscillator.stop(audioContext.currentTime + 0.2);
  }

  /**
   * Handle notification click
   * @param {Object} notification - Clicked notification
   */
  handleNotificationClick(notification) {
    // Mark as read
    this.markAsRead(notification.id);

    // Navigate based on notification type
    switch (notification.type) {
      case 'message':
      case 'mention':
        if (notification.channelId) {
          // Navigate to channel
          window.location.href = `/chat/${notification.channelId}`;
        }
        break;
      case 'friend_request':
        window.location.href = '/friends';
        break;
      default:
        // Stay on current page
        break;
    }
  }

  /**
   * Remove notification
   * @param {string} id - Notification ID
   */
  remove(id) {
    const element = Utils.dom.$(`[data-id="${id}"]`);
    if (element) {
      element.classList.remove('show');
      setTimeout(() => {
        if (element.parentNode) {
          element.parentNode.removeChild(element);
        }
      }, 300);
    }

    Utils.events.emit('notification:removed', id);
  }

  /**
   * Mark notification as read
   * @param {string} id - Notification ID
   */
  markAsRead(id) {
    const notification = this.notifications.get(id);
    if (notification) {
      notification.read = true;
      this.saveNotificationHistory();
      Utils.events.emit('notification:read', notification);
    }
  }

  /**
   * Mark all notifications as read
   */
  markAllAsRead() {
    this.notifications.forEach(notification => {
      notification.read = true;
    });
    this.saveNotificationHistory();
    Utils.events.emit('notifications:all_read');
  }

  /**
   * Clear all notifications
   */
  clearAll() {
    const container = this.getContainer();
    container.innerHTML = '';
    this.notifications.clear();
    this.saveNotificationHistory();
    Utils.events.emit('notifications:cleared');
  }

  /**
   * Get notification container
   * @returns {Element}
   */
  getContainer() {
    let container = Utils.dom.$('#notification-container');
    if (!container) {
      container = Utils.dom.createElement('div', {
        id: 'notification-container',
        className: 'notification-container'
      });
      document.body.appendChild(container);
    }
    return container;
  }

  /**
   * Limit visible notifications
   */
  limitVisibleNotifications() {
    const container = this.getContainer();
    const notifications = container.children;

    if (notifications.length > this.maxVisible) {
      for (let i = 0; i < notifications.length - this.maxVisible; i++) {
        this.remove(notifications[i].dataset.id);
      }
    }
  }

  /**
   * Get icon class for notification type
   * @param {string} type - Notification type
   * @returns {string}
   */
  getIconClass(type) {
    const icons = {
      success: 'check-circle',
      error: 'exclamation-triangle',
      warning: 'exclamation-circle',
      info: 'info-circle',
      message: 'comment',
      mention: 'at',
      friend_request: 'user-plus'
    };
    return icons[type] || 'bell';
  }

  /**
   * Show success notification
   * @param {string} message - Success message
   * @param {Object} options - Additional options
   */
  showSuccess(message, options = {}) {
    this.show({
      type: 'success',
      title: 'Success',
      message,
      duration: 3000,
      ...options
    });
  }

  /**
   * Show error notification
   * @param {string} message - Error message
   * @param {Object} options - Additional options
   */
  showError(message, options = {}) {
    this.show({
      type: 'error',
      title: 'Error',
      message,
      duration: 5000,
      ...options
    });
  }

  /**
   * Show warning notification
   * @param {string} message - Warning message
   * @param {Object} options - Additional options
   */
  showWarning(message, options = {}) {
    this.show({
      type: 'warning',
      title: 'Warning',
      message,
      duration: 4000,
      ...options
    });
  }

  /**
   * Show info notification
   * @param {string} message - Info message
   * @param {Object} options - Additional options
   */
  showInfo(message, options = {}) {
    this.show({
      type: 'info',
      title: 'Info',
      message,
      duration: 3000,
      ...options
    });
  }

  /**
   * Enable notifications
   */
  enable() {
    this.enabled = true;
    Utils.storage.set('notifications_enabled', true);
    Utils.events.emit('notifications:enabled');
  }

  /**
   * Disable notifications
   */
  disable() {
    this.enabled = false;
    Utils.storage.set('notifications_enabled', false);
    this.clearAll();
    Utils.events.emit('notifications:disabled');
  }

  /**
   * Enable notification sounds
   */
  enableSound() {
    this.soundEnabled = true;
    Utils.storage.set('notification_sound', true);
  }

  /**
   * Disable notification sounds
   */
  disableSound() {
    this.soundEnabled = false;
    Utils.storage.set('notification_sound', false);
  }

  /**
   * Enable desktop notifications
   */
  async enableDesktop() {
    const permission = await this.checkPermission();
    if (permission === 'granted') {
      this.desktopEnabled = true;
      Utils.storage.set('desktop_notifications', true);
      Utils.events.emit('notifications:desktop_enabled');
    }
  }

  /**
   * Disable desktop notifications
   */
  disableDesktop() {
    this.desktopEnabled = false;
    Utils.storage.set('desktop_notifications', false);
    Utils.events.emit('notifications:desktop_disabled');
  }

  /**
   * Pause notifications (when page is hidden)
   */
  pause() {
    this.wasEnabled = this.enabled;
    this.enabled = false;
  }

  /**
   * Resume notifications (when page is visible)
   */
  resume() {
    this.enabled = this.wasEnabled;
  }

  /**
   * Save notification history to storage
   */
  saveNotificationHistory() {
    const history = Array.from(this.notifications.values())
      .filter(n => n.persistent)
      .slice(-50); // Keep last 50 persistent notifications

    Utils.storage.set('notification_history', history);
  }

  /**
   * Load notification history from storage
   */
  loadNotificationHistory() {
    const history = Utils.storage.get('notification_history', []);
    history.forEach(notification => {
      this.notifications.set(notification.id, notification);
    });
  }

  /**
   * Get unread count
   * @returns {number}
   */
  getUnreadCount() {
    return Array.from(this.notifications.values())
      .filter(n => !n.read)
      .length;
  }

  /**
   * Get all notifications
   * @returns {Array}
   */
  getAll() {
    return Array.from(this.notifications.values());
  }

  /**
   * Get unread notifications
   * @returns {Array}
   */
  getUnread() {
    return Array.from(this.notifications.values())
      .filter(n => !n.read);
  }

  /**
   * Get notification by ID
   * @param {string} id - Notification ID
   * @returns {Object|null}
   */
  get(id) {
    return this.notifications.get(id) || null;
  }

  /**
   * Destroy notification manager
   */
  destroy() {
    this.clearAll();
    this.notifications.clear();
    Utils.events.off('websocket:notification');
    Utils.events.off('websocket:chat_message');
    Utils.events.off('websocket:mention');
    Utils.events.off('api:success');
    Utils.events.off('api:error');
  }
}

// Create global notification manager instance
window.NotificationManager = new NotificationManager();