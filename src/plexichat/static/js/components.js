/**
 * PlexiChat UI Components
 * Dynamic UI components for the chat interface
 */

class UIComponents {
  constructor() {
    this.components = new Map();
    this.eventListeners = new Map();
    this.init();
  }

  /**
   * Initialize components
   */
  init() {
    this.registerComponents();
    this.setupEventListeners();
  }

  /**
   * Register all components
   */
  registerComponents() {
    this.register('MessageList', this.createMessageList.bind(this));
    this.register('MessageInput', this.createMessageInput.bind(this));
    this.register('ChannelList', this.createChannelList.bind(this));
    this.register('UserList', this.createUserList.bind(this));
    this.register('NotificationToast', this.createNotificationToast.bind(this));
    this.register('Modal', this.createModal.bind(this));
    this.register('TypingIndicator', this.createTypingIndicator.bind(this));
    this.register('PresenceIndicator', this.createPresenceIndicator.bind(this));
    this.register('ReactionPicker', this.createReactionPicker.bind(this));
    this.register('FileUpload', this.createFileUpload.bind(this));
    this.register('EmojiPicker', this.createEmojiPicker.bind(this));
  }

  /**
   * Register a component
   * @param {string} name - Component name
   * @param {Function} factory - Component factory function
   */
  register(name, factory) {
    this.components.set(name, factory);
  }

  /**
   * Create component instance
   * @param {string} name - Component name
   * @param {Object} props - Component props
   * @returns {Component}
   */
  create(name, props = {}) {
    const factory = this.components.get(name);
    if (!factory) {
      throw new Error(`Component "${name}" not registered`);
    }
    return factory(props);
  }

  /**
   * Setup global event listeners
   */
  setupEventListeners() {
    // WebSocket events
    Utils.events.on('websocket:chat_message', (data) => {
      this.handleNewMessage(data);
    });

    Utils.events.on('websocket:presence_update', (data) => {
      this.handlePresenceUpdate(data);
    });

    Utils.events.on('websocket:typing', (data) => {
      this.handleTypingUpdate(data);
    });

    Utils.events.on('websocket:notification', (data) => {
      this.showNotification(data);
    });

    // API events
    Utils.events.on('api:error', (error) => {
      this.showError(error);
    });
  }

  /**
   * Create Message List Component
   * @param {Object} props - Component props
   * @returns {MessageListComponent}
   */
  createMessageList(props = {}) {
    return new MessageListComponent(props);
  }

  /**
   * Create Message Input Component
   * @param {Object} props - Component props
   * @returns {MessageInputComponent}
   */
  createMessageInput(props = {}) {
    return new MessageInputComponent(props);
  }

  /**
   * Create Channel List Component
   * @param {Object} props - Component props
   * @returns {ChannelListComponent}
   */
  createChannelList(props = {}) {
    return new ChannelListComponent(props);
  }

  /**
   * Create User List Component
   * @param {Object} props - Component props
   * @returns {UserListComponent}
   */
  createUserList(props = {}) {
    return new UserListComponent(props);
  }

  /**
   * Create Notification Toast Component
   * @param {Object} props - Component props
   * @returns {NotificationToastComponent}
   */
  createNotificationToast(props = {}) {
    return new NotificationToastComponent(props);
  }

  /**
   * Create Modal Component
   * @param {Object} props - Component props
   * @returns {ModalComponent}
   */
  createModal(props = {}) {
    return new ModalComponent(props);
  }

  /**
   * Create Typing Indicator Component
   * @param {Object} props - Component props
   * @returns {TypingIndicatorComponent}
   */
  createTypingIndicator(props = {}) {
    return new TypingIndicatorComponent(props);
  }

  /**
   * Create Presence Indicator Component
   * @param {Object} props - Component props
   * @returns {PresenceIndicatorComponent}
   */
  createPresenceIndicator(props = {}) {
    return new PresenceIndicatorComponent(props);
  }

  /**
   * Create Reaction Picker Component
   * @param {Object} props - Component props
   * @returns {ReactionPickerComponent}
   */
  createReactionPicker(props = {}) {
    return new ReactionPickerComponent(props);
  }

  /**
   * Create File Upload Component
   * @param {Object} props - Component props
   * @returns {FileUploadComponent}
   */
  createFileUpload(props = {}) {
    return new FileUploadComponent(props);
  }

  /**
   * Create Emoji Picker Component
   * @param {Object} props - Component props
   * @returns {EmojiPickerComponent}
   */
  createEmojiPicker(props = {}) {
    return new EmojiPickerComponent(props);
  }

  /**
   * Handle new message
   * @param {Object} data - Message data
   */
  handleNewMessage(data) {
    const messageList = this.getComponent('MessageList');
    if (messageList) {
      messageList.addMessage(data);
    }
  }

  /**
   * Handle presence update
   * @param {Object} data - Presence data
   */
  handlePresenceUpdate(data) {
    const userList = this.getComponent('UserList');
    if (userList) {
      userList.updatePresence(data);
    }
  }

  /**
   * Handle typing update
   * @param {Object} data - Typing data
   */
  handleTypingUpdate(data) {
    const typingIndicator = this.getComponent('TypingIndicator');
    if (typingIndicator) {
      typingIndicator.updateTyping(data);
    }
  }

  /**
   * Show notification
   * @param {Object} data - Notification data
   */
  showNotification(data) {
    const notification = this.create('NotificationToast', data);
    notification.show();
  }

  /**
   * Show error
   * @param {Object} error - Error data
   */
  showError(error) {
    this.showNotification({
      type: 'error',
      title: 'Error',
      message: error.message || 'An error occurred',
      duration: 5000
    });
  }

  /**
   * Get component instance
   * @param {string} name - Component name
   * @returns {Component|null}
   */
  getComponent(name) {
    // This would need to be implemented to track active components
    return null;
  }
}

/**
 * Base Component Class
 */
class BaseComponent {
  constructor(props = {}) {
    this.props = props;
    this.element = null;
    this.eventListeners = [];
    this.isMounted = false;
  }

  /**
   * Render component
   * @returns {HTMLElement}
   */
  render() {
    throw new Error('Render method must be implemented by subclass');
  }

  /**
   * Mount component to DOM
   * @param {HTMLElement} container - Container element
   */
  mount(container) {
    if (this.isMounted) return;

    this.element = this.render();
    container.appendChild(this.element);
    this.isMounted = true;
    this.componentDidMount();
  }

  /**
   * Unmount component from DOM
   */
  unmount() {
    if (!this.isMounted) return;

    if (this.element && this.element.parentNode) {
      this.element.parentNode.removeChild(this.element);
    }

    this.cleanupEventListeners();
    this.isMounted = false;
    this.componentWillUnmount();
  }

  /**
   * Update component props
   * @param {Object} newProps - New props
   */
  updateProps(newProps) {
    this.props = { ...this.props, ...newProps };
    this.componentDidUpdate();
  }

  /**
   * Add event listener
   * @param {string} event - Event type
   * @param {Function} handler - Event handler
   * @param {Element} element - Target element (optional)
   */
  addEventListener(event, handler, element = this.element) {
    if (!element) return;

    element.addEventListener(event, handler);
    this.eventListeners.push({ event, handler, element });
  }

  /**
   * Cleanup event listeners
   */
  cleanupEventListeners() {
    this.eventListeners.forEach(({ event, handler, element }) => {
      element.removeEventListener(event, handler);
    });
    this.eventListeners = [];
  }

  /**
   * Lifecycle method: called after component mounts
   */
  componentDidMount() {}

  /**
   * Lifecycle method: called before component unmounts
   */
  componentWillUnmount() {}

  /**
   * Lifecycle method: called after component updates
   */
  componentDidUpdate() {}

  /**
   * Set state (for stateful components)
   * @param {Object} newState - New state
   */
  setState(newState) {
    if (!this.state) this.state = {};
    this.state = { ...this.state, ...newState };
    this.forceUpdate();
  }

  /**
   * Force component re-render
   */
  forceUpdate() {
    if (!this.isMounted || !this.element) return;

    const newElement = this.render();
    this.element.parentNode.replaceChild(newElement, this.element);
    this.element = newElement;
  }
}

/**
 * Message List Component
 */
class MessageListComponent extends BaseComponent {
  constructor(props) {
    super(props);
    this.messages = props.messages || [];
    this.channelId = props.channelId;
    this.autoScroll = props.autoScroll !== false;
  }

  render() {
    const container = Utils.dom.createElement('div', {
      className: 'chat-messages',
      id: `messages-${this.channelId}`
    });

    this.messages.forEach(message => {
      const messageElement = this.renderMessage(message);
      container.appendChild(messageElement);
    });

    return container;
  }

  renderMessage(message) {
    const messageDiv = Utils.dom.createElement('div', {
      className: `message ${message.own ? 'own' : ''}`,
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

    if (message.own) {
      messageDiv.appendChild(content);
      messageDiv.appendChild(avatar);
    } else {
      messageDiv.appendChild(avatar);
      messageDiv.appendChild(content);
    }

    return messageDiv;
  }

  addMessage(message) {
    this.messages.push(message);

    if (this.element) {
      const messageElement = this.renderMessage(message);
      this.element.appendChild(messageElement);

      if (this.autoScroll) {
        this.scrollToBottom();
      }
    }
  }

  scrollToBottom() {
    if (this.element) {
      this.element.scrollTop = this.element.scrollHeight;
    }
  }

  componentDidMount() {
    if (this.autoScroll) {
      this.scrollToBottom();
    }
  }
}

/**
 * Message Input Component
 */
class MessageInputComponent extends BaseComponent {
  constructor(props) {
    super(props);
    this.channelId = props.channelId;
    this.placeholder = props.placeholder || 'Type a message...';
    this.maxLength = props.maxLength || 2000;
  }

  render() {
    const container = Utils.dom.createElement('div', { className: 'chat-input-container' });

    const form = Utils.dom.createElement('form', { className: 'chat-input' });

    const textarea = Utils.dom.createElement('textarea', {
      className: 'chat-input-textarea',
      placeholder: this.placeholder,
      maxlength: this.maxLength,
      rows: 1
    });

    const sendButton = Utils.dom.createElement('button', {
      className: 'chat-send-btn',
      type: 'submit',
      textContent: 'Send',
      disabled: true
    });

    form.appendChild(textarea);
    form.appendChild(sendButton);
    container.appendChild(form);

    return container;
  }

  componentDidMount() {
    const textarea = this.element.querySelector('.chat-input-textarea');
    const form = this.element.querySelector('.chat-input');
    const sendButton = this.element.querySelector('.chat-send-btn');

    // Auto-resize textarea
    this.addEventListener('input', this.handleInput.bind(this), textarea);

    // Form submission
    this.addEventListener('submit', this.handleSubmit.bind(this), form);

    // Keyboard shortcuts
    this.addEventListener('keydown', this.handleKeydown.bind(this), textarea);
  }

  handleInput(event) {
    const textarea = event.target;
    const sendButton = this.element.querySelector('.chat-send-btn');

    // Auto-resize
    textarea.style.height = 'auto';
    textarea.style.height = textarea.scrollHeight + 'px';

    // Enable/disable send button
    sendButton.disabled = !textarea.value.trim();
  }

  handleSubmit(event) {
    event.preventDefault();

    const textarea = this.element.querySelector('.chat-input-textarea');
    const content = textarea.value.trim();

    if (!content) return;

    // Send message
    if (window.WebSocketManager) {
      window.WebSocketManager.sendMessage(this.channelId, content);
    }

    // Clear input
    textarea.value = '';
    textarea.style.height = 'auto';
    this.element.querySelector('.chat-send-btn').disabled = true;
  }

  handleKeydown(event) {
    if (event.key === 'Enter' && !event.shiftKey) {
      event.preventDefault();
      this.handleSubmit(event);
    }
  }
}

/**
 * Notification Toast Component
 */
class NotificationToastComponent extends BaseComponent {
  constructor(props) {
    super(props);
    this.type = props.type || 'info';
    this.title = props.title || '';
    this.message = props.message || '';
    this.duration = props.duration || 3000;
    this.timeout = null;
  }

  render() {
    const toast = Utils.dom.createElement('div', {
      className: `notification ${this.type}`,
      role: 'alert'
    });

    if (this.title) {
      const title = Utils.dom.createElement('div', {
        className: 'notification-title',
        textContent: this.title
      });
      toast.appendChild(title);
    }

    const message = Utils.dom.createElement('div', {
      className: 'notification-message',
      textContent: this.message
    });
    toast.appendChild(message);

    const closeBtn = Utils.dom.createElement('button', {
      className: 'notification-close',
      'aria-label': 'Close notification'
    });

    const closeIcon = Utils.dom.createElement('i', {
      className: 'fas fa-times'
    });

    closeBtn.appendChild(closeIcon);
    toast.appendChild(closeBtn);

    return toast;
  }

  componentDidMount() {
    const closeBtn = this.element.querySelector('.notification-close');
    this.addEventListener('click', () => this.hide(), closeBtn);

    if (this.duration > 0) {
      this.timeout = setTimeout(() => this.hide(), this.duration);
    }
  }

  show() {
    const container = document.getElementById('notification-container');
    if (container) {
      container.appendChild(this.element);
      this.element.style.animation = 'slideInRight 0.3s ease-out';
    }
  }

  hide() {
    if (this.timeout) {
      clearTimeout(this.timeout);
    }

    this.element.style.animation = 'slideInRight 0.3s ease-out reverse';
    setTimeout(() => {
      if (this.element.parentNode) {
        this.element.parentNode.removeChild(this.element);
      }
    }, 300);
  }
}

/**
 * Modal Component
 */
class ModalComponent extends BaseComponent {
  constructor(props) {
    super(props);
    this.title = props.title || '';
    this.content = props.content || '';
    this.size = props.size || 'md';
    this.closable = props.closable !== false;
  }

  render() {
    const overlay = Utils.dom.createElement('div', {
      className: 'modal-overlay',
      id: 'modal-overlay'
    });

    const modal = Utils.dom.createElement('div', {
      className: `modal-content modal-${this.size}`
    });

    const header = Utils.dom.createElement('div', { className: 'modal-header' });

    const title = Utils.dom.createElement('h2', {
      className: 'modal-title',
      textContent: this.title
    });

    header.appendChild(title);

    if (this.closable) {
      const closeBtn = Utils.dom.createElement('button', {
        className: 'modal-close',
        'aria-label': 'Close modal'
      });

      const closeIcon = Utils.dom.createElement('i', {
        className: 'fas fa-times'
      });

      closeBtn.appendChild(closeIcon);
      header.appendChild(closeBtn);
    }

    const body = Utils.dom.createElement('div', { className: 'modal-body' });

    if (typeof this.content === 'string') {
      body.innerHTML = this.content;
    } else if (this.content instanceof Element) {
      body.appendChild(this.content);
    }

    modal.appendChild(header);
    modal.appendChild(body);
    overlay.appendChild(modal);

    return overlay;
  }

  componentDidMount() {
    if (this.closable) {
      const closeBtn = this.element.querySelector('.modal-close');
      const overlay = this.element;

      this.addEventListener('click', () => this.hide(), closeBtn);
      this.addEventListener('click', (e) => {
        if (e.target === overlay) this.hide();
      });
    }

    // Focus management
    const focusableElements = this.element.querySelectorAll(
      'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])'
    );

    if (focusableElements.length > 0) {
      focusableElements[0].focus();
    }

    // Trap focus
    this.addEventListener('keydown', this.handleKeydown.bind(this));
  }

  handleKeydown(event) {
    if (event.key === 'Escape' && this.closable) {
      this.hide();
    }
  }

  show() {
    document.body.appendChild(this.element);
    document.body.style.overflow = 'hidden';
  }

  hide() {
    if (this.element.parentNode) {
      this.element.parentNode.removeChild(this.element);
    }
    document.body.style.overflow = '';
  }
}

// Create global UI components instance
window.UIComponents = new UIComponents();