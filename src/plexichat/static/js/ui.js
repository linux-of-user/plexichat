/**
 * PlexiChat UI Utilities
 * General UI functionality and helpers
 */

class UI {
  constructor() {
    this.initialized = false;
    this.currentModal = null;
    this.tooltips = new Map();
    this.popovers = new Map();
    this.dropdowns = new Map();
    this.init();
  }

  /**
   * Initialize UI components
   */
  init() {
    if (this.initialized) return;

    this.setupGlobalHandlers();
    this.setupFormValidation();
    this.setupInfiniteScroll();
    this.setupImageLazyLoading();
    this.setupResponsiveHelpers();

    this.initialized = true;
  }

  /**
   * Setup global event handlers
   */
  setupGlobalHandlers() {
    // Handle clicks outside elements
    document.addEventListener('click', (e) => {
      this.handleOutsideClick(e);
    });

    // Handle escape key
    document.addEventListener('keydown', (e) => {
      if (e.key === 'Escape') {
        this.closeAllDropdowns();
        this.closeCurrentModal();
      }
    });

    // Handle window resize
    let resizeTimeout;
    window.addEventListener('resize', () => {
      clearTimeout(resizeTimeout);
      resizeTimeout = setTimeout(() => {
        this.handleResize();
      }, 100);
    });
  }

  /**
   * Handle clicks outside elements
   * @param {Event} e - Click event
   */
  handleOutsideClick(e) {
    // Close dropdowns
    this.dropdowns.forEach((dropdown, trigger) => {
      if (!trigger.contains(e.target) && !dropdown.contains(e.target)) {
        this.closeDropdown(trigger);
      }
    });

    // Close popovers
    this.popovers.forEach((popover, trigger) => {
      if (!trigger.contains(e.target) && !popover.contains(e.target)) {
        this.closePopover(trigger);
      }
    });

    // Close modals
    if (this.currentModal && !this.currentModal.contains(e.target)) {
      this.closeCurrentModal();
    }
  }

  /**
   * Handle window resize
   */
  handleResize() {
    // Update viewport height for mobile browsers
    const vh = window.innerHeight * 0.01;
    document.documentElement.style.setProperty('--vh', `${vh}px`);

    // Close mobile menu if window is resized to desktop size
    if (window.innerWidth >= 768) {
      this.closeMobileMenu();
    }

    Utils.events.emit('ui:resize', { width: window.innerWidth, height: window.innerHeight });
  }

  /**
   * Setup form validation
   */
  setupFormValidation() {
    Utils.dom.on('form', 'submit', (e) => {
      const form = e.target;
      if (!this.validateForm(form)) {
        e.preventDefault();
        return false;
      }
    });

    // Real-time validation
    Utils.dom.on('input, textarea, select', 'blur', (e) => {
      this.validateField(e.target);
    });
  }

  /**
   * Validate form
   * @param {HTMLFormElement} form - Form element
   * @returns {boolean}
   */
  validateForm(form) {
    let isValid = true;
    const fields = form.querySelectorAll('input, textarea, select');

    fields.forEach(field => {
      if (!this.validateField(field)) {
        isValid = false;
      }
    });

    return isValid;
  }

  /**
   * Validate field
   * @param {HTMLElement} field - Field element
   * @returns {boolean}
   */
  validateField(field) {
    const value = field.value.trim();
    const rules = this.getValidationRules(field);
    let isValid = true;
    let errorMessage = '';

    // Clear previous errors
    this.clearFieldError(field);

    // Check required
    if (rules.required && !value) {
      isValid = false;
      errorMessage = 'This field is required';
    }

    // Check minimum length
    if (rules.minLength && value.length < rules.minLength) {
      isValid = false;
      errorMessage = `Minimum length is ${rules.minLength} characters`;
    }

    // Check maximum length
    if (rules.maxLength && value.length > rules.maxLength) {
      isValid = false;
      errorMessage = `Maximum length is ${rules.maxLength} characters`;
    }

    // Check pattern
    if (rules.pattern && !rules.pattern.test(value)) {
      isValid = false;
      errorMessage = rules.message || 'Invalid format';
    }

    // Check email
    if (rules.email && !Utils.validation.email(value)) {
      isValid = false;
      errorMessage = 'Please enter a valid email address';
    }

    // Check URL
    if (rules.url && !Utils.validation.url(value)) {
      isValid = false;
      errorMessage = 'Please enter a valid URL';
    }

    // Show error if invalid
    if (!isValid) {
      this.showFieldError(field, errorMessage);
    }

    return isValid;
  }

  /**
   * Get validation rules for field
   * @param {HTMLElement} field - Field element
   * @returns {Object}
   */
  getValidationRules(field) {
    const rules = {};

    // HTML5 attributes
    if (field.hasAttribute('required')) rules.required = true;
    if (field.hasAttribute('minlength')) rules.minLength = parseInt(field.getAttribute('minlength'));
    if (field.hasAttribute('maxlength')) rules.maxLength = parseInt(field.getAttribute('maxlength'));
    if (field.hasAttribute('pattern')) rules.pattern = new RegExp(field.getAttribute('pattern'));

    // Data attributes
    if (field.dataset.validateEmail) rules.email = true;
    if (field.dataset.validateUrl) rules.url = true;
    if (field.dataset.errorMessage) rules.message = field.dataset.errorMessage;

    return rules;
  }

  /**
   * Show field error
   * @param {HTMLElement} field - Field element
   * @param {string} message - Error message
   */
  showFieldError(field, message) {
    field.classList.add('error');

    const errorElement = Utils.dom.createElement('div', {
      className: 'field-error',
      textContent: message
    });

    field.parentNode.insertBefore(errorElement, field.nextSibling);
  }

  /**
   * Clear field error
   * @param {HTMLElement} field - Field element
   */
  clearFieldError(field) {
    field.classList.remove('error');

    const errorElement = field.parentNode.querySelector('.field-error');
    if (errorElement) {
      errorElement.remove();
    }
  }

  /**
   * Setup infinite scroll
   */
  setupInfiniteScroll() {
    const containers = Utils.dom.$$('[data-infinite-scroll]');

    containers.forEach(container => {
      const observer = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
          if (entry.isIntersecting) {
            this.loadMoreContent(container);
          }
        });
      }, {
        rootMargin: '100px'
      });

      const sentinel = container.querySelector('.infinite-scroll-sentinel');
      if (sentinel) {
        observer.observe(sentinel);
      }
    });
  }

  /**
   * Load more content for infinite scroll
   * @param {Element} container - Container element
   */
  async loadMoreContent(container) {
    const loading = container.querySelector('.infinite-scroll-loading');
    if (loading) return; // Already loading

    // Show loading indicator
    const loadingElement = Utils.dom.createElement('div', {
      className: 'infinite-scroll-loading',
      textContent: 'Loading...'
    });
    container.appendChild(loadingElement);

    try {
      const endpoint = container.dataset.infiniteScroll;
      const page = parseInt(container.dataset.page || '1') + 1;

      const response = await fetch(`${endpoint}?page=${page}`);
      const data = await response.json();

      if (data.items && data.items.length > 0) {
        // Append new items
        data.items.forEach(item => {
          const itemElement = this.createItemElement(item, container.dataset.itemTemplate);
          container.insertBefore(itemElement, loadingElement);
        });

        container.dataset.page = page;

        // Check if there are more items
        if (!data.hasMore) {
          loadingElement.textContent = 'No more items';
          loadingElement.classList.add('no-more');
        }
      } else {
        loadingElement.textContent = 'No more items';
        loadingElement.classList.add('no-more');
      }
    } catch (error) {
      console.error('Infinite scroll error:', error);
      loadingElement.textContent = 'Error loading more items';
      loadingElement.classList.add('error');
    }
  }

  /**
   * Create item element from template
   * @param {Object} item - Item data
   * @param {string} template - Template selector
   * @returns {Element}
   */
  createItemElement(item, template) {
    const templateElement = Utils.dom.$(template);
    if (!templateElement) return document.createElement('div');

    const element = templateElement.cloneNode(true);
    element.style.display = '';

    // Replace placeholders with data
    Object.keys(item).forEach(key => {
      const placeholders = element.querySelectorAll(`[data-field="${key}"]`);
      placeholders.forEach(placeholder => {
        placeholder.textContent = item[key];
      });
    });

    return element;
  }

  /**
   * Setup image lazy loading
   */
  setupImageLazyLoading() {
    if ('IntersectionObserver' in window) {
      const imageObserver = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
          if (entry.isIntersecting) {
            const img = entry.target;
            img.src = img.dataset.src;
            img.classList.remove('lazy');
            imageObserver.unobserve(img);
          }
        });
      });

      Utils.dom.$$('img[data-src]').forEach(img => {
        imageObserver.observe(img);
      });
    }
  }

  /**
   * Setup responsive helpers
   */
  setupResponsiveHelpers() {
    // Add responsive classes based on screen size
    const updateResponsiveClasses = () => {
      const width = window.innerWidth;
      document.body.classList.toggle('mobile', width < 768);
      document.body.classList.toggle('tablet', width >= 768 && width < 1024);
      document.body.classList.toggle('desktop', width >= 1024);
    };

    updateResponsiveClasses();
    window.addEventListener('resize', updateResponsiveClasses);
  }

  /**
   * Show modal
   * @param {Object} options - Modal options
   */
  showModal(options) {
    const modal = Utils.dom.createElement('div', { className: 'modal-overlay' });
    const content = Utils.dom.createElement('div', { className: 'modal-content' });

    // Header
    if (options.title) {
      const header = Utils.dom.createElement('div', { className: 'modal-header' });
      const title = Utils.dom.createElement('h2', { className: 'modal-title', textContent: options.title });
      header.appendChild(title);

      if (!options.hideClose) {
        const closeBtn = Utils.dom.createElement('button', {
          className: 'modal-close',
          'aria-label': 'Close modal'
        });
        closeBtn.innerHTML = '&times;';
        closeBtn.addEventListener('click', () => this.closeModal(modal));
        header.appendChild(closeBtn);
      }

      content.appendChild(header);
    }

    // Body
    const body = Utils.dom.createElement('div', { className: 'modal-body' });
    if (typeof options.content === 'string') {
      body.innerHTML = options.content;
    } else if (options.content instanceof Element) {
      body.appendChild(options.content);
    }
    content.appendChild(body);

    // Footer
    if (options.buttons && options.buttons.length > 0) {
      const footer = Utils.dom.createElement('div', { className: 'modal-footer' });

      options.buttons.forEach(button => {
        const btn = Utils.dom.createElement('button', {
          className: `btn ${button.class || 'btn-primary'}`,
          textContent: button.text
        });

        if (button.handler) {
          btn.addEventListener('click', () => {
            button.handler();
            if (!button.keepOpen) {
              this.closeModal(modal);
            }
          });
        }

        footer.appendChild(btn);
      });

      content.appendChild(footer);
    }

    modal.appendChild(content);
    document.body.appendChild(modal);

    this.currentModal = modal;

    // Focus management
    setTimeout(() => {
      const focusable = content.querySelectorAll('button, [href], input, select, textarea');
      if (focusable.length > 0) {
        focusable[0].focus();
      }
    }, 100);

    return modal;
  }

  /**
   * Close modal
   * @param {Element} modal - Modal element
   */
  closeModal(modal) {
    if (modal && modal.parentNode) {
      modal.parentNode.removeChild(modal);
    }

    if (this.currentModal === modal) {
      this.currentModal = null;
    }
  }

  /**
   * Close current modal
   */
  closeCurrentModal() {
    if (this.currentModal) {
      this.closeModal(this.currentModal);
    }
  }

  /**
   * Show dropdown
   * @param {Element} trigger - Trigger element
   * @param {Element} dropdown - Dropdown element
   */
  showDropdown(trigger, dropdown) {
    this.closeAllDropdowns();

    dropdown.classList.add('show');
    trigger.setAttribute('aria-expanded', 'true');
    this.dropdowns.set(trigger, dropdown);
  }

  /**
   * Close dropdown
   * @param {Element} trigger - Trigger element
   */
  closeDropdown(trigger) {
    const dropdown = this.dropdowns.get(trigger);
    if (dropdown) {
      dropdown.classList.remove('show');
      trigger.setAttribute('aria-expanded', 'false');
      this.dropdowns.delete(trigger);
    }
  }

  /**
   * Close all dropdowns
   */
  closeAllDropdowns() {
    this.dropdowns.forEach((dropdown, trigger) => {
      this.closeDropdown(trigger);
    });
  }

  /**
   * Show popover
   * @param {Element} trigger - Trigger element
   * @param {Element} popover - Popover element
   */
  showPopover(trigger, popover) {
    this.closeAllPopovers();

    popover.classList.add('show');
    this.popovers.set(trigger, popover);
  }

  /**
   * Close popover
   * @param {Element} trigger - Trigger element
   */
  closePopover(trigger) {
    const popover = this.popovers.get(trigger);
    if (popover) {
      popover.classList.remove('show');
      this.popovers.delete(trigger);
    }
  }

  /**
   * Close all popovers
   */
  closeAllPopovers() {
    this.popovers.forEach((popover, trigger) => {
      this.closePopover(trigger);
    });
  }

  /**
   * Show tooltip
   * @param {Element} element - Target element
   * @param {string} text - Tooltip text
   */
  showTooltip(element, text) {
    const existing = this.tooltips.get(element);
    if (existing) {
      existing.remove();
    }

    const tooltip = Utils.dom.createElement('div', {
      className: 'tooltip',
      textContent: text
    });

    document.body.appendChild(tooltip);
    this.tooltips.set(element, tooltip);

    // Position tooltip
    const rect = element.getBoundingClientRect();
    tooltip.style.left = `${rect.left + rect.width / 2}px`;
    tooltip.style.top = `${rect.top - 10}px`;
    tooltip.style.transform = 'translateX(-50%) translateY(-100%)';
  }

  /**
   * Hide tooltip
   * @param {Element} element - Target element
   */
  hideTooltip(element) {
    const tooltip = this.tooltips.get(element);
    if (tooltip) {
      tooltip.remove();
      this.tooltips.delete(element);
    }
  }

  /**
   * Close mobile menu
   */
  closeMobileMenu() {
    const menu = Utils.dom.$('.navbar-nav');
    const toggle = Utils.dom.$('#mobile-menu-toggle');

    if (menu) {
      menu.classList.remove('show');
    }

    if (toggle) {
      toggle.classList.remove('active');
    }
  }

  /**
   * Show loading spinner
   * @param {Element} container - Container element
   */
  showLoading(container) {
    const spinner = Utils.dom.createElement('div', { className: 'loading-spinner' });
    container.appendChild(spinner);
  }

  /**
   * Hide loading spinner
   * @param {Element} container - Container element
   */
  hideLoading(container) {
    const spinner = container.querySelector('.loading-spinner');
    if (spinner) {
      spinner.remove();
    }
  }

  /**
   * Copy text to clipboard
   * @param {string} text - Text to copy
   * @returns {Promise}
   */
  async copyToClipboard(text) {
    try {
      await navigator.clipboard.writeText(text);
      this.showToast('Copied to clipboard', 'success');
      return true;
    } catch (error) {
      // Fallback for older browsers
      const textArea = Utils.dom.createElement('textarea', {
        value: text,
        style: 'position: fixed; top: -9999px; left: -9999px;'
      });

      document.body.appendChild(textArea);
      textArea.select();

      try {
        document.execCommand('copy');
        this.showToast('Copied to clipboard', 'success');
        return true;
      } catch (fallbackError) {
        this.showToast('Failed to copy to clipboard', 'error');
        return false;
      } finally {
        document.body.removeChild(textArea);
      }
    }
  }

  /**
   * Show toast notification
   * @param {string} message - Toast message
   * @param {string} type - Toast type
   */
  showToast(message, type = 'info') {
    if (window.NotificationManager) {
      window.NotificationManager.show({
        type,
        message,
        duration: 3000
      });
    }
  }

  /**
   * Debounce function calls
   * @param {Function} func - Function to debounce
   * @param {number} wait - Wait time
   * @returns {Function}
   */
  debounce(func, wait) {
    return Utils.debounce(func, wait);
  }

  /**
   * Throttle function calls
   * @param {Function} func - Function to throttle
   * @param {number} limit - Limit time
   * @returns {Function}
   */
  throttle(func, limit) {
    return Utils.throttle(func, limit);
  }

  /**
   * Get element by selector with context
   * @param {string} selector - CSS selector
   * @param {Element} context - Context element
   * @returns {Element|null}
   */
  $(selector, context = document) {
    return Utils.dom.$(selector, context);
  }

  /**
   * Get elements by selector with context
   * @param {string} selector - CSS selector
   * @param {Element} context - Context element
   * @returns {NodeList}
   */
  $$(selector, context = document) {
    return Utils.dom.$$(selector, context);
  }

  /**
   * Destroy UI instance
   */
  destroy() {
    this.closeAllDropdowns();
    this.closeAllPopovers();
    this.closeCurrentModal();

    this.tooltips.forEach(tooltip => tooltip.remove());
    this.tooltips.clear();
  }
}

// Create global UI instance
window.UI = new UI();