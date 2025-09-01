/**
 * PlexiChat Enhanced UI
 * Advanced user interface interactions and enhancements
 */

class EnhancedUI {
  constructor() {
    this.theme = Utils.storage.get('theme', 'dark');
    this.animations = new Map();
    this.intersectionObserver = null;
    this.resizeObserver = null;
    this.init();
  }

  /**
   * Initialize enhanced UI features
   */
  init() {
    this.setupTheme();
    this.setupAnimations();
    this.setupObservers();
    this.setupKeyboardShortcuts();
    this.setupTouchGestures();
    this.setupAccessibility();
    this.setupPerformanceOptimizations();
  }

  /**
   * Setup theme system
   */
  setupTheme() {
    // Set initial theme
    document.documentElement.setAttribute('data-theme', this.theme);

    // Theme toggle functionality
    Utils.dom.on('.theme-toggle', 'click', (e) => {
      this.toggleTheme();
    });

    // System theme detection
    this.setupSystemThemeDetection();
  }

  /**
   * Toggle between light and dark themes
   */
  toggleTheme() {
    this.theme = this.theme === 'dark' ? 'light' : 'dark';
    document.documentElement.setAttribute('data-theme', this.theme);
    Utils.storage.set('theme', this.theme);

    // Update theme toggle button
    const themeToggle = Utils.dom.$('.theme-toggle');
    if (themeToggle) {
      const icon = themeToggle.querySelector('.theme-icon');
      const text = themeToggle.querySelector('.theme-text');

      if (icon) {
        icon.className = `fas fa-${this.theme === 'dark' ? 'sun' : 'moon'}`;
      }

      if (text) {
        text.textContent = `${this.theme === 'dark' ? 'Light' : 'Dark'} Mode`;
      }
    }

    Utils.events.emit('theme:changed', { theme: this.theme });
  }

  /**
   * Setup system theme detection
   */
  setupSystemThemeDetection() {
    if (window.matchMedia) {
      const mediaQuery = window.matchMedia('(prefers-color-scheme: dark)');

      mediaQuery.addEventListener('change', (e) => {
        if (!Utils.storage.get('theme')) {
          // Only auto-switch if user hasn't manually set theme
          this.theme = e.matches ? 'dark' : 'light';
          document.documentElement.setAttribute('data-theme', this.theme);
        }
      });
    }
  }

  /**
   * Setup animations system
   */
  setupAnimations() {
    // Animate elements on scroll
    this.setupScrollAnimations();

    // Animate counters
    this.setupCounterAnimations();

    // Setup loading animations
    this.setupLoadingAnimations();
  }

  /**
   * Setup scroll-based animations
   */
  setupScrollAnimations() {
    this.intersectionObserver = new IntersectionObserver((entries) => {
      entries.forEach(entry => {
        if (entry.isIntersecting) {
          entry.target.classList.add('animate-in');
          this.intersectionObserver.unobserve(entry.target);
        }
      });
    }, {
      threshold: 0.1,
      rootMargin: '50px'
    });

    // Observe elements with animation classes
    Utils.dom.$$('.animate-on-scroll').forEach(element => {
      this.intersectionObserver.observe(element);
    });
  }

  /**
   * Setup counter animations
   */
  setupCounterAnimations() {
    Utils.dom.$$('[data-count]').forEach(counter => {
      const target = parseInt(counter.dataset.count);
      const duration = parseInt(counter.dataset.duration) || 2000;
      const start = parseInt(counter.dataset.start) || 0;

      this.animateCounter(counter, start, target, duration);
    });
  }

  /**
   * Animate counter from start to target
   * @param {Element} element - Counter element
   * @param {number} start - Start value
   * @param {number} target - Target value
   * @param {number} duration - Animation duration
   */
  animateCounter(element, start, target, duration) {
    const startTime = performance.now();
    const difference = target - start;

    const animate = (currentTime) => {
      const elapsed = currentTime - startTime;
      const progress = Math.min(elapsed / duration, 1);

      // Easing function
      const easeOutQuart = 1 - Math.pow(1 - progress, 4);
      const current = Math.round(start + difference * easeOutQuart);

      element.textContent = this.formatNumber(current);

      if (progress < 1) {
        requestAnimationFrame(animate);
      }
    };

    requestAnimationFrame(animate);
  }

  /**
   * Format number with appropriate suffix
   * @param {number} num - Number to format
   * @returns {string}
   */
  formatNumber(num) {
    if (num >= 1000000) {
      return (num / 1000000).toFixed(1) + 'M';
    } else if (num >= 1000) {
      return (num / 1000).toFixed(1) + 'K';
    }
    return num.toString();
  }

  /**
   * Setup loading animations
   */
  setupLoadingAnimations() {
    // Add loading class to body during navigation
    document.addEventListener('DOMContentLoaded', () => {
      document.body.classList.remove('loading');
    });

    // Handle form submissions
    Utils.dom.on('form', 'submit', (e) => {
      const form = e.target;
      if (!form.classList.contains('no-loading')) {
        this.showLoading(form);
      }
    });
  }

  /**
   * Show loading state for element
   * @param {Element} element - Element to show loading for
   */
  showLoading(element) {
    element.classList.add('loading');

    // Disable form elements
    const inputs = element.querySelectorAll('input, button, textarea');
    inputs.forEach(input => {
      input.disabled = true;
      input.dataset.originalDisabled = input.disabled;
    });

    // Add loading spinner
    const spinner = Utils.dom.createElement('div', {
      className: 'loading-overlay'
    });

    const spinnerInner = Utils.dom.createElement('div', {
      className: 'loading-spinner'
    });

    spinner.appendChild(spinnerInner);
    element.style.position = 'relative';
    element.appendChild(spinner);
  }

  /**
   * Hide loading state for element
   * @param {Element} element - Element to hide loading for
   */
  hideLoading(element) {
    element.classList.remove('loading');

    // Re-enable form elements
    const inputs = element.querySelectorAll('input, button, textarea');
    inputs.forEach(input => {
      if (!input.dataset.originalDisabled) {
        input.disabled = false;
      }
      delete input.dataset.originalDisabled;
    });

    // Remove loading spinner
    const spinner = element.querySelector('.loading-overlay');
    if (spinner) {
      spinner.remove();
    }
  }

  /**
   * Setup observers for responsive behavior
   */
  setupObservers() {
    // Resize observer for responsive adjustments
    this.resizeObserver = new ResizeObserver(entries => {
      entries.forEach(entry => {
        const { width } = entry.contentRect;

        // Mobile menu adjustments
        if (width < 768) {
          this.enableMobileMenu();
        } else {
          this.disableMobileMenu();
        }

        // Adjust chat layout
        this.adjustChatLayout(width);
      });
    });

    // Observe main content area
    const mainContent = Utils.dom.$('#main-content');
    if (mainContent) {
      this.resizeObserver.observe(mainContent);
    }
  }

  /**
   * Enable mobile menu functionality
   */
  enableMobileMenu() {
    const navbar = Utils.dom.$('.navbar-enhanced');
    const mobileToggle = Utils.dom.$('#mobile-menu-toggle');
    const navbarNav = Utils.dom.$('.navbar-nav');

    if (mobileToggle && navbarNav) {
      mobileToggle.style.display = 'flex';

      Utils.dom.on(mobileToggle, 'click', () => {
        navbarNav.classList.toggle('show');
        mobileToggle.classList.toggle('active');
      });
    }
  }

  /**
   * Disable mobile menu functionality
   */
  disableMobileMenu() {
    const mobileToggle = Utils.dom.$('#mobile-menu-toggle');
    const navbarNav = Utils.dom.$('.navbar-nav');

    if (mobileToggle) {
      mobileToggle.style.display = 'none';
      mobileToggle.classList.remove('active');
    }

    if (navbarNav) {
      navbarNav.classList.remove('show');
    }
  }

  /**
   * Adjust chat layout based on screen width
   * @param {number} width - Screen width
   */
  adjustChatLayout(width) {
    const chatContainer = Utils.dom.$('.chat-container');
    if (!chatContainer) return;

    if (width < 768) {
      chatContainer.classList.add('mobile');
    } else {
      chatContainer.classList.remove('mobile');
    }
  }

  /**
   * Setup keyboard shortcuts
   */
  setupKeyboardShortcuts() {
    document.addEventListener('keydown', (e) => {
      // Ignore if typing in input/textarea
      if (e.target.matches('input, textarea')) return;

      switch (e.key) {
        case '/':
          e.preventDefault();
          this.focusMessageInput();
          break;
        case 'Escape':
          this.closeModals();
          break;
        case 't':
          if (e.ctrlKey || e.metaKey) {
            e.preventDefault();
            this.toggleTheme();
          }
          break;
      }
    });
  }

  /**
   * Focus message input
   */
  focusMessageInput() {
    const messageInput = Utils.dom.$('.chat-input-textarea');
    if (messageInput) {
      messageInput.focus();
    }
  }

  /**
   * Close all open modals
   */
  closeModals() {
    const modals = Utils.dom.$$('.modal-overlay');
    modals.forEach(modal => modal.remove());
  }

  /**
   * Setup touch gestures for mobile
   */
  setupTouchGestures() {
    if (!('ontouchstart' in window)) return;

    let startX, startY;

    document.addEventListener('touchstart', (e) => {
      startX = e.touches[0].clientX;
      startY = e.touches[0].clientY;
    });

    document.addEventListener('touchend', (e) => {
      if (!startX || !startY) return;

      const endX = e.changedTouches[0].clientX;
      const endY = e.changedTouches[0].clientY;
      const diffX = startX - endX;
      const diffY = startY - endY;

      // Swipe gestures
      if (Math.abs(diffX) > Math.abs(diffY) && Math.abs(diffX) > 50) {
        if (diffX > 0) {
          // Swipe left
          this.handleSwipeLeft();
        } else {
          // Swipe right
          this.handleSwipeRight();
        }
      }
    });
  }

  /**
   * Handle swipe left gesture
   */
  handleSwipeLeft() {
    // Close sidebar on mobile
    const sidebar = Utils.dom.$('.chat-sidebar');
    if (sidebar && window.innerWidth < 768) {
      sidebar.classList.add('collapsed');
    }
  }

  /**
   * Handle swipe right gesture
   */
  handleSwipeRight() {
    // Open sidebar on mobile
    const sidebar = Utils.dom.$('.chat-sidebar');
    if (sidebar && window.innerWidth < 768) {
      sidebar.classList.remove('collapsed');
    }
  }

  /**
   * Setup accessibility enhancements
   */
  setupAccessibility() {
    // Skip links
    this.addSkipLinks();

    // Focus management
    this.setupFocusManagement();

    // ARIA live regions
    this.setupLiveRegions();

    // High contrast mode detection
    this.setupHighContrastDetection();
  }

  /**
   * Add skip links for accessibility
   */
  addSkipLinks() {
    const skipLink = Utils.dom.createElement('a', {
      href: '#main-content',
      className: 'skip-link sr-only',
      textContent: 'Skip to main content'
    });

    document.body.insertBefore(skipLink, document.body.firstChild);
  }

  /**
   * Setup focus management
   */
  setupFocusManagement() {
    // Focus trap for modals
    Utils.dom.on('.modal-overlay', 'keydown', (e) => {
      if (e.key === 'Tab') {
        this.trapFocus(e.target, e);
      }
    });

    // Focus visible styles
    document.addEventListener('keydown', (e) => {
      if (e.key === 'Tab') {
        document.body.classList.add('keyboard-navigation');
      }
    });

    document.addEventListener('mousedown', () => {
      document.body.classList.remove('keyboard-navigation');
    });
  }

  /**
   * Trap focus within element
   * @param {Element} container - Container element
   * @param {Event} e - Keyboard event
   */
  trapFocus(container, e) {
    const focusableElements = container.querySelectorAll(
      'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])'
    );

    const firstElement = focusableElements[0];
    const lastElement = focusableElements[focusableElements.length - 1];

    if (e.shiftKey) {
      if (document.activeElement === firstElement) {
        lastElement.focus();
        e.preventDefault();
      }
    } else {
      if (document.activeElement === lastElement) {
        firstElement.focus();
        e.preventDefault();
      }
    }
  }

  /**
   * Setup ARIA live regions
   */
  setupLiveRegions() {
    // Create live region for notifications
    const liveRegion = Utils.dom.createElement('div', {
      'aria-live': 'polite',
      'aria-atomic': 'true',
      className: 'sr-only',
      id: 'live-region'
    });

    document.body.appendChild(liveRegion);

    // Update live region for notifications
    Utils.events.on('notification:new', (data) => {
      liveRegion.textContent = `${data.title}: ${data.message}`;
      setTimeout(() => {
        liveRegion.textContent = '';
      }, 1000);
    });
  }

  /**
   * Setup high contrast mode detection
   */
  setupHighContrastDetection() {
    if (window.matchMedia) {
      const mediaQuery = window.matchMedia('(prefers-contrast: high)');

      mediaQuery.addEventListener('change', (e) => {
        document.body.classList.toggle('high-contrast', e.matches);
      });

      document.body.classList.toggle('high-contrast', mediaQuery.matches);
    }
  }

  /**
   * Setup performance optimizations
   */
  setupPerformanceOptimizations() {
    // Debounce scroll events
    let scrollTimeout;
    window.addEventListener('scroll', () => {
      if (!scrollTimeout) {
        scrollTimeout = setTimeout(() => {
          this.handleScroll();
          scrollTimeout = null;
        }, 16); // ~60fps
      }
    });

    // Throttle resize events
    let resizeTimeout;
    window.addEventListener('resize', () => {
      clearTimeout(resizeTimeout);
      resizeTimeout = setTimeout(() => {
        this.handleResize();
      }, 100);
    });

    // Lazy load images
    this.setupLazyLoading();

    // Preload critical resources
    this.preloadCriticalResources();
  }

  /**
   * Handle scroll events
   */
  handleScroll() {
    const scrolled = window.pageYOffset;
    const rate = scrolled * -0.5;

    // Parallax effect for hero section
    const hero = Utils.dom.$('.hero-section');
    if (hero) {
      hero.style.transform = `translateY(${rate}px)`;
    }

    // Update navbar on scroll
    const navbar = Utils.dom.$('.navbar-enhanced');
    if (navbar) {
      navbar.classList.toggle('scrolled', scrolled > 50);
    }
  }

  /**
   * Handle resize events
   */
  handleResize() {
    // Recalculate layout
    this.adjustChatLayout(window.innerWidth);
  }

  /**
   * Setup lazy loading for images
   */
  setupLazyLoading() {
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
   * Preload critical resources
   */
  preloadCriticalResources() {
    // Preload theme CSS
    const themeLink = document.querySelector('link[href*="themes.css"]');
    if (themeLink) {
      const link = document.createElement('link');
      link.rel = 'preload';
      link.href = themeLink.href;
      link.as = 'style';
      document.head.appendChild(link);
    }
  }

  /**
   * Show toast notification
   * @param {string} message - Notification message
   * @param {string} type - Notification type
   * @param {number} duration - Duration in milliseconds
   */
  showToast(message, type = 'info', duration = 3000) {
    if (window.UIComponents) {
      const toast = window.UIComponents.create('NotificationToast', {
        message,
        type,
        duration
      });
      toast.show();
    }
  }

  /**
   * Show modal dialog
   * @param {Object} options - Modal options
   */
  showModal(options) {
    if (window.UIComponents) {
      const modal = window.UIComponents.create('Modal', options);
      modal.show();
    }
  }

  /**
   * Enable dark mode
   */
  enableDarkMode() {
    this.theme = 'dark';
    document.documentElement.setAttribute('data-theme', this.theme);
    Utils.storage.set('theme', this.theme);
  }

  /**
   * Enable light mode
   */
  enableLightMode() {
    this.theme = 'light';
    document.documentElement.setAttribute('data-theme', this.theme);
    Utils.storage.set('theme', this.theme);
  }

  /**
   * Get current theme
   * @returns {string}
   */
  getCurrentTheme() {
    return this.theme;
  }

  /**
   * Destroy enhanced UI instance
   */
  destroy() {
    if (this.intersectionObserver) {
      this.intersectionObserver.disconnect();
    }

    if (this.resizeObserver) {
      this.resizeObserver.disconnect();
    }

    // Clear any timeouts/intervals
    this.animations.clear();
  }
}

// Create global enhanced UI instance
window.EnhancedUI = new EnhancedUI();