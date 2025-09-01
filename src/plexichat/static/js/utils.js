/**
 * PlexiChat Utility Functions
 * Core utility functions for the web interface
 */

class Utils {
  /**
   * DOM manipulation utilities
   */
  static dom = {
    /**
     * Get element by selector
     * @param {string} selector - CSS selector
     * @param {Element} context - Context element (optional)
     * @returns {Element|null}
     */
    $(selector, context = document) {
      return context.querySelector(selector);
    },

    /**
     * Get elements by selector
     * @param {string} selector - CSS selector
     * @param {Element} context - Context element (optional)
     * @returns {NodeList}
     */
    $$(selector, context = document) {
      return context.querySelectorAll(selector);
    },

    /**
     * Create element with attributes and content
     * @param {string} tag - HTML tag name
     * @param {Object} attrs - Attributes object
     * @param {string|Element} content - Inner content
     * @returns {Element}
     */
    createElement(tag, attrs = {}, content = '') {
      const element = document.createElement(tag);

      // Set attributes
      Object.entries(attrs).forEach(([key, value]) => {
        if (key === 'className') {
          element.className = value;
        } else if (key === 'style' && typeof value === 'object') {
          Object.assign(element.style, value);
        } else if (key.startsWith('on') && typeof value === 'function') {
          element.addEventListener(key.slice(2).toLowerCase(), value);
        } else {
          element.setAttribute(key, value);
        }
      });

      // Set content
      if (typeof content === 'string') {
        element.innerHTML = content;
      } else if (content instanceof Element) {
        element.appendChild(content);
      }

      return element;
    },

    /**
     * Add event listener with delegation
     * @param {string} selector - CSS selector
     * @param {string} event - Event type
     * @param {Function} handler - Event handler
     * @param {Element} context - Context element (optional)
     */
    on(selector, event, handler, context = document) {
      context.addEventListener(event, (e) => {
        if (e.target.matches(selector) || e.target.closest(selector)) {
          handler.call(e.target, e);
        }
      });
    },

    /**
     * Toggle element visibility
     * @param {Element} element - Element to toggle
     * @param {boolean} show - Show or hide
     */
    toggle(element, show = null) {
      if (show === null) {
        show = element.style.display === 'none';
      }
      element.style.display = show ? 'block' : 'none';
    },

    /**
     * Add CSS class
     * @param {Element} element - Target element
     * @param {string} className - Class to add
     */
    addClass(element, className) {
      element.classList.add(className);
    },

    /**
     * Remove CSS class
     * @param {Element} element - Target element
     * @param {string} className - Class to remove
     */
    removeClass(element, className) {
      element.classList.remove(className);
    },

    /**
     * Toggle CSS class
     * @param {Element} element - Target element
     * @param {string} className - Class to toggle
     */
    toggleClass(element, className) {
      element.classList.toggle(className);
    },

    /**
     * Check if element has class
     * @param {Element} element - Target element
     * @param {string} className - Class to check
     * @returns {boolean}
     */
    hasClass(element, className) {
      return element.classList.contains(className);
    }
  };

  /**
   * String manipulation utilities
   */
  static string = {
    /**
     * Capitalize first letter
     * @param {string} str - Input string
     * @returns {string}
     */
    capitalize(str) {
      return str.charAt(0).toUpperCase() + str.slice(1);
    },

    /**
     * Convert to camelCase
     * @param {string} str - Input string
     * @returns {string}
     */
    camelCase(str) {
      return str.replace(/[-_\s]+(.)?/g, (_, c) => c ? c.toUpperCase() : '');
    },

    /**
     * Convert to kebab-case
     * @param {string} str - Input string
     * @returns {string}
     */
    kebabCase(str) {
      return str.replace(/([a-z])([A-Z])/g, '$1-$2').toLowerCase();
    },

    /**
     * Truncate string with ellipsis
     * @param {string} str - Input string
     * @param {number} maxLength - Maximum length
     * @returns {string}
     */
    truncate(str, maxLength) {
      if (str.length <= maxLength) return str;
      return str.slice(0, maxLength - 3) + '...';
    },

    /**
     * Generate random string
     * @param {number} length - String length
     * @returns {string}
     */
    random(length = 8) {
      const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
      let result = '';
      for (let i = 0; i < length; i++) {
        result += chars.charAt(Math.floor(Math.random() * chars.length));
      }
      return result;
    }
  };

  /**
   * Array manipulation utilities
   */
  static array = {
    /**
     * Remove duplicates from array
     * @param {Array} arr - Input array
     * @returns {Array}
     */
    unique(arr) {
      return [...new Set(arr)];
    },

    /**
     * Shuffle array elements
     * @param {Array} arr - Input array
     * @returns {Array}
     */
    shuffle(arr) {
      const shuffled = [...arr];
      for (let i = shuffled.length - 1; i > 0; i--) {
        const j = Math.floor(Math.random() * (i + 1));
        [shuffled[i], shuffled[j]] = [shuffled[j], shuffled[i]];
      }
      return shuffled;
    },

    /**
     * Group array by key
     * @param {Array} arr - Input array
     * @param {string|Function} key - Grouping key or function
     * @returns {Object}
     */
    groupBy(arr, key) {
      return arr.reduce((groups, item) => {
        const groupKey = typeof key === 'function' ? key(item) : item[key];
        if (!groups[groupKey]) {
          groups[groupKey] = [];
        }
        groups[groupKey].push(item);
        return groups;
      }, {});
    },

    /**
     * Chunk array into smaller arrays
     * @param {Array} arr - Input array
     * @param {number} size - Chunk size
     * @returns {Array}
     */
    chunk(arr, size) {
      const chunks = [];
      for (let i = 0; i < arr.length; i += size) {
        chunks.push(arr.slice(i, i + size));
      }
      return chunks;
    }
  };

  /**
   * Date and time utilities
   */
  static date = {
    /**
     * Format date to readable string
     * @param {Date|string} date - Date to format
     * @param {string} format - Format string
     * @returns {string}
     */
    format(date, format = 'YYYY-MM-DD HH:mm:ss') {
      const d = new Date(date);
      const tokens = {
        YYYY: d.getFullYear(),
        MM: String(d.getMonth() + 1).padStart(2, '0'),
        DD: String(d.getDate()).padStart(2, '0'),
        HH: String(d.getHours()).padStart(2, '0'),
        mm: String(d.getMinutes()).padStart(2, '0'),
        ss: String(d.getSeconds()).padStart(2, '0')
      };

      return format.replace(/YYYY|MM|DD|HH|mm|ss/g, match => tokens[match]);
    },

    /**
     * Get relative time string
     * @param {Date|string} date - Date to compare
     * @returns {string}
     */
    relativeTime(date) {
      const now = new Date();
      const d = new Date(date);
      const diff = now - d;
      const minutes = Math.floor(diff / 60000);
      const hours = Math.floor(diff / 3600000);
      const days = Math.floor(diff / 86400000);

      if (minutes < 1) return 'Just now';
      if (minutes < 60) return `${minutes}m ago`;
      if (hours < 24) return `${hours}h ago`;
      if (days < 7) return `${days}d ago`;
      return this.format(d, 'MMM DD');
    },

    /**
     * Check if date is today
     * @param {Date|string} date - Date to check
     * @returns {boolean}
     */
    isToday(date) {
      const d = new Date(date);
      const today = new Date();
      return d.toDateString() === today.toDateString();
    }
  };

  /**
   * Validation utilities
   */
  static validation = {
    /**
     * Validate email address
     * @param {string} email - Email to validate
     * @returns {boolean}
     */
    email(email) {
      const regex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
      return regex.test(email);
    },

    /**
     * Validate URL
     * @param {string} url - URL to validate
     * @returns {boolean}
     */
    url(url) {
      try {
        new URL(url);
        return true;
      } catch {
        return false;
      }
    },

    /**
     * Check if string is empty
     * @param {string} str - String to check
     * @returns {boolean}
     */
    isEmpty(str) {
      return !str || str.trim().length === 0;
    },

    /**
     * Check string length
     * @param {string} str - String to check
     * @param {number} min - Minimum length
     * @param {number} max - Maximum length
     * @returns {boolean}
     */
    length(str, min = 0, max = Infinity) {
      const len = str.length;
      return len >= min && len <= max;
    }
  };

  /**
   * Storage utilities
   */
  static storage = {
    /**
     * Get item from localStorage
     * @param {string} key - Storage key
     * @param {*} defaultValue - Default value
     * @returns {*}
     */
    get(key, defaultValue = null) {
      try {
        const item = localStorage.getItem(key);
        return item ? JSON.parse(item) : defaultValue;
      } catch {
        return defaultValue;
      }
    },

    /**
     * Set item in localStorage
     * @param {string} key - Storage key
     * @param {*} value - Value to store
     */
    set(key, value) {
      try {
        localStorage.setItem(key, JSON.stringify(value));
      } catch (error) {
        console.error('Storage set error:', error);
      }
    },

    /**
     * Remove item from localStorage
     * @param {string} key - Storage key
     */
    remove(key) {
      try {
        localStorage.removeItem(key);
      } catch (error) {
        console.error('Storage remove error:', error);
      }
    },

    /**
     * Clear all localStorage
     */
    clear() {
      try {
        localStorage.clear();
      } catch (error) {
        console.error('Storage clear error:', error);
      }
    }
  };

  /**
   * HTTP utilities
   */
  static http = {
    /**
     * Make HTTP request
     * @param {string} url - Request URL
     * @param {Object} options - Request options
     * @returns {Promise}
     */
    async request(url, options = {}) {
      const defaultOptions = {
        headers: {
          'Content-Type': 'application/json',
          'X-CSRF-Token': window.ChatAPI?.csrfToken || ''
        }
      };

      const config = { ...defaultOptions, ...options };

      if (config.body && typeof config.body === 'object') {
        config.body = JSON.stringify(config.body);
      }

      try {
        const response = await fetch(url, config);
        const data = await response.json();
        return { data, status: response.status, ok: response.ok };
      } catch (error) {
        console.error('HTTP request error:', error);
        throw error;
      }
    },

    /**
     * GET request
     * @param {string} url - Request URL
     * @param {Object} options - Request options
     * @returns {Promise}
     */
    get(url, options = {}) {
      return this.request(url, { ...options, method: 'GET' });
    },

    /**
     * POST request
     * @param {string} url - Request URL
     * @param {Object} data - Request data
     * @param {Object} options - Request options
     * @returns {Promise}
     */
    post(url, data, options = {}) {
      return this.request(url, { ...options, method: 'POST', body: data });
    },

    /**
     * PUT request
     * @param {string} url - Request URL
     * @param {Object} data - Request data
     * @param {Object} options - Request options
     * @returns {Promise}
     */
    put(url, data, options = {}) {
      return this.request(url, { ...options, method: 'PUT', body: data });
    },

    /**
     * DELETE request
     * @param {string} url - Request URL
     * @param {Object} options - Request options
     * @returns {Promise}
     */
    delete(url, options = {}) {
      return this.request(url, { ...options, method: 'DELETE' });
    }
  };

  /**
   * Event utilities
   */
  static events = {
    /**
     * Custom event system
     */
    listeners: new Map(),

    /**
     * Add event listener
     * @param {string} event - Event name
     * @param {Function} callback - Event callback
     */
    on(event, callback) {
      if (!this.listeners.has(event)) {
        this.listeners.set(event, []);
      }
      this.listeners.get(event).push(callback);
    },

    /**
     * Remove event listener
     * @param {string} event - Event name
     * @param {Function} callback - Event callback
     */
    off(event, callback) {
      if (this.listeners.has(event)) {
        const listeners = this.listeners.get(event);
        const index = listeners.indexOf(callback);
        if (index > -1) {
          listeners.splice(index, 1);
        }
      }
    },

    /**
     * Emit event
     * @param {string} event - Event name
     * @param {*} data - Event data
     */
    emit(event, data) {
      if (this.listeners.has(event)) {
        this.listeners.get(event).forEach(callback => {
          try {
            callback(data);
          } catch (error) {
            console.error('Event callback error:', error);
          }
        });
      }
    }
  };

  /**
   * Debounce function
   * @param {Function} func - Function to debounce
   * @param {number} wait - Wait time in milliseconds
   * @returns {Function}
   */
  static debounce(func, wait) {
    let timeout;
    return function executedFunction(...args) {
      const later = () => {
        clearTimeout(timeout);
        func(...args);
      };
      clearTimeout(timeout);
      timeout = setTimeout(later, wait);
    };
  }

  /**
   * Throttle function
   * @param {Function} func - Function to throttle
   * @param {number} limit - Limit time in milliseconds
   * @returns {Function}
   */
  static throttle(func, limit) {
    let inThrottle;
    return function executedFunction(...args) {
      if (!inThrottle) {
        func.apply(this, args);
        inThrottle = true;
        setTimeout(() => inThrottle = false, limit);
      }
    };
  }

  /**
   * Generate UUID
   * @returns {string}
   */
  static uuid() {
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
      const r = Math.random() * 16 | 0;
      const v = c === 'x' ? r : (r & 0x3 | 0x8);
      return v.toString(16);
    });
  }

  /**
   * Deep clone object
   * @param {*} obj - Object to clone
   * @returns {*}
   */
  static deepClone(obj) {
    if (obj === null || typeof obj !== 'object') return obj;
    if (obj instanceof Date) return new Date(obj.getTime());
    if (obj instanceof Array) return obj.map(item => this.deepClone(item));
    if (typeof obj === 'object') {
      const cloned = {};
      Object.keys(obj).forEach(key => {
        cloned[key] = this.deepClone(obj[key]);
      });
      return cloned;
    }
  }

  /**
   * Check if object is empty
   * @param {Object} obj - Object to check
   * @returns {boolean}
   */
  static isEmpty(obj) {
    return obj && Object.keys(obj).length === 0 && obj.constructor === Object;
  }

  /**
   * Get nested object property
   * @param {Object} obj - Object to search
   * @param {string} path - Property path (e.g., 'a.b.c')
   * @param {*} defaultValue - Default value
   * @returns {*}
   */
  static get(obj, path, defaultValue = undefined) {
    const keys = path.split('.');
    let result = obj;
    for (const key of keys) {
      if (result && typeof result === 'object' && key in result) {
        result = result[key];
      } else {
        return defaultValue;
      }
    }
    return result;
  }
}

// Make Utils globally available
window.Utils = Utils;