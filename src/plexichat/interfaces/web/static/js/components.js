/**
 * PlexiChat UI Components
 * Reusable UI components for the enhanced framework
 */

// Base Component Class
class BaseComponent {
    constructor(element, ui, options = {}) {
        this.element = element;
        this.ui = ui;
        this.options = { ...this.defaultOptions, ...options };
        this.isDestroyed = false;
        
        this.init();
    }

    get defaultOptions() {
        return {};
    }

    init() {
        this.bindEvents();
    }

    bindEvents() {
        // Override in subclasses
    }

    destroy() {
        this.isDestroyed = true;
        if (this.element) {
            this.element.removeEventListener = () => {};
        }
    }

    emit(eventName, data = {}) {
        if (this.ui) {
            this.ui.emit(eventName, { component: this, ...data });
        }
    }
}

// Modal Component
class ModalComponent extends BaseComponent {
    get defaultOptions() {
        return {
            backdrop: true,
            keyboard: true,
            focus: true,
            show: false
        };
    }

    init() {
        super.init();
        this.createModal();
        if (this.options.show) {
            this.show();
        }
    }

    createModal() {
        if (!this.element) {
            this.element = document.createElement('div');
            this.element.className = 'modal-enhanced';
            this.element.innerHTML = `
                <div class="modal-content-enhanced">
                    <div class="modal-header-enhanced">
                        <h3 class="modal-title-enhanced">${this.options.title || 'Modal'}</h3>
                        <button class="modal-close-enhanced" data-dismiss="modal">
                            <i class="fas fa-times"></i>
                        </button>
                    </div>
                    <div class="modal-body-enhanced">
                        ${this.options.content || ''}
                    </div>
                    ${this.options.footer ? `<div class="modal-footer-enhanced">${this.options.footer}</div>` : ''}
                </div>
            `;
            document.body.appendChild(this.element);
        }
    }

    bindEvents() {
        // Close button
        this.element.querySelector('[data-dismiss="modal"]')?.addEventListener('click', () => {
            this.hide();
        });

        // Backdrop click
        if (this.options.backdrop) {
            this.element.addEventListener('click', (e) => {
                if (e.target === this.element) {
                    this.hide();
                }
            });
        }

        // Keyboard events
        if (this.options.keyboard) {
            document.addEventListener('keydown', (e) => {
                if (e.key === 'Escape' && this.isVisible()) {
                    this.hide();
                }
            });
        }
    }

    show() {
        this.element.classList.add('active');
        document.body.style.overflow = 'hidden';
        
        if (this.options.focus && this.ui) {
            this.ui.trapFocus(this.element);
        }
        
        this.emit('modalShown');
    }

    hide() {
        this.element.classList.remove('active');
        document.body.style.overflow = '';
        this.emit('modalHidden');
    }

    isVisible() {
        return this.element.classList.contains('active');
    }

    setContent(content) {
        const body = this.element.querySelector('.modal-body-enhanced');
        if (body) {
            body.innerHTML = content;
        }
    }
}

// Notification Component
class NotificationComponent extends BaseComponent {
    get defaultOptions() {
        return {
            type: 'info',
            duration: 5000,
            position: 'top-right',
            closable: true,
            message: ''
        };
    }

    init() {
        super.init();
        this.createNotification();
        this.show();
        
        if (this.options.duration > 0) {
            setTimeout(() => this.hide(), this.options.duration);
        }
    }

    createNotification() {
        this.element = document.createElement('div');
        this.element.className = `notification notification-${this.options.type}`;
        this.element.innerHTML = `
            <div class="notification-content">
                <i class="notification-icon fas fa-${this.getIcon()}"></i>
                <span class="notification-message">${this.options.message}</span>
                ${this.options.closable ? '<button class="notification-close"><i class="fas fa-times"></i></button>' : ''}
            </div>
        `;

        const container = this.getContainer();
        container.appendChild(this.element);
    }

    getContainer() {
        let container = document.querySelector('.notification-container');
        if (!container) {
            container = document.createElement('div');
            container.className = 'notification-container';
            document.body.appendChild(container);
        }
        return container;
    }

    getIcon() {
        const icons = {
            success: 'check-circle',
            error: 'exclamation-triangle',
            warning: 'exclamation-circle',
            info: 'info-circle'
        };
        return icons[this.options.type] || 'info-circle';
    }

    bindEvents() {
        const closeBtn = this.element.querySelector('.notification-close');
        if (closeBtn) {
            closeBtn.addEventListener('click', () => this.hide());
        }
    }

    show() {
        setTimeout(() => {
            this.element.classList.add('fade-in');
        }, 10);
    }

    hide() {
        this.element.classList.add('fade-out');
        setTimeout(() => {
            if (this.element.parentNode) {
                this.element.parentNode.removeChild(this.element);
            }
        }, 300);
    }
}

// Dropdown Component
class DropdownComponent extends BaseComponent {
    get defaultOptions() {
        return {
            trigger: 'click',
            placement: 'bottom-start',
            offset: [0, 8]
        };
    }

    init() {
        super.init();
        this.trigger = this.element.querySelector('[data-dropdown-trigger]');
        this.menu = this.element.querySelector('[data-dropdown-menu]');
        this.isOpen = false;
    }

    bindEvents() {
        if (this.options.trigger === 'click') {
            this.trigger?.addEventListener('click', (e) => {
                e.preventDefault();
                this.toggle();
            });
        } else if (this.options.trigger === 'hover') {
            this.element.addEventListener('mouseenter', () => this.show());
            this.element.addEventListener('mouseleave', () => this.hide());
        }

        // Close on outside click
        document.addEventListener('click', (e) => {
            if (!this.element.contains(e.target) && this.isOpen) {
                this.hide();
            }
        });

        // Close on escape
        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape' && this.isOpen) {
                this.hide();
            }
        });
    }

    toggle() {
        this.isOpen ? this.hide() : this.show();
    }

    show() {
        if (this.menu) {
            this.menu.style.display = 'block';
            this.isOpen = true;
            this.element.classList.add('active');
            this.emit('dropdownShown');
        }
    }

    hide() {
        if (this.menu) {
            this.menu.style.display = 'none';
            this.isOpen = false;
            this.element.classList.remove('active');
            this.emit('dropdownHidden');
        }
    }
}

// Tooltip Component
class TooltipComponent extends BaseComponent {
    get defaultOptions() {
        return {
            placement: 'top',
            trigger: 'hover',
            delay: 0,
            content: ''
        };
    }

    init() {
        super.init();
        this.content = this.options.content || this.element.getAttribute('data-tooltip');
        this.createTooltip();
    }

    createTooltip() {
        this.tooltip = document.createElement('div');
        this.tooltip.className = 'tooltip';
        this.tooltip.innerHTML = `
            <div class="tooltip-arrow"></div>
            <div class="tooltip-content">${this.content}</div>
        `;
        document.body.appendChild(this.tooltip);
    }

    bindEvents() {
        if (this.options.trigger === 'hover') {
            this.element.addEventListener('mouseenter', () => this.show());
            this.element.addEventListener('mouseleave', () => this.hide());
        } else if (this.options.trigger === 'click') {
            this.element.addEventListener('click', () => this.toggle());
        }
    }

    show() {
        if (this.showTimeout) clearTimeout(this.showTimeout);
        
        this.showTimeout = setTimeout(() => {
            this.tooltip.style.display = 'block';
            this.position();
            this.tooltip.classList.add('fade-in');
        }, this.options.delay);
    }

    hide() {
        if (this.showTimeout) clearTimeout(this.showTimeout);
        
        this.tooltip.classList.remove('fade-in');
        setTimeout(() => {
            this.tooltip.style.display = 'none';
        }, 150);
    }

    position() {
        const rect = this.element.getBoundingClientRect();
        const tooltipRect = this.tooltip.getBoundingClientRect();
        
        let top, left;
        
        switch (this.options.placement) {
            case 'top':
                top = rect.top - tooltipRect.height - 8;
                left = rect.left + (rect.width - tooltipRect.width) / 2;
                break;
            case 'bottom':
                top = rect.bottom + 8;
                left = rect.left + (rect.width - tooltipRect.width) / 2;
                break;
            case 'left':
                top = rect.top + (rect.height - tooltipRect.height) / 2;
                left = rect.left - tooltipRect.width - 8;
                break;
            case 'right':
                top = rect.top + (rect.height - tooltipRect.height) / 2;
                left = rect.right + 8;
                break;
        }
        
        this.tooltip.style.top = `${top + window.scrollY}px`;
        this.tooltip.style.left = `${left + window.scrollX}px`;
    }

    toggle() {
        this.tooltip.style.display === 'block' ? this.hide() : this.show();
    }
}

// Tabs Component
class TabsComponent extends BaseComponent {
    init() {
        super.init();
        this.tabs = this.element.querySelectorAll('[data-tab]');
        this.panels = this.element.querySelectorAll('[data-tab-panel]');
        this.activeTab = this.element.querySelector('[data-tab].active') || this.tabs[0];
        
        this.showTab(this.activeTab.getAttribute('data-tab'));
    }

    bindEvents() {
        this.tabs.forEach(tab => {
            tab.addEventListener('click', (e) => {
                e.preventDefault();
                const tabId = tab.getAttribute('data-tab');
                this.showTab(tabId);
            });
        });
    }

    showTab(tabId) {
        // Update tabs
        this.tabs.forEach(tab => {
            tab.classList.toggle('active', tab.getAttribute('data-tab') === tabId);
        });

        // Update panels
        this.panels.forEach(panel => {
            panel.classList.toggle('active', panel.getAttribute('data-tab-panel') === tabId);
        });

        this.emit('tabChanged', { tabId });
    }
}

// Export components
window.ModalComponent = ModalComponent;
window.NotificationComponent = NotificationComponent;
window.DropdownComponent = DropdownComponent;
window.TooltipComponent = TooltipComponent;
// Shortcuts Help Modal Component
class ShortcutsHelpModalComponent extends ModalComponent {
    constructor(options = {}) {
        super(null, null, {
            title: 'Keyboard Shortcuts',
            content: '',
            footer: '',
            ...options
        });

        this.searchTerm = '';
        this.selectedCategory = 'all';
        this.shortcutsData = {};

        this.init();
    }

    init() {
        super.init();
        this.createModal();
        this.loadShortcutsData();
        this.renderContent();
        this.bindEvents();
    }

    createModal() {
        if (!this.element) {
            this.element = document.createElement('div');
            this.element.className = 'modal-enhanced shortcuts-help-modal';
            this.element.innerHTML = `
                <div class="modal-content-enhanced shortcuts-modal-content">
                    <div class="modal-header-enhanced">
                        <h3 class="modal-title-enhanced">
                            <i class="fas fa-keyboard"></i>
                            Keyboard Shortcuts
                        </h3>
                        <button class="modal-close-enhanced" data-dismiss="modal">
                            <i class="fas fa-times"></i>
                        </button>
                    </div>
                    <div class="modal-body-enhanced">
                        <div class="shortcuts-controls">
                            <div class="shortcuts-search">
                                <input type="text" placeholder="Search shortcuts..." class="shortcuts-search-input">
                                <i class="fas fa-search search-icon"></i>
                            </div>
                            <div class="shortcuts-categories">
                                <button class="category-btn active" data-category="all">All</button>
                                <button class="category-btn" data-category="messaging">Messaging</button>
                                <button class="category-btn" data-category="navigation">Navigation</button>
                                <button class="category-btn" data-category="interface">Interface</button>
                                <button class="category-btn" data-category="files">Files</button>
                                <button class="category-btn" data-category="user">User</button>
                            </div>
                        </div>
                        <div class="shortcuts-list">
                            <!-- Shortcuts will be rendered here -->
                        </div>
                    </div>
                    <div class="modal-footer-enhanced">
                        <div class="shortcuts-footer-info">
                            <span class="platform-info">
                                <i class="fas fa-info-circle"></i>
                                Shortcuts are platform-aware and may differ on Mac/Windows/Linux
                            </span>
                        </div>
                        <div class="shortcuts-actions">
                            <button class="btn btn-secondary" onclick="shortcutsHelpModal.hide()">Close</button>
                        </div>
                    </div>
                </div>
            `;
            document.body.appendChild(this.element);
        }
    }

    loadShortcutsData() {
        if (window.shortcutsManager) {
            this.shortcutsData = window.shortcutsManager.getShortcutsByCategory();
        } else {
            // Fallback data
            this.shortcutsData = {
                messaging: [
                    { keys: ['Enter'], description: 'Send message' },
                    { keys: ['Shift', 'Enter'], description: 'New line' }
                ],
                navigation: [
                    { keys: ['Ctrl', '/'], description: 'Focus message input' },
                    { keys: ['Ctrl', 'k'], description: 'Open search' }
                ]
            };
        }
    }

    renderContent() {
        const listContainer = this.element.querySelector('.shortcuts-list');
        if (!listContainer) return;

        const shortcuts = this.getFilteredShortcuts();

        if (shortcuts.length === 0) {
            listContainer.innerHTML = `
                <div class="no-shortcuts">
                    <i class="fas fa-search"></i>
                    <p>No shortcuts found matching "${this.searchTerm}"</p>
                </div>
            `;
            return;
        }

        const groupedShortcuts = this.groupShortcutsByCategory(shortcuts);

        listContainer.innerHTML = Object.entries(groupedShortcuts)
            .map(([category, categoryShortcuts]) => `
                <div class="shortcuts-category">
                    <h4 class="category-title">
                        <i class="fas fa-${this.getCategoryIcon(category)}"></i>
                        ${this.capitalizeFirst(category)}
                    </h4>
                    <div class="category-shortcuts">
                        ${categoryShortcuts.map(shortcut => `
                            <div class="shortcut-item">
                                <div class="shortcut-keys">
                                    ${this.formatShortcutKeys(shortcut.keys)}
                                </div>
                                <div class="shortcut-description">
                                    ${shortcut.description}
                                </div>
                            </div>
                        `).join('')}
                    </div>
                </div>
            `).join('');
    }

    getFilteredShortcuts() {
        let shortcuts = [];

        if (this.selectedCategory === 'all') {
            Object.values(this.shortcutsData).forEach(categoryShortcuts => {
                shortcuts.push(...categoryShortcuts);
            });
        } else {
            shortcuts = this.shortcutsData[this.selectedCategory] || [];
        }

        if (this.searchTerm) {
            const term = this.searchTerm.toLowerCase();
            shortcuts = shortcuts.filter(shortcut =>
                shortcut.description.toLowerCase().includes(term) ||
                shortcut.keys.some(key => key.toLowerCase().includes(term))
            );
        }

        return shortcuts;
    }

    groupShortcutsByCategory(shortcuts) {
        const grouped = {};

        shortcuts.forEach(shortcut => {
            const category = shortcut.category || 'general';
            if (!grouped[category]) {
                grouped[category] = [];
            }
            grouped[category].push(shortcut);
        });

        return grouped;
    }

    formatShortcutKeys(keys) {
        if (!keys || !Array.isArray(keys)) return '';

        return keys.map(key => {
            const formattedKey = this.formatKey(key);
            return `<kbd class="shortcut-key">${formattedKey}</kbd>`;
        }).join(' + ');
    }

    formatKey(key) {
        if (window.shortcutsManager) {
            // Use the manager's formatting
            return window.shortcutsManager.formatKeys([key]).replace(' + ', '');
        }

        // Fallback formatting
        switch (key) {
            case 'Control':
                return navigator.platform.includes('Mac') ? '⌘' : 'Ctrl';
            case 'Alt':
                return navigator.platform.includes('Mac') ? '⌥' : 'Alt';
            case 'Shift':
                return '⇧';
            case 'ArrowUp':
                return '↑';
            case 'ArrowDown':
                return '↓';
            default:
                return key;
        }
    }

    getCategoryIcon(category) {
        const icons = {
            messaging: 'comment',
            navigation: 'arrows-alt',
            interface: 'desktop',
            files: 'file',
            user: 'user',
            general: 'keyboard'
        };
        return icons[category] || 'keyboard';
    }

    capitalizeFirst(str) {
        return str.charAt(0).toUpperCase() + str.slice(1);
    }

    bindEvents() {
        super.bindEvents();

        // Search functionality
        const searchInput = this.element.querySelector('.shortcuts-search-input');
        if (searchInput) {
            searchInput.addEventListener('input', (e) => {
                this.searchTerm = e.target.value;
                this.renderContent();
            });
        }

        // Category filtering
        const categoryBtns = this.element.querySelectorAll('.category-btn');
        categoryBtns.forEach(btn => {
            btn.addEventListener('click', (e) => {
                // Update active state
                categoryBtns.forEach(b => b.classList.remove('active'));
                e.target.classList.add('active');

                // Update selected category
                this.selectedCategory = e.target.dataset.category;
                this.renderContent();
            });
        });
    }

    show() {
        super.show();
        // Focus search input when modal opens
        setTimeout(() => {
            const searchInput = this.element.querySelector('.shortcuts-search-input');
            if (searchInput) {
                searchInput.focus();
            }
        }, 100);
    }
}

// Create global shortcuts help modal instance
const shortcutsHelpModal = new ShortcutsHelpModalComponent();

// Export for global access
window.ShortcutsHelpModalComponent = ShortcutsHelpModalComponent;
window.shortcutsHelpModal = shortcutsHelpModal;
window.TabsComponent = TabsComponent;
