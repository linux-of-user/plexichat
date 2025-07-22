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
window.TabsComponent = TabsComponent;
