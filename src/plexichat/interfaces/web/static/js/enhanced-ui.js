/**
 * PlexiChat Enhanced UI Framework
 * Modern JavaScript framework for advanced UI interactions
 */

class PlexiChatUI {
    constructor() {
        this.theme = localStorage.getItem('plexichat-theme') || 'system';
        this.components = new Map();
        this.observers = new Map();
        this.animations = new Map();
        
        this.init();
    }

    init() {
        this.setupTheme();
        this.setupComponents();
        this.setupObservers();
        this.setupEventListeners();
        this.setupAnimations();
        
        console.log('🎨 PlexiChat Enhanced UI Framework initialized');
    }

    // Theme Management
    setupTheme() {
        this.applyTheme(this.theme);
        
        // Auto-detect system theme changes
        if (window.matchMedia) {
            const mediaQuery = window.matchMedia('(prefers-color-scheme: dark)');
            mediaQuery.addEventListener('change', () => {
                if (this.theme === 'system') {
                    this.applyTheme('system');
                }
            });
        }
    }

    applyTheme(theme) {
        const root = document.documentElement;
        
        if (theme === 'system') {
            const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
            root.setAttribute('data-theme', prefersDark ? 'dark' : 'light');
        } else {
            root.setAttribute('data-theme', theme);
        }
        
        this.theme = theme;
        localStorage.setItem('plexichat-theme', theme);
        
        // Emit theme change event
        this.emit('themeChanged', { theme });
    }

    toggleTheme() {
        const themes = ['light', 'dark', 'system'];
        const currentIndex = themes.indexOf(this.theme);
        const nextTheme = themes[(currentIndex + 1) % themes.length];
        this.applyTheme(nextTheme);
    }

    // Component System
    setupComponents() {
        this.registerComponent('modal', ModalComponent);
        this.registerComponent('notification', NotificationComponent);
        this.registerComponent('dropdown', DropdownComponent);
        this.registerComponent('tooltip', TooltipComponent);
        this.registerComponent('tabs', TabsComponent);
        this.registerComponent('accordion', AccordionComponent);
        this.registerComponent('chart', ChartComponent);
        this.registerComponent('datatable', DataTableComponent);
    }

    registerComponent(name, componentClass) {
        this.components.set(name, componentClass);
        
        // Auto-initialize components found in DOM
        document.querySelectorAll(`[data-component="${name}"]`).forEach(element => {
            new componentClass(element, this);
        });
    }

    createComponent(name, element, options = {}) {
        const ComponentClass = this.components.get(name);
        if (ComponentClass) {
            return new ComponentClass(element, this, options);
        }
        console.warn(`Component "${name}" not found`);
        return null;
    }

    // Observer System
    setupObservers() {
        // Intersection Observer for animations
        this.intersectionObserver = new IntersectionObserver((entries) => {
            entries.forEach(entry => {
                if (entry.isIntersecting) {
                    entry.target.classList.add('animate-in');
                    entry.target.classList.remove('animate-out');
                } else {
                    entry.target.classList.add('animate-out');
                    entry.target.classList.remove('animate-in');
                }
            });
        }, { threshold: 0.1 });

        // Mutation Observer for dynamic content
        this.mutationObserver = new MutationObserver((mutations) => {
            mutations.forEach(mutation => {
                mutation.addedNodes.forEach(node => {
                    if (node.nodeType === Node.ELEMENT_NODE) {
                        this.initializeElement(node);
                    }
                });
            });
        });

        this.mutationObserver.observe(document.body, {
            childList: true,
            subtree: true
        });
    }

    initializeElement(element) {
        // Initialize components
        const componentType = element.getAttribute('data-component');
        if (componentType && this.components.has(componentType)) {
            this.createComponent(componentType, element);
        }

        // Initialize animations
        if (element.hasAttribute('data-animate')) {
            this.intersectionObserver.observe(element);
        }

        // Initialize tooltips
        if (element.hasAttribute('data-tooltip')) {
            this.createComponent('tooltip', element);
        }
    }

    // Event System
    setupEventListeners() {
        // Global keyboard shortcuts
        document.addEventListener('keydown', (e) => {
            // Ctrl/Cmd + K for search
            if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
                e.preventDefault();
                this.emit('searchToggle');
            }
            
            // Ctrl/Cmd + Shift + T for theme toggle
            if ((e.ctrlKey || e.metaKey) && e.shiftKey && e.key === 'T') {
                e.preventDefault();
                this.toggleTheme();
            }
            
            // Escape key handling
            if (e.key === 'Escape') {
                this.emit('escape');
            }
        });

        // Click outside handling
        document.addEventListener('click', (e) => {
            this.emit('clickOutside', { target: e.target });
        });

        // Scroll handling
        let scrollTimeout;
        window.addEventListener('scroll', () => {
            document.body.classList.add('scrolling');
            
            clearTimeout(scrollTimeout);
            scrollTimeout = setTimeout(() => {
                document.body.classList.remove('scrolling');
            }, 150);
            
            this.emit('scroll', { scrollY: window.scrollY });
        });

        // Resize handling
        let resizeTimeout;
        window.addEventListener('resize', () => {
            clearTimeout(resizeTimeout);
            resizeTimeout = setTimeout(() => {
                this.emit('resize', { 
                    width: window.innerWidth, 
                    height: window.innerHeight 
                });
            }, 150);
        });
    }

    // Animation System
    setupAnimations() {
        // CSS Custom Properties for animations
        const style = document.createElement('style');
        style.textContent = `
            .animate-in {
                animation: fadeInUp 0.6s ease-out forwards;
            }
            
            .animate-out {
                animation: fadeOutDown 0.3s ease-in forwards;
            }
            
            @keyframes fadeInUp {
                from {
                    opacity: 0;
                    transform: translateY(20px);
                }
                to {
                    opacity: 1;
                    transform: translateY(0);
                }
            }
            
            @keyframes fadeOutDown {
                from {
                    opacity: 1;
                    transform: translateY(0);
                }
                to {
                    opacity: 0;
                    transform: translateY(10px);
                }
            }
            
            .pulse {
                animation: pulse 2s infinite;
            }
            
            @keyframes pulse {
                0%, 100% { opacity: 1; }
                50% { opacity: 0.5; }
            }
            
            .bounce-in {
                animation: bounceIn 0.6s ease-out;
            }
            
            @keyframes bounceIn {
                0% {
                    transform: scale(0.3);
                    opacity: 0;
                }
                50% {
                    transform: scale(1.05);
                }
                70% {
                    transform: scale(0.9);
                }
                100% {
                    transform: scale(1);
                    opacity: 1;
                }
            }
        `;
        document.head.appendChild(style);
    }

    // Event Emitter
    emit(eventName, data = {}) {
        const event = new CustomEvent(`plexichat:${eventName}`, {
            detail: data,
            bubbles: true
        });
        document.dispatchEvent(event);
    }

    on(eventName, callback) {
        document.addEventListener(`plexichat:${eventName}`, callback);
    }

    off(eventName, callback) {
        document.removeEventListener(`plexichat:${eventName}`, callback);
    }

    // Utility Methods
    async loadComponent(url) {
        try {
            const response = await fetch(url);
            const html = await response.text();
            const template = document.createElement('template');
            template.innerHTML = html;
            return template.content;
        } catch (error) {
            console.error('Failed to load component:', error);
            return null;
        }
    }

    showNotification(message, type = 'info', duration = 5000) {
        const notification = this.createComponent('notification', null, {
            message,
            type,
            duration
        });
        return notification;
    }

    showModal(content, options = {}) {
        const modal = this.createComponent('modal', null, {
            content,
            ...options
        });
        return modal;
    }

    // Performance Monitoring
    measurePerformance(name, fn) {
        const start = performance.now();
        const result = fn();
        const end = performance.now();
        console.log(`⚡ ${name}: ${(end - start).toFixed(2)}ms`);
        return result;
    }

    // Accessibility Helpers
    announceToScreenReader(message) {
        const announcement = document.createElement('div');
        announcement.setAttribute('aria-live', 'polite');
        announcement.setAttribute('aria-atomic', 'true');
        announcement.className = 'sr-only';
        announcement.textContent = message;
        
        document.body.appendChild(announcement);
        
        setTimeout(() => {
            document.body.removeChild(announcement);
        }, 1000);
    }

    // Focus Management
    trapFocus(element) {
        const focusableElements = element.querySelectorAll(
            'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])'
        );
        
        const firstElement = focusableElements[0];
        const lastElement = focusableElements[focusableElements.length - 1];
        
        element.addEventListener('keydown', (e) => {
            if (e.key === 'Tab') {
                if (e.shiftKey) {
                    if (document.activeElement === firstElement) {
                        e.preventDefault();
                        lastElement.focus();
                    }
                } else {
                    if (document.activeElement === lastElement) {
                        e.preventDefault();
                        firstElement.focus();
                    }
                }
            }
        });
        
        firstElement?.focus();
    }
}

// Initialize the UI framework when DOM is ready
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
        window.PlexiUI = new PlexiChatUI();
    });
} else {
    window.PlexiUI = new PlexiChatUI();
}
