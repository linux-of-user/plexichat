/**
 * PlexiChat Main JavaScript
 * Core functionality for the web interface
 */

class PlexiChatApp {
    constructor() {
        this.apiBase = '/api/v1';
        this.currentUser = null;
        this.socket = null;
        this.notifications = [];
        
        this.init();
    }
    
    async init() {
        // Initialize the application
        await this.checkAuth();
        this.setupEventListeners();
        this.initializeComponents();
        this.startHeartbeat();
    }
    
    async checkAuth() {
        try {
            const response = await fetch('/auth/verify-session', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ session_id: this.getSessionId() })
            });
            
            if (response.ok) {
                const data = await response.json();
                this.currentUser = data.data;
                this.updateUI();
            } else {
                this.redirectToLogin();
            }
        } catch (error) {
            console.error('Auth check failed:', error);
            this.redirectToLogin();
        }
    }
    
    setupEventListeners() {
        // Global event listeners
        document.addEventListener('DOMContentLoaded', () => {
            this.initializeTooltips();
            this.initializeModals();
        });
        
        // Keyboard shortcuts
        document.addEventListener('keydown', (e) => {
            if (e.ctrlKey || e.metaKey) {
                switch (e.key) {
                    case 'k':
                        e.preventDefault();
                        this.openQuickSearch();
                        break;
                    case '/':
                        e.preventDefault();
                        this.focusMessageInput();
                        break;
                }
            }
        });
        
        // Window events
        window.addEventListener('beforeunload', () => {
            this.cleanup();
        });
    }
    
    initializeComponents() {
        // Initialize all UI components
        this.initializeNotifications();
        this.initializeSearch();
        this.initializeChat();
        this.initializeFileUpload();
    }
    
    initializeNotifications() {
        // Create notification container if it doesn't exist
        if (!document.getElementById('notification-container')) {
            const container = document.createElement('div');
            container.id = 'notification-container';
            container.className = 'notification-container';
            document.body.appendChild(container);
        }
    }
    
    showNotification(message, type = 'info', duration = 5000) {
        const container = document.getElementById('notification-container');
        const notification = document.createElement('div');
        const id = 'notification-' + Date.now();
        
        notification.id = id;
        notification.className = `notification notification-${type} fade-in`;
        notification.innerHTML = `
            <div class="notification-content">
                <i class="fas fa-${this.getNotificationIcon(type)}"></i>
                <span>${message}</span>
                <button class="notification-close" onclick="plexichat.closeNotification('${id}')">
                    <i class="fas fa-times"></i>
                </button>
            </div>
        `;
        
        container.appendChild(notification);
        
        // Auto-remove after duration
        if (duration > 0) {
            setTimeout(() => {
                this.closeNotification(id);
            }, duration);
        }
        
        return id;
    }
    
    closeNotification(id) {
        const notification = document.getElementById(id);
        if (notification) {
            notification.classList.add('fade-out');
            setTimeout(() => {
                notification.remove();
            }, 300);
        }
    }
    
    getNotificationIcon(type) {
        const icons = {
            'success': 'check-circle',
            'error': 'exclamation-circle',
            'warning': 'exclamation-triangle',
            'info': 'info-circle'
        };
        return icons[type] || 'info-circle';
    }
    
    async apiCall(endpoint, options = {}) {
        const url = `${this.apiBase}${endpoint}`;
        const defaultOptions = {
            headers: {
                'Content-Type': 'application/json',
                'X-Requested-With': 'XMLHttpRequest'
            }
        };
        
        const finalOptions = { ...defaultOptions, ...options };
        
        try {
            const response = await fetch(url, finalOptions);
            const data = await response.json();
            
            if (!response.ok) {
                throw new Error(data.message || `HTTP ${response.status}`);
            }
            
            return data;
        } catch (error) {
            this.showNotification(`API Error: ${error.message}`, 'error');
            throw error;
        }
    }
    
    getSessionId() {
        return localStorage.getItem('plexichat_session') || 
               document.cookie.split('; ')
                   .find(row => row.startsWith('plexichat_session='))
                   ?.split('=')[1];
    }
    
    redirectToLogin() {
        if (window.location.pathname !== '/auth/login') {
            window.location.href = '/auth/login';
        }
    }
    
    updateUI() {
        if (this.currentUser) {
            // Update user info in UI
            const userElements = document.querySelectorAll('[data-user-info]');
            userElements.forEach(el => {
                const info = el.dataset.userInfo;
                if (this.currentUser[info]) {
                    el.textContent = this.currentUser[info];
                }
            });
        }
    }
    
    initializeTooltips() {
        // Initialize Bootstrap tooltips
        if (typeof bootstrap !== 'undefined') {
            const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
            tooltipTriggerList.map(function (tooltipTriggerEl) {
                return new bootstrap.Tooltip(tooltipTriggerEl);
            });
        }
    }
    
    initializeModals() {
        // Initialize Bootstrap modals
        if (typeof bootstrap !== 'undefined') {
            const modalElements = document.querySelectorAll('.modal');
            modalElements.forEach(modalEl => {
                new bootstrap.Modal(modalEl);
            });
        }
    }
    
    initializeSearch() {
        const searchInput = document.getElementById('global-search');
        if (searchInput) {
            let searchTimeout;
            
            searchInput.addEventListener('input', (e) => {
                clearTimeout(searchTimeout);
                const query = e.target.value.trim();
                
                if (query.length >= 2) {
                    searchTimeout = setTimeout(() => {
                        this.performSearch(query);
                    }, 300);
                } else {
                    this.clearSearchResults();
                }
            });
        }
    }
    
    async performSearch(query) {
        try {
            const results = await this.apiCall(`/search?q=${encodeURIComponent(query)}`);
            this.displaySearchResults(results);
        } catch (error) {
            console.error('Search failed:', error);
        }
    }
    
    displaySearchResults(results) {
        const container = document.getElementById('search-results');
        if (container) {
            container.innerHTML = '';
            
            if (results.length === 0) {
                container.innerHTML = '<div class="search-no-results">No results found</div>';
            } else {
                results.forEach(result => {
                    const resultEl = document.createElement('div');
                    resultEl.className = 'search-result';
                    resultEl.innerHTML = `
                        <div class="search-result-title">${result.title}</div>
                        <div class="search-result-content">${result.content}</div>
                    `;
                    container.appendChild(resultEl);
                });
            }
            
            container.style.display = 'block';
        }
    }
    
    clearSearchResults() {
        const container = document.getElementById('search-results');
        if (container) {
            container.style.display = 'none';
        }
    }
    
    initializeChat() {
        // Initialize chat functionality
        const messageInput = document.getElementById('message-input');
        if (messageInput) {
            messageInput.addEventListener('keydown', (e) => {
                if (e.key === 'Enter' && !e.shiftKey) {
                    e.preventDefault();
                    this.sendMessage();
                }
            });
        }
    }
    
    async sendMessage() {
        const input = document.getElementById('message-input');
        if (!input) return;
        
        const content = input.value.trim();
        if (!content) return;
        
        try {
            await this.apiCall('/messages', {
                method: 'POST',
                body: JSON.stringify({
                    content: content,
                    channel_id: this.getCurrentChannelId()
                })
            });
            
            input.value = '';
            this.showNotification('Message sent', 'success', 2000);
        } catch (error) {
            this.showNotification('Failed to send message', 'error');
        }
    }
    
    getCurrentChannelId() {
        // Get current channel ID from URL or context
        const match = window.location.pathname.match(/\/channels\/(\d+)/);
        return match ? match[1] : null;
    }
    
    initializeFileUpload() {
        const uploadArea = document.getElementById('file-upload-area');
        if (uploadArea) {
            uploadArea.addEventListener('dragover', (e) => {
                e.preventDefault();
                uploadArea.classList.add('drag-over');
            });
            
            uploadArea.addEventListener('dragleave', () => {
                uploadArea.classList.remove('drag-over');
            });
            
            uploadArea.addEventListener('drop', (e) => {
                e.preventDefault();
                uploadArea.classList.remove('drag-over');
                this.handleFileUpload(e.dataTransfer.files);
            });
        }
    }
    
    async handleFileUpload(files) {
        for (const file of files) {
            if (this.validateFile(file)) {
                await this.uploadFile(file);
            }
        }
    }
    
    validateFile(file) {
        const maxSize = 25 * 1024 * 1024; // 25MB
        const allowedTypes = ['image/jpeg', 'image/png', 'image/gif', 'application/pdf', 'text/plain'];
        
        if (file.size > maxSize) {
            this.showNotification('File too large (max 25MB)', 'error');
            return false;
        }
        
        if (!allowedTypes.includes(file.type)) {
            this.showNotification('File type not allowed', 'error');
            return false;
        }
        
        return true;
    }
    
    async uploadFile(file) {
        const formData = new FormData();
        formData.append('file', file);
        formData.append('channel_id', this.getCurrentChannelId());
        
        try {
            const response = await fetch(`${this.apiBase}/files/upload`, {
                method: 'POST',
                body: formData
            });
            
            if (response.ok) {
                this.showNotification('File uploaded successfully', 'success');
            } else {
                throw new Error('Upload failed');
            }
        } catch (error) {
            this.showNotification('File upload failed', 'error');
        }
    }
    
    startHeartbeat() {
        // Send periodic heartbeat to maintain session
        setInterval(() => {
            if (this.currentUser) {
                this.apiCall('/heartbeat', { method: 'POST' }).catch(() => {
                    // Heartbeat failed, user might be logged out
                    this.checkAuth();
                });
            }
        }, 30000); // Every 30 seconds
    }
    
    openQuickSearch() {
        const searchInput = document.getElementById('global-search');
        if (searchInput) {
            searchInput.focus();
            searchInput.select();
        }
    }
    
    focusMessageInput() {
        const messageInput = document.getElementById('message-input');
        if (messageInput) {
            messageInput.focus();
        }
    }
    
    cleanup() {
        // Cleanup when page is unloading
        if (this.socket) {
            this.socket.close();
        }
    }
}

// Initialize the application
const plexichat = new PlexiChatApp();

// Export for global access
window.plexichat = plexichat;
