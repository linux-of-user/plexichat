/**
 * Enhanced Dashboard JavaScript
 * Provides advanced functionality for the PlexiChat dashboard
 */

class EnhancedDashboard {
    constructor() {
        this.wsConnection = null;
        this.refreshInterval = null;
        this.securityMonitor = null;
        this.lastActivity = Date.now();
        this.sessionTimeout = 30 * 60 * 1000; // 30 minutes
        this.autoRefreshEnabled = true;
        this.notifications = [];
        
        this.init();
    }

    init() {
        this.setupEventListeners();
        this.initializeWebSocket();
        this.startActivityMonitoring();
        this.startAutoRefresh();
        this.loadUserPreferences();
        this.initializeSecurityMonitoring();
    }

    setupEventListeners() {
        // Activity tracking
        document.addEventListener('click', () => this.updateActivity());
        document.addEventListener('keypress', () => this.updateActivity());
        document.addEventListener('mousemove', () => this.updateActivity());
        
        // Keyboard shortcuts
        document.addEventListener('keydown', (e) => this.handleKeyboardShortcuts(e));
        
        // Window events
        window.addEventListener('beforeunload', () => this.cleanup());
        window.addEventListener('focus', () => this.onWindowFocus());
        window.addEventListener('blur', () => this.onWindowBlur());
        
        // Network status
        window.addEventListener('online', () => this.onNetworkOnline());
        window.addEventListener('offline', () => this.onNetworkOffline());
    }

    initializeWebSocket() {
        const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        const wsUrl = `${protocol}//${window.location.host}/ws/dashboard`;
        
        try {
            this.wsConnection = new WebSocket(wsUrl);
            
            this.wsConnection.onopen = () => {
                console.log('WebSocket connected');
                this.updateConnectionStatus('connected');
            };
            
            this.wsConnection.onmessage = (event) => {
                this.handleWebSocketMessage(JSON.parse(event.data));
            };
            
            this.wsConnection.onclose = () => {
                console.log('WebSocket disconnected');
                this.updateConnectionStatus('disconnected');
                this.scheduleReconnect();
            };
            
            this.wsConnection.onerror = (error) => {
                console.error('WebSocket error:', error);
                this.updateConnectionStatus('error');
            };
        } catch (error) {
            console.error('Failed to initialize WebSocket:', error);
        }
    }

    handleWebSocketMessage(data) {
        switch (data.type) {
            case 'stats_update':
                this.updateStatistics(data.payload);
                break;
            case 'security_alert':
                this.handleSecurityAlert(data.payload);
                break;
            case 'system_notification':
                this.showNotification(data.payload.message, data.payload.type);
                break;
            case 'activity_update':
                this.updateActivityFeed(data.payload);
                break;
            default:
                console.log('Unknown message type:', data.type);
        }
    }

    updateStatistics(stats) {
        // Update stat cards with animation
        Object.keys(stats).forEach(key => {
            const element = document.getElementById(key);
            if (element) {
                this.animateNumberChange(element, stats[key]);
            }
        });
    }

    animateNumberChange(element, newValue) {
        const currentValue = parseInt(element.textContent) || 0;
        const difference = newValue - currentValue;
        const steps = 20;
        const stepValue = difference / steps;
        let currentStep = 0;

        const animation = setInterval(() => {
            currentStep++;
            const value = Math.round(currentValue + (stepValue * currentStep));
            element.textContent = value;
            
            if (currentStep >= steps) {
                clearInterval(animation);
                element.textContent = newValue;
            }
        }, 50);
    }

    handleSecurityAlert(alert) {
        const severity = alert.severity || 'warning';
        const message = alert.message || 'Security alert detected';
        
        this.showNotification(message, severity);
        this.updateSecurityIndicator(severity);
        
        // Log security event
        console.warn('Security Alert:', alert);
        
        // Add to security log if severe
        if (severity === 'critical' || severity === 'high') {
            this.addToSecurityLog(alert);
        }
    }

    updateSecurityIndicator(level) {
        const indicator = document.getElementById('securityIndicator');
        if (!indicator) return;
        
        indicator.className = 'security-indicator';
        
        switch (level) {
            case 'critical':
            case 'high':
                indicator.classList.add('danger');
                indicator.innerHTML = '<i class="fas fa-exclamation-triangle"></i> Security Alert';
                break;
            case 'medium':
            case 'warning':
                indicator.classList.add('warning');
                indicator.innerHTML = '<i class="fas fa-shield-alt"></i> Security Warning';
                break;
            default:
                indicator.innerHTML = '<i class="fas fa-shield-alt"></i> Secure Connection';
        }
    }

    updateActivityFeed(activities) {
        const activityList = document.getElementById('activityList');
        if (!activityList) return;
        
        const activityHTML = activities.map(activity => `
            <div class="activity-item" style="animation: slideInRight 0.5s ease-out;">
                <div class="activity-icon bg-${activity.type}">
                    <i class="${activity.icon}"></i>
                </div>
                <div class="flex-grow-1">
                    <div class="fw-bold">${this.escapeHtml(activity.message)}</div>
                    <small class="text-muted">${this.formatTime(activity.timestamp)}</small>
                </div>
            </div>
        `).join('');
        
        activityList.innerHTML = activityHTML;
    }

    startActivityMonitoring() {
        this.securityMonitor = setInterval(() => {
            const timeSinceActivity = Date.now() - this.lastActivity;
            
            // Session timeout warning
            if (timeSinceActivity > this.sessionTimeout - 5 * 60 * 1000) { // 5 minutes before timeout
                this.showSessionWarning();
            }
            
            // Auto-logout on timeout
            if (timeSinceActivity > this.sessionTimeout) {
                this.handleSessionTimeout();
            }
        }, 60000); // Check every minute
    }

    startAutoRefresh() {
        if (!this.autoRefreshEnabled) return;
        
        this.refreshInterval = setInterval(() => {
            this.refreshDashboardData();
        }, 30000); // Refresh every 30 seconds
    }

    refreshDashboardData() {
        if (!navigator.onLine) return;
        
        fetch('/api/dashboard/stats', {
            method: 'GET',
            headers: {
                'X-Requested-With': 'XMLHttpRequest',
                'X-CSRFToken': this.getCSRFToken()
            }
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                this.updateStatistics(data.stats);
            }
        })
        .catch(error => {
            console.error('Failed to refresh dashboard data:', error);
        });
    }

    showNotification(message, type = 'info', duration = 5000) {
        const notification = {
            id: Date.now(),
            message: this.escapeHtml(message),
            type: type,
            timestamp: new Date()
        };
        
        this.notifications.push(notification);
        this.displayNotification(notification);
        
        // Auto-remove after duration
        setTimeout(() => {
            this.removeNotification(notification.id);
        }, duration);
    }

    displayNotification(notification) {
        const toast = document.getElementById('notificationToast');
        const messageEl = document.getElementById('toastMessage');
        
        if (!toast || !messageEl) return;
        
        messageEl.textContent = notification.message;
        toast.className = `notification-toast show border-${notification.type}`;
        
        // Update icon based on type
        const icon = toast.querySelector('i');
        if (icon) {
            icon.className = this.getNotificationIcon(notification.type);
        }
    }

    getNotificationIcon(type) {
        const icons = {
            success: 'fas fa-check-circle text-success',
            error: 'fas fa-exclamation-circle text-danger',
            warning: 'fas fa-exclamation-triangle text-warning',
            info: 'fas fa-info-circle text-info'
        };
        return icons[type] || icons.info;
    }

    removeNotification(id) {
        this.notifications = this.notifications.filter(n => n.id !== id);
        
        if (this.notifications.length === 0) {
            const toast = document.getElementById('notificationToast');
            if (toast) {
                toast.classList.remove('show');
            }
        }
    }

    handleKeyboardShortcuts(event) {
        // Ctrl/Cmd + shortcuts
        if (event.ctrlKey || event.metaKey) {
            switch (event.key) {
                case 'r':
                    event.preventDefault();
                    this.refreshDashboardData();
                    this.showNotification('Dashboard refreshed', 'success');
                    break;
                case 'd':
                    event.preventDefault();
                    this.toggleDarkMode();
                    break;
                case 'l':
                    event.preventDefault();
                    this.confirmLogout();
                    break;
            }
        }
        
        // Function keys
        switch (event.key) {
            case 'F5':
                event.preventDefault();
                this.refreshDashboardData();
                break;
            case 'Escape':
                this.hideAllModals();
                break;
        }
    }

    updateActivity() {
        this.lastActivity = Date.now();
    }

    onWindowFocus() {
        this.refreshDashboardData();
        this.updateActivity();
    }

    onWindowBlur() {
        // Pause auto-refresh when window is not focused
        if (this.refreshInterval) {
            clearInterval(this.refreshInterval);
            this.refreshInterval = null;
        }
    }

    onNetworkOnline() {
        this.showNotification('Connection restored', 'success');
        this.initializeWebSocket();
        this.startAutoRefresh();
    }

    onNetworkOffline() {
        this.showNotification('Connection lost - working offline', 'warning');
        this.updateConnectionStatus('offline');
    }

    updateConnectionStatus(status) {
        const indicator = document.getElementById('securityIndicator');
        if (!indicator) return;
        
        switch (status) {
            case 'connected':
                indicator.style.backgroundColor = '#27ae60';
                break;
            case 'disconnected':
                indicator.style.backgroundColor = '#f39c12';
                break;
            case 'offline':
            case 'error':
                indicator.style.backgroundColor = '#e74c3c';
                break;
        }
    }

    scheduleReconnect() {
        setTimeout(() => {
            if (!this.wsConnection || this.wsConnection.readyState === WebSocket.CLOSED) {
                this.initializeWebSocket();
            }
        }, 5000);
    }

    showSessionWarning() {
        this.showNotification(
            'Your session will expire in 5 minutes. Click anywhere to extend.',
            'warning',
            10000
        );
    }

    handleSessionTimeout() {
        this.showNotification('Session expired. Redirecting to login...', 'error');
        setTimeout(() => {
            window.location.href = '/login?expired=1';
        }, 3000);
    }

    confirmLogout() {
        if (confirm('Are you sure you want to logout?')) {
            this.logout();
        }
    }

    logout() {
        this.cleanup();
        window.location.href = '/logout';
    }

    cleanup() {
        if (this.wsConnection) {
            this.wsConnection.close();
        }
        if (this.refreshInterval) {
            clearInterval(this.refreshInterval);
        }
        if (this.securityMonitor) {
            clearInterval(this.securityMonitor);
        }
    }

    toggleDarkMode() {
        document.body.classList.toggle('dark-mode');
        const isDark = document.body.classList.contains('dark-mode');
        localStorage.setItem('darkMode', isDark);
        this.showNotification(`${isDark ? 'Dark' : 'Light'} mode enabled`, 'info');
    }

    loadUserPreferences() {
        // Load dark mode preference
        if (localStorage.getItem('darkMode') === 'true') {
            document.body.classList.add('dark-mode');
        }
        
        // Load other preferences
        const autoRefresh = localStorage.getItem('autoRefresh');
        if (autoRefresh !== null) {
            this.autoRefreshEnabled = autoRefresh === 'true';
        }
    }

    hideAllModals() {
        const modals = document.querySelectorAll('.modal.show');
        modals.forEach(modal => {
            const bsModal = bootstrap.Modal.getInstance(modal);
            if (bsModal) {
                bsModal.hide();
            }
        });
    }

    escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    formatTime(timestamp) {
        const date = new Date(timestamp);
        const now = new Date();
        const diff = now - date;
        
        if (diff < 60000) return 'Just now';
        if (diff < 3600000) return `${Math.floor(diff / 60000)} minutes ago`;
        if (diff < 86400000) return `${Math.floor(diff / 3600000)} hours ago`;
        return date.toLocaleDateString();
    }

    getCSRFToken() {
        const meta = document.querySelector('meta[name="csrf-token"]');
        return meta ? meta.getAttribute('content') : '';
    }

    addToSecurityLog(alert) {
        // Add security event to local log
        const securityLog = JSON.parse(localStorage.getItem('securityLog') || '[]');
        securityLog.push({
            ...alert,
            timestamp: new Date().toISOString(),
            userAgent: navigator.userAgent,
            url: window.location.href
        });
        
        // Keep only last 100 entries
        if (securityLog.length > 100) {
            securityLog.splice(0, securityLog.length - 100);
        }
        
        localStorage.setItem('securityLog', JSON.stringify(securityLog));
    }
}

// Initialize dashboard when DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
    window.enhancedDashboard = new EnhancedDashboard();
});

// Global functions for template compatibility
function showNotification(message, type) {
    if (window.enhancedDashboard) {
        window.enhancedDashboard.showNotification(message, type);
    }
}

function hideNotification() {
    if (window.enhancedDashboard) {
        window.enhancedDashboard.removeNotification();
    }
}

function toggleDarkMode() {
    if (window.enhancedDashboard) {
        window.enhancedDashboard.toggleDarkMode();
    }
}

function logout() {
    if (window.enhancedDashboard) {
        window.enhancedDashboard.confirmLogout();
    }
}
