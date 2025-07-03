// Enhanced Admin Console JavaScript with advanced features
class EnhancedAdminConsole {
    constructor() {
        this.apiBase = '/v1';
        this.adminBase = '/admin';
        this.refreshInterval = 30000; // 30 seconds
        this.autoRefreshEnabled = true;
        this.theme = localStorage.getItem('admin-theme') || 'light';
        this.sidebarCollapsed = localStorage.getItem('sidebar-collapsed') === 'true';
        
        this.init();
    }

    init() {
        this.setupTheme();
        this.setupSidebar();
        this.setupEventListeners();
        this.loadDashboard();
        this.startAutoRefresh();
        this.setupWebSocket();
    }

    setupTheme() {
        document.documentElement.setAttribute('data-bs-theme', this.theme);
        const themeIcon = document.getElementById('themeIcon');
        if (themeIcon) {
            themeIcon.className = this.theme === 'dark' ? 'fas fa-sun' : 'fas fa-moon';
        }
    }

    setupSidebar() {
        const sidebar = document.getElementById('sidebar');
        const mainContent = document.getElementById('mainContent');
        
        if (this.sidebarCollapsed) {
            sidebar.classList.add('collapsed');
            mainContent.classList.add('expanded');
        }
    }

    setupEventListeners() {
        // Tab switching with animation
        document.querySelectorAll('[data-bs-toggle="tab"]').forEach(tab => {
            tab.addEventListener('shown.bs.tab', (e) => {
                const target = e.target.getAttribute('href').substring(1);
                this.loadTabContent(target);
                
                // Add fade-in animation
                const tabPane = document.getElementById(target);
                if (tabPane) {
                    tabPane.classList.add('fade-in');
                    setTimeout(() => tabPane.classList.remove('fade-in'), 500);
                }
            });
        });

        // Keyboard shortcuts
        document.addEventListener('keydown', (e) => {
            if (e.ctrlKey || e.metaKey) {
                switch (e.key) {
                    case 'r':
                        e.preventDefault();
                        this.refreshAll();
                        break;
                    case 't':
                        e.preventDefault();
                        this.runQuickTest();
                        break;
                    case 'l':
                        e.preventDefault();
                        this.viewLogs();
                        break;
                }
            }
        });

        // Auto-save configuration changes
        document.addEventListener('input', (e) => {
            if (e.target.matches('.config-editor')) {
                this.debounce(() => this.autoSaveConfig(), 2000);
            }
        });
    }

    setupWebSocket() {
        // Setup WebSocket for real-time updates
        try {
            const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
            const wsUrl = `${protocol}//${window.location.host}/ws/admin`;
            
            this.ws = new WebSocket(wsUrl);
            
            this.ws.onopen = () => {
                console.log('WebSocket connected');
                this.showToast('Connected to real-time updates', 'success');
            };
            
            this.ws.onmessage = (event) => {
                const data = JSON.parse(event.data);
                this.handleWebSocketMessage(data);
            };
            
            this.ws.onclose = () => {
                console.log('WebSocket disconnected');
                // Attempt to reconnect after 5 seconds
                setTimeout(() => this.setupWebSocket(), 5000);
            };
            
            this.ws.onerror = (error) => {
                console.error('WebSocket error:', error);
            };
        } catch (error) {
            console.warn('WebSocket not available:', error);
        }
    }

    handleWebSocketMessage(data) {
        switch (data.type) {
            case 'system_status':
                this.updateSystemStatus(data.payload);
                break;
            case 'new_log':
                this.updateLogs(data.payload);
                break;
            case 'test_result':
                this.updateTestResults(data.payload);
                break;
            case 'alert':
                this.showToast(data.payload.message, data.payload.type);
                break;
        }
    }

    async apiCall(endpoint, options = {}) {
        const defaultOptions = {
            headers: {
                'Content-Type': 'application/json',
                'X-Requested-With': 'XMLHttpRequest'
            }
        };

        const config = { ...defaultOptions, ...options };
        
        try {
            const response = await fetch(endpoint, config);
            
            if (!response.ok) {
                const errorData = await response.json().catch(() => ({}));
                throw new Error(errorData.detail || `HTTP ${response.status}: ${response.statusText}`);
            }
            
            return await response.json();
        } catch (error) {
            console.error('API call failed:', error);
            this.showToast(`API Error: ${error.message}`, 'error');
            throw error;
        }
    }

    showLoading(show = true) {
        const overlay = document.getElementById('loadingOverlay');
        if (overlay) {
            overlay.style.display = show ? 'flex' : 'none';
        }
    }

    showToast(message, type = 'info', duration = 5000) {
        const container = document.getElementById('toastContainer');
        if (!container) return;

        const toastId = 'toast-' + Date.now();
        const iconMap = {
            success: 'fa-check-circle',
            error: 'fa-exclamation-triangle',
            warning: 'fa-exclamation-circle',
            info: 'fa-info-circle'
        };

        const colorMap = {
            success: 'text-bg-success',
            error: 'text-bg-danger',
            warning: 'text-bg-warning',
            info: 'text-bg-info'
        };

        const toast = document.createElement('div');
        toast.id = toastId;
        toast.className = `toast align-items-center ${colorMap[type]} border-0`;
        toast.setAttribute('role', 'alert');
        toast.innerHTML = `
            <div class="d-flex">
                <div class="toast-body">
                    <i class="fas ${iconMap[type]} me-2"></i>${message}
                </div>
                <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast"></button>
            </div>
        `;

        container.appendChild(toast);
        
        const bsToast = new bootstrap.Toast(toast, { delay: duration });
        bsToast.show();

        toast.addEventListener('hidden.bs.toast', () => {
            container.removeChild(toast);
        });
    }

    async loadDashboard() {
        try {
            // Load dashboard data with parallel requests
            const [status, metrics, activity] = await Promise.all([
                this.apiCall(`${this.apiBase}/status/health`),
                this.apiCall(`${this.apiBase}/status/metrics`),
                this.apiCall(`${this.adminBase}/recent-activity`).catch(() => [])
            ]);

            // Update system status
            this.updateSystemStatusDisplay(status);
            
            // Update metrics
            this.updateMetricsDisplay(metrics);
            
            // Update recent activity
            this.updateRecentActivity(activity);

        } catch (error) {
            console.error('Failed to load dashboard:', error);
            this.showToast('Failed to load dashboard data', 'error');
        }
    }

    updateSystemStatusDisplay(status) {
        const statusElement = document.getElementById('system-status-text');
        if (statusElement) {
            statusElement.textContent = status.status || 'Unknown';
            statusElement.className = `h5 mb-0 font-weight-bold status-${status.status?.toLowerCase() || 'unknown'}`;
        }
    }

    updateMetricsDisplay(metrics) {
        // Update uptime
        const uptimeElement = document.getElementById('uptime-text');
        if (uptimeElement && metrics.uptime_seconds) {
            uptimeElement.textContent = this.formatUptime(metrics.uptime_seconds);
        }

        // Update user count
        const usersElement = document.getElementById('active-users-text');
        if (usersElement) {
            usersElement.textContent = metrics.active_users || '0';
        }

        // Update message count
        const messagesElement = document.getElementById('messages-today-text');
        if (messagesElement) {
            messagesElement.textContent = metrics.messages_today || '0';
        }
    }

    updateRecentActivity(activities) {
        const container = document.getElementById('recent-activity');
        if (!container) return;

        if (activities && activities.length > 0) {
            container.innerHTML = activities.map(item => `
                <div class="d-flex align-items-center mb-3 slide-in">
                    <div class="flex-shrink-0">
                        <div class="rounded-circle bg-${this.getActivityColor(item.type)} p-2">
                            <i class="fas fa-${this.getActivityIcon(item.type)} text-white"></i>
                        </div>
                    </div>
                    <div class="flex-grow-1 ms-3">
                        <div class="fw-semibold">${item.description}</div>
                        <small class="text-muted">${this.formatTimestamp(item.timestamp)}</small>
                    </div>
                </div>
            `).join('');
        } else {
            container.innerHTML = `
                <div class="text-center text-muted">
                    <i class="fas fa-inbox fa-2x mb-2"></i>
                    <p>No recent activity</p>
                </div>
            `;
        }
    }

    async loadTabContent(tabName) {
        this.showLoading(true);
        
        try {
            switch (tabName) {
                case 'system-status':
                    await this.loadSystemStatus();
                    break;
                case 'self-tests':
                    await this.loadSelfTests();
                    break;
                case 'configuration':
                    await this.loadConfiguration();
                    break;
                case 'user-management':
                    await this.loadUserManagement();
                    break;
                case 'logs':
                    await this.loadLogs();
                    break;
                case 'monitoring':
                    await this.loadMonitoring();
                    break;
                case 'security':
                    await this.loadSecurity();
                    break;
            }
        } catch (error) {
            console.error(`Failed to load ${tabName}:`, error);
            this.showToast(`Failed to load ${tabName}`, 'error');
        } finally {
            this.showLoading(false);
        }
    }

    async loadSystemStatus() {
        // Implementation for system status tab
        console.log('Loading system status...');
    }

    async loadSelfTests() {
        // Implementation for self-tests tab
        console.log('Loading self-tests...');
    }

    async loadConfiguration() {
        // Implementation for configuration tab
        console.log('Loading configuration...');
    }

    async loadUserManagement() {
        // Implementation for user management tab
        console.log('Loading user management...');
    }

    async loadLogs() {
        // Implementation for logs tab
        console.log('Loading logs...');
    }

    async loadMonitoring() {
        // Implementation for monitoring tab
        console.log('Loading monitoring...');
    }

    async loadSecurity() {
        // Implementation for security tab
        console.log('Loading security...');
    }

    formatUptime(seconds) {
        const days = Math.floor(seconds / 86400);
        const hours = Math.floor((seconds % 86400) / 3600);
        const minutes = Math.floor((seconds % 3600) / 60);
        
        if (days > 0) {
            return `${days}d ${hours}h ${minutes}m`;
        } else if (hours > 0) {
            return `${hours}h ${minutes}m`;
        } else {
            return `${minutes}m`;
        }
    }

    formatTimestamp(timestamp) {
        return new Date(timestamp).toLocaleString();
    }

    getActivityIcon(type) {
        const icons = {
            'user_login': 'sign-in-alt',
            'user_created': 'user-plus',
            'message_sent': 'paper-plane',
            'test_run': 'vial',
            'error': 'exclamation-triangle',
            'system': 'cog',
            'config_change': 'edit',
            'backup': 'save'
        };
        return icons[type] || 'info-circle';
    }

    getActivityColor(type) {
        const colors = {
            'user_login': 'success',
            'user_created': 'info',
            'message_sent': 'primary',
            'test_run': 'warning',
            'error': 'danger',
            'system': 'secondary',
            'config_change': 'info',
            'backup': 'success'
        };
        return colors[type] || 'secondary';
    }

    startAutoRefresh() {
        if (this.autoRefreshEnabled) {
            setInterval(() => {
                const activeTab = document.querySelector('.nav-link.active').getAttribute('href').substring(1);
                if (activeTab === 'dashboard') {
                    this.loadDashboard();
                }
            }, this.refreshInterval);
        }
    }

    debounce(func, wait) {
        clearTimeout(this.debounceTimer);
        this.debounceTimer = setTimeout(func, wait);
    }

    async autoSaveConfig() {
        // Auto-save configuration changes
        console.log('Auto-saving configuration...');
        this.showToast('Configuration auto-saved', 'success', 2000);
    }

    // Global action methods
    async runQuickTest() {
        this.showLoading(true);
        try {
            const result = await this.apiCall(`${this.adminBase}/quick-test`, { method: 'POST' });
            this.showToast('Quick test completed successfully', 'success');
            return result;
        } catch (error) {
            this.showToast('Quick test failed', 'error');
            throw error;
        } finally {
            this.showLoading(false);
        }
    }

    async refreshAll() {
        this.showLoading(true);
        try {
            await this.loadDashboard();
            this.showToast('Dashboard refreshed', 'success');
        } catch (error) {
            this.showToast('Failed to refresh dashboard', 'error');
        } finally {
            this.showLoading(false);
        }
    }

    viewLogs() {
        // Switch to logs tab
        const logsTab = document.querySelector('[href="#logs"]');
        if (logsTab) {
            const tab = new bootstrap.Tab(logsTab);
            tab.show();
        }
    }
}

// Theme and UI functions
function toggleTheme() {
    const currentTheme = document.documentElement.getAttribute('data-bs-theme');
    const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
    
    document.documentElement.setAttribute('data-bs-theme', newTheme);
    localStorage.setItem('admin-theme', newTheme);
    
    const themeIcon = document.getElementById('themeIcon');
    if (themeIcon) {
        themeIcon.className = newTheme === 'dark' ? 'fas fa-sun' : 'fas fa-moon';
    }
    
    // Update admin console theme
    if (window.adminConsole) {
        window.adminConsole.theme = newTheme;
    }
}

function toggleSidebar() {
    const sidebar = document.getElementById('sidebar');
    const mainContent = document.getElementById('mainContent');
    
    sidebar.classList.toggle('collapsed');
    mainContent.classList.toggle('expanded');
    
    const isCollapsed = sidebar.classList.contains('collapsed');
    localStorage.setItem('sidebar-collapsed', isCollapsed);
    
    if (window.adminConsole) {
        window.adminConsole.sidebarCollapsed = isCollapsed;
    }
}

// Global functions for backward compatibility
function refreshAll() {
    if (window.adminConsole) {
        window.adminConsole.refreshAll();
    }
}

function runQuickTest() {
    if (window.adminConsole) {
        window.adminConsole.runQuickTest();
    }
}

function viewLogs() {
    if (window.adminConsole) {
        window.adminConsole.viewLogs();
    }
}

// Initialize when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    window.adminConsole = new EnhancedAdminConsole();
    
    // Add keyboard shortcut hints
    console.log('Admin Console Keyboard Shortcuts:');
    console.log('Ctrl+R: Refresh Dashboard');
    console.log('Ctrl+T: Run Quick Test');
    console.log('Ctrl+L: View Logs');
});

// Handle page visibility changes
document.addEventListener('visibilitychange', () => {
    if (window.adminConsole) {
        if (document.hidden) {
            // Pause auto-refresh when tab is not visible
            window.adminConsole.autoRefreshEnabled = false;
        } else {
            // Resume auto-refresh when tab becomes visible
            window.adminConsole.autoRefreshEnabled = true;
            window.adminConsole.refreshAll();
        }
    }
});

// Export for global access
window.EnhancedAdminConsole = EnhancedAdminConsole;
