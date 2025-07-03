// Admin Console JavaScript
class AdminConsole {
    constructor() {
        this.apiBase = '/v1';
        this.adminBase = '/admin';
        this.refreshInterval = 30000; // 30 seconds
        this.autoRefreshEnabled = true;
        this.init();
    }

    init() {
        this.setupEventListeners();
        this.loadDashboard();
        this.startAutoRefresh();
    }

    setupEventListeners() {
        // Tab switching
        document.querySelectorAll('[data-bs-toggle="tab"]').forEach(tab => {
            tab.addEventListener('shown.bs.tab', (e) => {
                const target = e.target.getAttribute('href').substring(1);
                this.loadTabContent(target);
            });
        });

        // Configuration category switching
        document.addEventListener('click', (e) => {
            if (e.target.matches('[data-category]')) {
                e.preventDefault();
                this.loadConfigCategory(e.target.dataset.category);
                
                // Update active state
                document.querySelectorAll('[data-category]').forEach(el => el.classList.remove('active'));
                e.target.classList.add('active');
            }
        });
    }

    async apiCall(endpoint, options = {}) {
        const defaultOptions = {
            headers: {
                'Content-Type': 'application/json',
            }
        };

        const config = { ...defaultOptions, ...options };
        
        try {
            const response = await fetch(endpoint, config);
            
            if (!response.ok) {
                throw new Error(`HTTP ${response.status}: ${response.statusText}`);
            }
            
            return await response.json();
        } catch (error) {
            console.error('API call failed:', error);
            this.showError(`API Error: ${error.message}`);
            throw error;
        }
    }

    showLoading(show = true) {
        const modal = new bootstrap.Modal(document.getElementById('loadingModal'));
        if (show) {
            modal.show();
        } else {
            modal.hide();
        }
    }

    showError(message) {
        // Create toast notification
        const toast = document.createElement('div');
        toast.className = 'toast align-items-center text-white bg-danger border-0 position-fixed top-0 end-0 m-3';
        toast.style.zIndex = '9999';
        toast.innerHTML = `
            <div class="d-flex">
                <div class="toast-body">
                    <i class="fas fa-exclamation-triangle me-2"></i>${message}
                </div>
                <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast"></button>
            </div>
        `;
        
        document.body.appendChild(toast);
        const bsToast = new bootstrap.Toast(toast);
        bsToast.show();
        
        // Remove after hiding
        toast.addEventListener('hidden.bs.toast', () => {
            document.body.removeChild(toast);
        });
    }

    showSuccess(message) {
        const toast = document.createElement('div');
        toast.className = 'toast align-items-center text-white bg-success border-0 position-fixed top-0 end-0 m-3';
        toast.style.zIndex = '9999';
        toast.innerHTML = `
            <div class="d-flex">
                <div class="toast-body">
                    <i class="fas fa-check-circle me-2"></i>${message}
                </div>
                <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast"></button>
            </div>
        `;
        
        document.body.appendChild(toast);
        const bsToast = new bootstrap.Toast(toast);
        bsToast.show();
        
        toast.addEventListener('hidden.bs.toast', () => {
            document.body.removeChild(toast);
        });
    }

    async loadDashboard() {
        try {
            // Load system status
            const status = await this.apiCall(`${this.apiBase}/status/health`);
            document.getElementById('system-status-text').textContent = status.status || 'Unknown';
            document.getElementById('system-status-text').className = `h5 mb-0 font-weight-bold status-${status.status?.toLowerCase() || 'unknown'}`;

            // Load uptime
            const uptime = await this.apiCall(`${this.apiBase}/status/uptime`);
            document.getElementById('uptime-text').textContent = this.formatUptime(uptime.uptime_seconds);

            // Load metrics
            const metrics = await this.apiCall(`${this.apiBase}/status/metrics`);
            document.getElementById('active-users-text').textContent = metrics.active_users || '0';
            document.getElementById('messages-today-text').textContent = metrics.messages_today || '0';

            // Load recent activity
            await this.loadRecentActivity();

        } catch (error) {
            console.error('Failed to load dashboard:', error);
        }
    }

    async loadRecentActivity() {
        try {
            const activity = await this.apiCall(`${this.adminBase}/recent-activity`);
            const container = document.getElementById('recent-activity');
            
            if (activity && activity.length > 0) {
                container.innerHTML = activity.map(item => `
                    <div class="d-flex align-items-center mb-2">
                        <div class="flex-shrink-0">
                            <i class="fas fa-${this.getActivityIcon(item.type)} text-${this.getActivityColor(item.type)}"></i>
                        </div>
                        <div class="flex-grow-1 ms-3">
                            <div class="fw-bold">${item.description}</div>
                            <small class="text-muted">${this.formatTimestamp(item.timestamp)}</small>
                        </div>
                    </div>
                `).join('');
            } else {
                container.innerHTML = '<p class="text-muted">No recent activity</p>';
            }
        } catch (error) {
            document.getElementById('recent-activity').innerHTML = '<p class="text-danger">Failed to load recent activity</p>';
        }
    }

    async loadTabContent(tabName) {
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
            case 'api-docs':
                await this.loadApiDocs();
                break;
            case 'monitoring':
                await this.loadMonitoring();
                break;
        }
    }

    async loadSystemStatus() {
        try {
            const health = await this.apiCall(`${this.apiBase}/status/health`);
            const metrics = await this.apiCall(`${this.apiBase}/status/metrics`);
            
            document.getElementById('system-health-content').innerHTML = this.renderSystemHealth(health, metrics);
            document.getElementById('resource-usage').innerHTML = this.renderResourceUsage(metrics);
            document.getElementById('service-status').innerHTML = this.renderServiceStatus(health);
        } catch (error) {
            document.getElementById('system-health-content').innerHTML = '<p class="text-danger">Failed to load system status</p>';
        }
    }

    async loadSelfTests() {
        try {
            const results = await this.apiCall(`${this.apiBase}/status/selftest`);
            document.getElementById('test-results-container').innerHTML = this.renderTestResults(results);
        } catch (error) {
            document.getElementById('test-results-container').innerHTML = '<p class="text-danger">Failed to load test results</p>';
        }
    }

    async loadConfiguration() {
        try {
            const config = await this.apiCall(`${this.adminBase}/configuration`);
            this.currentConfig = config;
            this.loadConfigCategory('core');
        } catch (error) {
            document.getElementById('config-editor-container').innerHTML = '<p class="text-danger">Failed to load configuration</p>';
        }
    }

    loadConfigCategory(category) {
        if (!this.currentConfig) return;
        
        const categoryConfig = this.currentConfig[category] || {};
        const container = document.getElementById('config-editor-container');
        
        container.innerHTML = `
            <h6 class="mb-3">${this.getCategoryTitle(category)} Configuration</h6>
            <form id="config-form-${category}">
                ${Object.entries(categoryConfig).map(([key, value]) => `
                    <div class="mb-3">
                        <label for="${key}" class="form-label">${this.formatConfigKey(key)}</label>
                        <input type="${this.getInputType(value)}" class="form-control config-editor" 
                               id="${key}" name="${key}" value="${value || ''}"
                               data-category="${category}">
                        <div class="form-text">${this.getConfigDescription(key)}</div>
                    </div>
                `).join('')}
            </form>
        `;
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
            'system': 'cog'
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
            'system': 'secondary'
        };
        return colors[type] || 'secondary';
    }

    renderSystemHealth(health, metrics) {
        return `
            <div class="row">
                <div class="col-md-6">
                    <h6>Overall Status</h6>
                    <div class="alert alert-${health.status === 'healthy' ? 'success' : 'warning'}">
                        <i class="fas fa-${health.status === 'healthy' ? 'check-circle' : 'exclamation-triangle'}"></i>
                        System is ${health.status}
                    </div>
                </div>
                <div class="col-md-6">
                    <h6>Last Check</h6>
                    <p>${this.formatTimestamp(health.timestamp)}</p>
                </div>
            </div>
            ${health.alerts && health.alerts.length > 0 ? `
                <div class="mt-3">
                    <h6>Active Alerts</h6>
                    ${health.alerts.map(alert => `
                        <div class="alert alert-warning">
                            <i class="fas fa-exclamation-triangle"></i> ${alert}
                        </div>
                    `).join('')}
                </div>
            ` : ''}
        `;
    }

    renderResourceUsage(metrics) {
        return `
            <div class="mb-3">
                <label class="form-label">CPU Usage</label>
                <div class="progress">
                    <div class="progress-bar" style="width: ${metrics.cpu?.percent || 0}%">
                        ${metrics.cpu?.percent || 0}%
                    </div>
                </div>
            </div>
            <div class="mb-3">
                <label class="form-label">Memory Usage</label>
                <div class="progress">
                    <div class="progress-bar bg-info" style="width: ${metrics.memory?.percent_used || 0}%">
                        ${metrics.memory?.percent_used || 0}%
                    </div>
                </div>
            </div>
            <div class="mb-3">
                <label class="form-label">Disk Usage</label>
                <div class="progress">
                    <div class="progress-bar bg-warning" style="width: ${metrics.disk?.percent_used || 0}%">
                        ${metrics.disk?.percent_used || 0}%
                    </div>
                </div>
            </div>
        `;
    }

    renderServiceStatus(health) {
        const services = [
            { name: 'Web Server', status: 'running' },
            { name: 'Database', status: health.database ? 'running' : 'error' },
            { name: 'Self-Tests', status: 'running' },
            { name: 'Monitoring', status: 'running' }
        ];

        return services.map(service => `
            <div class="d-flex justify-content-between align-items-center mb-2">
                <span>${service.name}</span>
                <span class="badge bg-${service.status === 'running' ? 'success' : 'danger'}">
                    ${service.status}
                </span>
            </div>
        `).join('');
    }

    renderTestResults(results) {
        if (!results || !results.tests) {
            return '<p class="text-muted">No test results available</p>';
        }

        return `
            <div class="row">
                <div class="col-12">
                    <h6>Test Summary</h6>
                    <div class="row mb-3">
                        <div class="col-md-3">
                            <div class="text-center">
                                <div class="h4 text-success">${results.passed || 0}</div>
                                <small>Passed</small>
                            </div>
                        </div>
                        <div class="col-md-3">
                            <div class="text-center">
                                <div class="h4 text-danger">${results.failed || 0}</div>
                                <small>Failed</small>
                            </div>
                        </div>
                        <div class="col-md-3">
                            <div class="text-center">
                                <div class="h4 text-warning">${results.errors || 0}</div>
                                <small>Errors</small>
                            </div>
                        </div>
                        <div class="col-md-3">
                            <div class="text-center">
                                <div class="h4 text-info">${results.total_tests || 0}</div>
                                <small>Total</small>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
            <div class="table-responsive">
                <table class="table table-striped">
                    <thead>
                        <tr>
                            <th>Test Name</th>
                            <th>Status</th>
                            <th>Duration</th>
                            <th>Message</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${results.tests.map(test => `
                            <tr class="test-result-${test.status.toLowerCase()}">
                                <td>${test.name}</td>
                                <td>
                                    <span class="badge bg-${this.getTestStatusColor(test.status)}">
                                        ${test.status}
                                    </span>
                                </td>
                                <td>${test.duration_ms}ms</td>
                                <td>${test.message || '-'}</td>
                            </tr>
                        `).join('')}
                    </tbody>
                </table>
            </div>
        `;
    }

    getTestStatusColor(status) {
        const colors = {
            'PASS': 'success',
            'FAIL': 'danger',
            'ERROR': 'warning',
            'SKIP': 'secondary',
            'TIMEOUT': 'dark'
        };
        return colors[status] || 'secondary';
    }

    getCategoryTitle(category) {
        const titles = {
            'core': 'Core Application',
            'database': 'Database',
            'logging': 'Logging',
            'selftest': 'Self-Tests',
            'monitoring': 'Monitoring',
            'security': 'Security'
        };
        return titles[category] || category;
    }

    formatConfigKey(key) {
        return key.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase());
    }

    getInputType(value) {
        if (typeof value === 'boolean') return 'checkbox';
        if (typeof value === 'number') return 'number';
        return 'text';
    }

    getConfigDescription(key) {
        // This would normally come from the configuration schema
        return `Configuration setting for ${key.toLowerCase().replace(/_/g, ' ')}`;
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

    // Global functions for button clicks
    async runAllTests() {
        this.showLoading(true);
        try {
            await this.apiCall(`${this.adminBase}/run-tests`, { method: 'POST' });
            this.showSuccess('All tests started successfully');
            setTimeout(() => this.loadSelfTests(), 2000);
        } catch (error) {
            this.showError('Failed to start tests');
        } finally {
            this.showLoading(false);
        }
    }

    async runQuickTest() {
        this.showLoading(true);
        try {
            await this.apiCall(`${this.adminBase}/quick-test`, { method: 'POST' });
            this.showSuccess('Quick test completed');
        } catch (error) {
            this.showError('Quick test failed');
        } finally {
            this.showLoading(false);
        }
    }

    async saveConfiguration() {
        this.showLoading(true);
        try {
            // Collect all form data
            const formData = new FormData(document.querySelector('[id^="config-form-"]'));
            const config = Object.fromEntries(formData);
            
            await this.apiCall(`${this.adminBase}/configuration`, {
                method: 'POST',
                body: JSON.stringify(config)
            });
            
            this.showSuccess('Configuration saved successfully');
        } catch (error) {
            this.showError('Failed to save configuration');
        } finally {
            this.showLoading(false);
        }
    }
}

// Global functions for HTML onclick handlers
let adminConsole;

function refreshAll() {
    adminConsole.loadDashboard();
}

function runFullSelfTest() {
    adminConsole.runAllTests();
}

function runQuickTest() {
    adminConsole.runQuickTest();
}

function saveConfiguration() {
    adminConsole.saveConfiguration();
}

function refreshSystemStatus() {
    adminConsole.loadSystemStatus();
}

function refreshTestResults() {
    adminConsole.loadSelfTests();
}

function runConnectivityTests() {
    adminConsole.apiCall('/admin/run-tests/connectivity', { method: 'POST' })
        .then(() => adminConsole.showSuccess('Connectivity tests started'))
        .catch(() => adminConsole.showError('Failed to start connectivity tests'));
}

function runDatabaseTests() {
    adminConsole.apiCall('/admin/run-tests/database', { method: 'POST' })
        .then(() => adminConsole.showSuccess('Database tests started'))
        .catch(() => adminConsole.showError('Failed to start database tests'));
}

function runUserTests() {
    adminConsole.apiCall('/admin/run-tests/users', { method: 'POST' })
        .then(() => adminConsole.showSuccess('User tests started'))
        .catch(() => adminConsole.showError('Failed to start user tests'));
}

function runEndpointTests() {
    adminConsole.apiCall('/admin/run-tests/endpoints', { method: 'POST' })
        .then(() => adminConsole.showSuccess('Endpoint tests started'))
        .catch(() => adminConsole.showError('Failed to start endpoint tests'));
}

// Initialize when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    adminConsole = new AdminConsole();
});

// Export for global access
window.adminConsole = adminConsole;
