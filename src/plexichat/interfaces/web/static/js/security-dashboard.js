/**
 * Security Dashboard JavaScript
 * Handles real-time security monitoring and management
 */

class SecurityDashboard {
    constructor() {
        this.refreshInterval = 30000; // 30 seconds
        this.autoRefreshTimer = null;
        this.init();
    }

    init() {
        this.loadSecurityMetrics();
        this.loadSecurityEvents();
        this.loadBlockedIPs();
        this.startAutoRefresh();
    }

    async loadSecurityMetrics() {
        try {
            const response = await fetch('/api/v1/security/metrics', {
                headers: {
                    'Authorization': `Bearer ${this.getAuthToken()}`
                }
            });

            if (!response.ok) {
                throw new Error('Failed to load security metrics');
            }

            const metrics = await response.json();
            this.updateMetricsDisplay(metrics);
        } catch (error) {
            console.error('Error loading security metrics:', error);
            this.showError('Failed to load security metrics');
        }
    }

    updateMetricsDisplay(metrics) {
        document.getElementById('security-level').textContent = metrics.security_level || 'UNKNOWN';
        document.getElementById('threats-blocked').textContent = metrics.threat_detections || 0;
        document.getElementById('active-sessions').textContent = metrics.active_sessions || 0;
        document.getElementById('blocked-ips').textContent = metrics.blocked_ips || 0;

        // Update last updated time
        const lastUpdated = new Date(metrics.last_updated).toLocaleString();
        this.updateLastRefreshTime(lastUpdated);
    }

    async loadSecurityEvents() {
        try {
            const response = await fetch('/api/v1/security/audit-logs?limit=10', {
                headers: {
                    'Authorization': `Bearer ${this.getAuthToken()}`
                }
            });

            if (!response.ok) {
                throw new Error('Failed to load security events');
            }

            const data = await response.json();
            this.displaySecurityEvents(data.events);
        } catch (error) {
            console.error('Error loading security events:', error);
            this.showError('Failed to load security events');
        }
    }

    displaySecurityEvents(events) {
        const container = document.getElementById('security-events');
        container.innerHTML = '';

        if (!events || events.length === 0) {
            container.innerHTML = '<p class="text-muted">No recent security events</p>';
            return;
        }

        events.forEach(event => {
            const eventElement = document.createElement('div');
            eventElement.className = 'log-entry';
            
            const timestamp = new Date(event.timestamp * 1000).toLocaleString();
            const severityClass = this.getSeverityClass(event.severity);
            
            eventElement.innerHTML = `
                <div class="d-flex justify-content-between">
                    <div>
                        <strong class="${severityClass}">${event.event_type}</strong>
                        <small class="text-muted d-block">${event.ip_address} - ${timestamp}</small>
                    </div>
                    <div>
                        <span class="badge bg-secondary">${event.severity}</span>
                    </div>
                </div>
                <div class="mt-1">
                    <small>${JSON.stringify(event.details)}</small>
                </div>
            `;
            
            container.appendChild(eventElement);
        });
    }

    async loadBlockedIPs() {
        try {
            const response = await fetch('/api/v1/security/blocked-ips', {
                headers: {
                    'Authorization': `Bearer ${this.getAuthToken()}`
                }
            });

            if (!response.ok) {
                throw new Error('Failed to load blocked IPs');
            }

            const data = await response.json();
            this.displayBlockedIPs(data.blocked_ips);
        } catch (error) {
            console.error('Error loading blocked IPs:', error);
            this.showError('Failed to load blocked IPs');
        }
    }

    displayBlockedIPs(blockedIPs) {
        const container = document.getElementById('blocked-ips-list');
        container.innerHTML = '';

        if (!blockedIPs || blockedIPs.length === 0) {
            container.innerHTML = '<p class="text-muted">No blocked IP addresses</p>';
            return;
        }

        blockedIPs.forEach(ip => {
            const ipElement = document.createElement('div');
            ipElement.className = 'd-flex justify-content-between align-items-center mb-2';
            ipElement.innerHTML = `
                <span>${ip}</span>
                <button class="btn btn-sm btn-outline-success" onclick="securityDashboard.unblockIP('${ip}')">
                    <i class="fas fa-unlock"></i> Unblock
                </button>
            `;
            container.appendChild(ipElement);
        });
    }

    async blockIP() {
        const ipAddress = document.getElementById('ip-to-block').value.trim();
        const reason = document.getElementById('block-reason').value.trim() || 'Manual block';

        if (!ipAddress) {
            this.showError('Please enter an IP address to block');
            return;
        }

        try {
            const response = await fetch('/api/v1/security/block-ip', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${this.getAuthToken()}`
                },
                body: JSON.stringify({
                    ip_address: ipAddress,
                    reason: reason
                })
            });

            if (!response.ok) {
                throw new Error('Failed to block IP address');
            }

            const result = await response.json();
            this.showSuccess(`IP ${ipAddress} has been blocked successfully`);
            
            // Clear inputs and reload blocked IPs
            document.getElementById('ip-to-block').value = '';
            document.getElementById('block-reason').value = '';
            this.loadBlockedIPs();
            this.loadSecurityMetrics();
        } catch (error) {
            console.error('Error blocking IP:', error);
            this.showError('Failed to block IP address');
        }
    }

    async unblockIP(ipAddress) {
        try {
            const response = await fetch(`/api/v1/security/block-ip/${ipAddress}`, {
                method: 'DELETE',
                headers: {
                    'Authorization': `Bearer ${this.getAuthToken()}`
                }
            });

            if (!response.ok) {
                throw new Error('Failed to unblock IP address');
            }

            this.showSuccess(`IP ${ipAddress} has been unblocked successfully`);
            this.loadBlockedIPs();
            this.loadSecurityMetrics();
        } catch (error) {
            console.error('Error unblocking IP:', error);
            this.showError('Failed to unblock IP address');
        }
    }

    async analyzeThreat() {
        const inputData = document.getElementById('threat-input').value.trim();
        
        if (!inputData) {
            this.showError('Please enter text to analyze');
            return;
        }

        try {
            const response = await fetch('/api/v1/security/analyze-threat', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${this.getAuthToken()}`
                },
                body: JSON.stringify({
                    input_data: inputData,
                    analysis_type: 'comprehensive'
                })
            });

            if (!response.ok) {
                throw new Error('Failed to analyze threat');
            }

            const result = await response.json();
            this.displayThreatResults(result);
        } catch (error) {
            console.error('Error analyzing threat:', error);
            this.showError('Failed to analyze threat');
        }
    }

    displayThreatResults(result) {
        const container = document.getElementById('threat-results');
        
        let alertClass = 'alert-success';
        let icon = 'fa-check-circle';
        let message = 'No threats detected';

        if (result.is_malicious) {
            alertClass = 'alert-danger';
            icon = 'fa-exclamation-triangle';
            message = `Threats detected! Score: ${result.threat_score}/100`;
        }

        let threatsHtml = '';
        if (result.threats_detected && Object.keys(result.threats_detected).length > 0) {
            threatsHtml = '<h6>Threats Found:</h6><ul>';
            for (const [category, patterns] of Object.entries(result.threats_detected)) {
                threatsHtml += `<li><strong>${category}:</strong> ${patterns.length} pattern(s) matched</li>`;
            }
            threatsHtml += '</ul>';
        }

        container.innerHTML = `
            <div class="alert ${alertClass}">
                <i class="fas ${icon}"></i> ${message}
                ${threatsHtml}
            </div>
        `;
    }

    async performSecurityScan() {
        try {
            this.showInfo('Performing security scan...');
            
            const response = await fetch('/api/v1/security/scan', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${this.getAuthToken()}`
                },
                body: JSON.stringify({
                    scan_type: 'comprehensive',
                    include_vulnerabilities: true,
                    include_threats: true
                })
            });

            if (!response.ok) {
                throw new Error('Failed to perform security scan');
            }

            const result = await response.json();
            this.showSuccess(`Security scan completed. Score: ${result.security_score}/100`);
            this.loadSecurityMetrics();
        } catch (error) {
            console.error('Error performing security scan:', error);
            this.showError('Failed to perform security scan');
        }
    }

    async emergencyLockdown() {
        if (!confirm('Are you sure you want to activate emergency lockdown? This will restrict system access.')) {
            return;
        }

        try {
            const response = await fetch('/api/v1/security/emergency-lockdown', {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${this.getAuthToken()}`
                }
            });

            if (!response.ok) {
                throw new Error('Failed to activate emergency lockdown');
            }

            const result = await response.json();
            this.showWarning('Emergency lockdown activated!');
        } catch (error) {
            console.error('Error activating emergency lockdown:', error);
            this.showError('Failed to activate emergency lockdown');
        }
    }

    refreshDashboard() {
        this.loadSecurityMetrics();
        this.loadSecurityEvents();
        this.loadBlockedIPs();
    }

    startAutoRefresh() {
        this.autoRefreshTimer = setInterval(() => {
            this.refreshDashboard();
        }, this.refreshInterval);
    }

    stopAutoRefresh() {
        if (this.autoRefreshTimer) {
            clearInterval(this.autoRefreshTimer);
            this.autoRefreshTimer = null;
        }
    }

    getSeverityClass(severity) {
        switch (severity?.toUpperCase()) {
            case 'CRITICAL':
                return 'severity-critical';
            case 'WARNING':
                return 'severity-warning';
            default:
                return 'severity-info';
        }
    }

    getAuthToken() {
        // This should be implemented based on your authentication system
        return localStorage.getItem('auth_token') || '';
    }

    updateLastRefreshTime(time) {
        // Update a last refresh indicator if it exists
        const indicator = document.getElementById('last-refresh');
        if (indicator) {
            indicator.textContent = `Last updated: ${time}`;
        }
    }

    showSuccess(message) {
        this.showAlert(message, 'success');
    }

    showError(message) {
        this.showAlert(message, 'danger');
    }

    showWarning(message) {
        this.showAlert(message, 'warning');
    }

    showInfo(message) {
        this.showAlert(message, 'info');
    }

    showAlert(message, type) {
        // Create and show a Bootstrap alert
        const alertDiv = document.createElement('div');
        alertDiv.className = `alert alert-${type} alert-dismissible fade show position-fixed`;
        alertDiv.style.cssText = 'top: 20px; right: 20px; z-index: 9999; min-width: 300px;';
        alertDiv.innerHTML = `
            ${message}
            <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
        `;
        
        document.body.appendChild(alertDiv);
        
        // Auto-remove after 5 seconds
        setTimeout(() => {
            if (alertDiv.parentNode) {
                alertDiv.parentNode.removeChild(alertDiv);
            }
        }, 5000);
    }
}

// Initialize dashboard when page loads
let securityDashboard;
document.addEventListener('DOMContentLoaded', function() {
    securityDashboard = new SecurityDashboard();
});

// Global functions for HTML onclick handlers
function refreshDashboard() {
    securityDashboard.refreshDashboard();
}

function performSecurityScan() {
    securityDashboard.performSecurityScan();
}

function emergencyLockdown() {
    securityDashboard.emergencyLockdown();
}

function analyzeThreat() {
    securityDashboard.analyzeThreat();
}

function blockIP() {
    securityDashboard.blockIP();
}
