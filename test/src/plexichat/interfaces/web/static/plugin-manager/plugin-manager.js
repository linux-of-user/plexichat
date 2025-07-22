
// Enhanced Plugin Manager JavaScript
class PluginManager {
    constructor() {
        this.plugins = [];
        this.filteredPlugins = [];
        this.currentFilters = {
            status: 'all',
            category: 'all',
            search: ''
        };
        this.init();
    }
    
    async init() {
        await this.loadPlugins();
        this.setupEventListeners();
        this.renderPlugins();
        this.updateStats();
    }
    
    async loadPlugins() {
        try {
            const response = await fetch('/api/v1/plugins/');
            const data = await response.json();
            this.plugins = data.plugins || [];
            this.filteredPlugins = [...this.plugins];
        } catch (error) {
            console.error('Failed to load plugins:', error);
            this.showAlert('Failed to load plugins', 'error');
        }
    }
    
    setupEventListeners() {
        // Filter event listeners
        document.getElementById('status-filter')?.addEventListener('change', (e) => {
            this.currentFilters.status = e.target.value;
            this.filterPlugins();
        });
        
        document.getElementById('category-filter')?.addEventListener('change', (e) => {
            this.currentFilters.category = e.target.value;
            this.filterPlugins();
        });
        
        document.getElementById('search-input')?.addEventListener('input', (e) => {
            this.currentFilters.search = e.target.value;
            this.filterPlugins();
        });
        
        // Action buttons
        document.getElementById('refresh-plugins')?.addEventListener('click', () => {
            this.loadPlugins();
        });
        
        document.getElementById('install-zip')?.addEventListener('click', () => {
            this.showInstallModal();
        });
        
        document.getElementById('marketplace-btn')?.addEventListener('click', () => {
            this.showMarketplace();
        });
    }
    
    filterPlugins() {
        this.filteredPlugins = this.plugins.filter(plugin => {
            // Status filter
            if (this.currentFilters.status !== 'all' && plugin.status !== this.currentFilters.status) {
                return false;
            }
            
            // Category filter
            if (this.currentFilters.category !== 'all' && plugin.metadata?.category !== this.currentFilters.category) {
                return false;
            }
            
            // Search filter
            if (this.currentFilters.search) {
                const searchTerm = this.currentFilters.search.toLowerCase();
                const searchableText = [
                    plugin.name,
                    plugin.metadata?.name,
                    plugin.metadata?.description,
                    plugin.metadata?.author
                ].join(' ').toLowerCase();
                
                if (!searchableText.includes(searchTerm)) {
                    return false;
                }
            }
            
            return true;
        });
        
        this.renderPlugins();
    }
    
    renderPlugins() {
        const container = document.getElementById('plugin-grid');
        if (!container) return;
        
        container.innerHTML = '';
        
        if (this.filteredPlugins.length === 0) {
            container.innerHTML = '<div class="alert alert-info">No plugins found matching the current filters.</div>';
            return;
        }
        
        this.filteredPlugins.forEach(plugin => {
            const card = this.createPluginCard(plugin);
            container.appendChild(card);
        });
    }
    
    createPluginCard(plugin) {
        const card = document.createElement('div');
        card.className = 'plugin-card';
        
        const status = plugin.status || 'unknown';
        const metadata = plugin.metadata || {};
        
        card.innerHTML = `
            <div class="plugin-card-header">
                <h3 class="plugin-name">${metadata.name || plugin.name}</h3>
                <span class="plugin-status status-${status}">${status}</span>
            </div>
            <p class="plugin-description">${metadata.description || 'No description available'}</p>
            <div class="plugin-meta">
                <span class="plugin-meta-item">
                    <i class="fas fa-user"></i>
                    ${metadata.author || 'Unknown'}
                </span>
                <span class="plugin-meta-item">
                    <i class="fas fa-tag"></i>
                    ${metadata.category || 'General'}
                </span>
                <span class="plugin-meta-item">
                    <i class="fas fa-code-branch"></i>
                    v${metadata.version || '1.0.0'}
                </span>
            </div>
            <div class="plugin-actions-card">
                ${this.createActionButtons(plugin)}
            </div>
        `;
        
        return card;
    }
    
    createActionButtons(plugin) {
        const buttons = [];
        const status = plugin.status || 'unknown';
        
        if (status === 'loaded' || status === 'enabled') {
            buttons.push(`
                <button class="btn btn-warning" onclick="pluginManager.disablePlugin('${plugin.name}')">
                    <i class="fas fa-pause"></i> Disable
                </button>
            `);
        } else {
            buttons.push(`
                <button class="btn btn-success" onclick="pluginManager.enablePlugin('${plugin.name}')">
                    <i class="fas fa-play"></i> Enable
                </button>
            `);
        }
        
        buttons.push(`
            <button class="btn btn-primary" onclick="pluginManager.configurePlugin('${plugin.name}')">
                <i class="fas fa-cog"></i> Configure
            </button>
        `);
        
        buttons.push(`
            <button class="btn btn-danger" onclick="pluginManager.removePlugin('${plugin.name}')">
                <i class="fas fa-trash"></i> Remove
            </button>
        `);
        
        return buttons.join('');
    }
    
    async enablePlugin(pluginName) {
        try {
            const response = await fetch(`/api/v1/plugins/enable`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ plugin_name: pluginName })
            });
            
            if (response.ok) {
                this.showAlert(`Plugin ${pluginName} enabled successfully`, 'success');
                await this.loadPlugins();
            } else {
                this.showAlert(`Failed to enable plugin ${pluginName}`, 'error');
            }
        } catch (error) {
            console.error('Error enabling plugin:', error);
            this.showAlert('Error enabling plugin', 'error');
        }
    }
    
    async disablePlugin(pluginName) {
        try {
            const response = await fetch(`/api/v1/plugins/disable`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ plugin_name: pluginName })
            });
            
            if (response.ok) {
                this.showAlert(`Plugin ${pluginName} disabled successfully`, 'success');
                await this.loadPlugins();
            } else {
                this.showAlert(`Failed to disable plugin ${pluginName}`, 'error');
            }
        } catch (error) {
            console.error('Error disabling plugin:', error);
            this.showAlert('Error disabling plugin', 'error');
        }
    }
    
    async configurePlugin(pluginName) {
        try {
            const response = await fetch(`/api/v1/plugins/${pluginName}`);
            const plugin = await response.json();
            
            this.showConfigModal(plugin);
        } catch (error) {
            console.error('Error loading plugin config:', error);
            this.showAlert('Error loading plugin configuration', 'error');
        }
    }
    
    async removePlugin(pluginName) {
        if (!confirm(`Are you sure you want to remove plugin ${pluginName}?`)) {
            return;
        }
        
        try {
            const response = await fetch(`/api/v1/plugins/remove`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ plugin_name: pluginName })
            });
            
            if (response.ok) {
                this.showAlert(`Plugin ${pluginName} removed successfully`, 'success');
                await this.loadPlugins();
            } else {
                this.showAlert(`Failed to remove plugin ${pluginName}`, 'error');
            }
        } catch (error) {
            console.error('Error removing plugin:', error);
            this.showAlert('Error removing plugin', 'error');
        }
    }
    
    showInstallModal() {
        const modal = document.getElementById('install-modal');
        if (modal) {
            modal.style.display = 'block';
        }
    }
    
    hideInstallModal() {
        const modal = document.getElementById('install-modal');
        if (modal) {
            modal.style.display = 'none';
        }
    }
    
    async installFromZip() {
        const fileInput = document.getElementById('zip-file');
        const file = fileInput.files[0];
        
        if (!file) {
            this.showAlert('Please select a ZIP file', 'warning');
            return;
        }
        
        const formData = new FormData();
        formData.append('zip_file', file);
        
        try {
            const response = await fetch('/api/v1/plugins/install-zip', {
                method: 'POST',
                body: formData
            });
            
            if (response.ok) {
                this.showAlert('Plugin installed successfully', 'success');
                this.hideInstallModal();
                await this.loadPlugins();
            } else {
                this.showAlert('Failed to install plugin', 'error');
            }
        } catch (error) {
            console.error('Error installing plugin:', error);
            this.showAlert('Error installing plugin', 'error');
        }
    }
    
    showConfigModal(plugin) {
        const modal = document.getElementById('config-modal');
        const content = document.getElementById('config-content');
        
        if (modal && content) {
            content.innerHTML = this.createConfigForm(plugin);
            modal.style.display = 'block';
            
            // Setup form submission
            const form = content.querySelector('form');
            if (form) {
                form.onsubmit = (e) => {
                    e.preventDefault();
                    this.savePluginConfig(plugin.name, form);
                };
            }
        }
    }
    
    createConfigForm(plugin) {
        const metadata = plugin.metadata || {};
        const config = plugin.config || {};
        
        return `
            <div class="modal-header">
                <h2 class="modal-title">Configure ${metadata.name || plugin.name}</h2>
                <span class="close" onclick="this.parentElement.parentElement.parentElement.style.display='none'">&times;</span>
            </div>
            <form class="config-form">
                <div class="form-group">
                    <label class="form-label">Plugin Name</label>
                    <input type="text" class="form-input" value="${metadata.name || plugin.name}" readonly>
                </div>
                <div class="form-group">
                    <label class="form-label">Version</label>
                    <input type="text" class="form-input" value="${metadata.version || '1.0.0'}" readonly>
                </div>
                <div class="form-group">
                    <label class="form-label">Description</label>
                    <textarea class="form-textarea" readonly>${metadata.description || 'No description'}</textarea>
                </div>
                <div class="form-group">
                    <label class="form-label">Enabled</label>
                    <input type="checkbox" class="form-checkbox" ${plugin.enabled ? 'checked' : ''} name="enabled">
                </div>
                <div class="form-group">
                    <label class="form-label">Auto Start</label>
                    <input type="checkbox" class="form-checkbox" ${metadata.auto_start ? 'checked' : ''} name="auto_start">
                </div>
                <div class="plugin-actions">
                    <button type="submit" class="btn btn-primary">Save Configuration</button>
                    <button type="button" class="btn btn-warning" onclick="this.parentElement.parentElement.parentElement.style.display='none'">Cancel</button>
                </div>
            </form>
        `;
    }
    
    async savePluginConfig(pluginName, form) {
        const formData = new FormData(form);
        const config = {
            enabled: formData.get('enabled') === 'on',
            auto_start: formData.get('auto_start') === 'on'
        };
        
        try {
            const response = await fetch(`/api/v1/plugins/${pluginName}/config`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ config })
            });
            
            if (response.ok) {
                this.showAlert('Plugin configuration saved successfully', 'success');
                document.getElementById('config-modal').style.display = 'none';
                await this.loadPlugins();
            } else {
                this.showAlert('Failed to save plugin configuration', 'error');
            }
        } catch (error) {
            console.error('Error saving plugin config:', error);
            this.showAlert('Error saving plugin configuration', 'error');
        }
    }
    
    updateStats() {
        const stats = {
            total: this.plugins.length,
            loaded: this.plugins.filter(p => p.status === 'loaded').length,
            enabled: this.plugins.filter(p => p.enabled).length,
            disabled: this.plugins.filter(p => !p.enabled).length
        };
        
        // Update stats display
        Object.keys(stats).forEach(key => {
            const element = document.getElementById(`stat-${key}`);
            if (element) {
                element.textContent = stats[key];
            }
        });
    }
    
    showAlert(message, type) {
        const alertDiv = document.createElement('div');
        alertDiv.className = `alert alert-${type}`;
        alertDiv.textContent = message;
        
        const container = document.querySelector('.plugin-manager');
        if (container) {
            container.insertBefore(alertDiv, container.firstChild);
            
            setTimeout(() => {
                alertDiv.remove();
            }, 5000);
        }
    }
    
    showMarketplace() {
        // Implementation for marketplace view
        console.log('Marketplace functionality would be implemented here');
    }
}

// Initialize plugin manager when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    window.pluginManager = new PluginManager();
});

// Close modals when clicking outside
window.onclick = function(event) {
    const modals = document.querySelectorAll('.modal');
    modals.forEach(modal => {
        if (event.target === modal) {
            modal.style.display = 'none';
        }
    });
}
