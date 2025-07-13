#!/usr/bin/env python3
"""
PlexiChat Plugin Manager UI Creation

Simple script to create enhanced plugin management UI files.
"""

import asyncio
import logging
import sys
from pathlib import Path


class PluginUICreator:
    """Create enhanced plugin management UI files."""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        
        # Setup logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
    
    async def create_enhanced_plugin_ui(self):
        """Create enhanced plugin management UI."""
        try:
            # Create UI directory structure
            ui_dir = Path("src/plexichat/interfaces/web/static/plugin-manager")
            ui_dir.mkdir(parents=True, exist_ok=True)
            
            # Create enhanced CSS
            await self._create_enhanced_css(ui_dir)
            
            # Create enhanced JavaScript
            await self._create_enhanced_js(ui_dir)
            
            # Create plugin management HTML
            await self._create_plugin_management_html(ui_dir)
            
            # Create marketplace HTML
            await self._create_marketplace_html(ui_dir)
            
            # Create plugin configuration template
            await self._create_config_template(ui_dir)
            
            self.logger.info("Enhanced plugin UI created successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to create enhanced plugin UI: {e}")
            return False
    
    async def _create_enhanced_css(self, ui_dir: Path):
        """Create enhanced CSS for plugin manager."""
        css_file = ui_dir / "plugin-manager.css"
        
        css_content = """
/* Enhanced Plugin Manager CSS */
.plugin-manager {
    max-width: 1200px;
    margin: 0 auto;
    padding: 20px;
    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
}

.plugin-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 30px;
    padding: 20px;
    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
    color: white;
    border-radius: 10px;
    box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
}

.plugin-title {
    font-size: 2.5em;
    font-weight: 300;
    margin: 0;
}

.plugin-actions {
    display: flex;
    gap: 10px;
}

.btn {
    padding: 10px 20px;
    border: none;
    border-radius: 5px;
    cursor: pointer;
    font-weight: 500;
    transition: all 0.3s ease;
    text-decoration: none;
    display: inline-flex;
    align-items: center;
    gap: 8px;
}

.btn-primary {
    background: #007bff;
    color: white;
}

.btn-primary:hover {
    background: #0056b3;
    transform: translateY(-2px);
}

.btn-success {
    background: #28a745;
    color: white;
}

.btn-success:hover {
    background: #1e7e34;
    transform: translateY(-2px);
}

.btn-warning {
    background: #ffc107;
    color: #212529;
}

.btn-warning:hover {
    background: #e0a800;
    transform: translateY(-2px);
}

.btn-danger {
    background: #dc3545;
    color: white;
}

.btn-danger:hover {
    background: #c82333;
    transform: translateY(-2px);
}

.plugin-filters {
    display: flex;
    gap: 15px;
    margin-bottom: 20px;
    padding: 15px;
    background: #f8f9fa;
    border-radius: 8px;
}

.filter-group {
    display: flex;
    flex-direction: column;
    gap: 5px;
}

.filter-label {
    font-weight: 500;
    color: #495057;
}

.filter-input {
    padding: 8px 12px;
    border: 1px solid #ced4da;
    border-radius: 4px;
    font-size: 14px;
}

.plugin-grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(350px, 1fr));
    gap: 20px;
    margin-bottom: 30px;
}

.plugin-card {
    background: white;
    border-radius: 10px;
    padding: 20px;
    box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
    transition: all 0.3s ease;
    border: 1px solid #e9ecef;
}

.plugin-card:hover {
    transform: translateY(-5px);
    box-shadow: 0 5px 20px rgba(0, 0, 0, 0.15);
}

.plugin-card-header {
    display: flex;
    justify-content: space-between;
    align-items: flex-start;
    margin-bottom: 15px;
}

.plugin-name {
    font-size: 1.3em;
    font-weight: 600;
    color: #212529;
    margin: 0;
}

.plugin-status {
    padding: 4px 8px;
    border-radius: 12px;
    font-size: 0.8em;
    font-weight: 500;
}

.status-loaded {
    background: #d4edda;
    color: #155724;
}

.status-disabled {
    background: #f8d7da;
    color: #721c24;
}

.status-error {
    background: #f8d7da;
    color: #721c24;
}

.status-loading {
    background: #fff3cd;
    color: #856404;
}

.plugin-description {
    color: #6c757d;
    margin-bottom: 15px;
    line-height: 1.5;
}

.plugin-meta {
    display: flex;
    flex-wrap: wrap;
    gap: 10px;
    margin-bottom: 15px;
}

.plugin-meta-item {
    display: flex;
    align-items: center;
    gap: 5px;
    font-size: 0.9em;
    color: #6c757d;
}

.plugin-actions-card {
    display: flex;
    gap: 8px;
    flex-wrap: wrap;
}

.plugin-stats {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: 15px;
    margin-top: 30px;
}

.stat-card {
    background: white;
    padding: 20px;
    border-radius: 8px;
    box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
    text-align: center;
}

.stat-number {
    font-size: 2em;
    font-weight: 600;
    color: #007bff;
    margin-bottom: 5px;
}

.stat-label {
    color: #6c757d;
    font-size: 0.9em;
}

.modal {
    display: none;
    position: fixed;
    z-index: 1000;
    left: 0;
    top: 0;
    width: 100%;
    height: 100%;
    background-color: rgba(0, 0, 0, 0.5);
}

.modal-content {
    background-color: white;
    margin: 5% auto;
    padding: 20px;
    border-radius: 10px;
    width: 80%;
    max-width: 600px;
    max-height: 80vh;
    overflow-y: auto;
}

.modal-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 20px;
    padding-bottom: 10px;
    border-bottom: 1px solid #e9ecef;
}

.modal-title {
    font-size: 1.5em;
    font-weight: 600;
    color: #212529;
}

.close {
    color: #aaa;
    font-size: 28px;
    font-weight: bold;
    cursor: pointer;
}

.close:hover {
    color: #000;
}

.config-form {
    display: flex;
    flex-direction: column;
    gap: 15px;
}

.form-group {
    display: flex;
    flex-direction: column;
    gap: 5px;
}

.form-label {
    font-weight: 500;
    color: #495057;
}

.form-input {
    padding: 10px;
    border: 1px solid #ced4da;
    border-radius: 4px;
    font-size: 14px;
}

.form-textarea {
    padding: 10px;
    border: 1px solid #ced4da;
    border-radius: 4px;
    font-size: 14px;
    min-height: 100px;
    resize: vertical;
}

.form-select {
    padding: 10px;
    border: 1px solid #ced4da;
    border-radius: 4px;
    font-size: 14px;
}

.form-checkbox {
    margin-right: 8px;
}

.alert {
    padding: 12px 16px;
    border-radius: 4px;
    margin-bottom: 15px;
}

.alert-success {
    background-color: #d4edda;
    color: #155724;
    border: 1px solid #c3e6cb;
}

.alert-error {
    background-color: #f8d7da;
    color: #721c24;
    border: 1px solid #f5c6cb;
}

.alert-warning {
    background-color: #fff3cd;
    color: #856404;
    border: 1px solid #ffeaa7;
}

.alert-info {
    background-color: #d1ecf1;
    color: #0c5460;
    border: 1px solid #bee5eb;
}

/* Responsive design */
@media (max-width: 768px) {
    .plugin-header {
        flex-direction: column;
        gap: 15px;
        text-align: center;
    }
    
    .plugin-actions {
        flex-wrap: wrap;
        justify-content: center;
    }
    
    .plugin-filters {
        flex-direction: column;
    }
    
    .plugin-grid {
        grid-template-columns: 1fr;
    }
    
    .plugin-stats {
        grid-template-columns: 1fr;
    }
    
    .modal-content {
        width: 95%;
        margin: 10% auto;
    }
}
"""
        
        with open(css_file, 'w') as f:
            f.write(css_content)
        
        self.logger.info(f"Enhanced CSS created: {css_file}")
    
    async def _create_enhanced_js(self, ui_dir: Path):
        """Create enhanced JavaScript for plugin manager."""
        js_file = ui_dir / "plugin-manager.js"
        
        js_content = """
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
"""
        
        with open(js_file, 'w') as f:
            f.write(js_content)
        
        self.logger.info(f"Enhanced JavaScript created: {js_file}")
    
    async def _create_plugin_management_html(self, ui_dir: Path):
        """Create enhanced plugin management HTML."""
        html_file = ui_dir / "plugin-manager.html"
        
        html_content = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PlexiChat Plugin Manager</title>
    <link rel="stylesheet" href="plugin-manager.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
</head>
<body>
    <div class="plugin-manager">
        <div class="plugin-header">
            <h1 class="plugin-title">Plugin Manager</h1>
            <div class="plugin-actions">
                <button id="refresh-plugins" class="btn btn-primary">
                    <i class="fas fa-sync-alt"></i> Refresh
                </button>
                <button id="install-zip" class="btn btn-success">
                    <i class="fas fa-download"></i> Install ZIP
                </button>
                <button id="marketplace-btn" class="btn btn-primary">
                    <i class="fas fa-store"></i> Marketplace
                </button>
            </div>
        </div>
        
        <div class="plugin-filters">
            <div class="filter-group">
                <label class="filter-label">Status</label>
                <select id="status-filter" class="filter-input">
                    <option value="all">All Status</option>
                    <option value="loaded">Loaded</option>
                    <option value="enabled">Enabled</option>
                    <option value="disabled">Disabled</option>
                    <option value="error">Error</option>
                </select>
            </div>
            <div class="filter-group">
                <label class="filter-label">Category</label>
                <select id="category-filter" class="filter-input">
                    <option value="all">All Categories</option>
                    <option value="security">Security</option>
                    <option value="utility">Utility</option>
                    <option value="feature">Feature</option>
                    <option value="demo">Demo</option>
                </select>
            </div>
            <div class="filter-group">
                <label class="filter-label">Search</label>
                <input type="text" id="search-input" class="filter-input" placeholder="Search plugins...">
            </div>
        </div>
        
        <div class="plugin-stats">
            <div class="stat-card">
                <div class="stat-number" id="stat-total">0</div>
                <div class="stat-label">Total Plugins</div>
            </div>
            <div class="stat-card">
                <div class="stat-number" id="stat-loaded">0</div>
                <div class="stat-label">Loaded</div>
            </div>
            <div class="stat-card">
                <div class="stat-number" id="stat-enabled">0</div>
                <div class="stat-label">Enabled</div>
            </div>
            <div class="stat-card">
                <div class="stat-number" id="stat-disabled">0</div>
                <div class="stat-label">Disabled</div>
            </div>
        </div>
        
        <div id="plugin-grid" class="plugin-grid">
            <!-- Plugin cards will be rendered here -->
        </div>
    </div>
    
    <!-- Install Modal -->
    <div id="install-modal" class="modal">
        <div class="modal-content">
            <div class="modal-header">
                <h2 class="modal-title">Install Plugin from ZIP</h2>
                <span class="close" onclick="document.getElementById('install-modal').style.display='none'">&times;</span>
            </div>
            <div class="config-form">
                <div class="form-group">
                    <label class="form-label">Select ZIP File</label>
                    <input type="file" id="zip-file" class="form-input" accept=".zip">
                </div>
                <div class="plugin-actions">
                    <button onclick="pluginManager.installFromZip()" class="btn btn-primary">Install</button>
                    <button onclick="document.getElementById('install-modal').style.display='none'" class="btn btn-warning">Cancel</button>
                </div>
            </div>
        </div>
    </div>
    
    <!-- Config Modal -->
    <div id="config-modal" class="modal">
        <div class="modal-content">
            <div id="config-content">
                <!-- Configuration form will be rendered here -->
            </div>
        </div>
    </div>
    
    <script src="plugin-manager.js"></script>
</body>
</html>
"""
        
        with open(html_file, 'w') as f:
            f.write(html_content)
        
        self.logger.info(f"Plugin management HTML created: {html_file}")
    
    async def _create_marketplace_html(self, ui_dir: Path):
        """Create marketplace HTML."""
        marketplace_file = ui_dir / "marketplace.html"
        
        marketplace_content = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PlexiChat Plugin Marketplace</title>
    <link rel="stylesheet" href="plugin-manager.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
</head>
<body>
    <div class="plugin-manager">
        <div class="plugin-header">
            <h1 class="plugin-title">Plugin Marketplace</h1>
            <div class="plugin-actions">
                <button onclick="window.history.back()" class="btn btn-primary">
                    <i class="fas fa-arrow-left"></i> Back to Manager
                </button>
            </div>
        </div>
        
        <div class="marketplace-section">
            <div class="marketplace-header">
                <h2 class="marketplace-title">Featured Plugins</h2>
            </div>
            
            <div class="plugin-search">
                <input type="text" id="marketplace-search" class="search-input" placeholder="Search marketplace...">
                <button class="search-btn">Search</button>
            </div>
            
            <div id="marketplace-grid" class="plugin-grid">
                <!-- Marketplace plugins will be rendered here -->
            </div>
        </div>
    </div>
    
    <script>
        // Marketplace functionality would be implemented here
        console.log('Marketplace loaded');
    </script>
</body>
</html>
"""
        
        with open(marketplace_file, 'w') as f:
            f.write(marketplace_content)
        
        self.logger.info(f"Marketplace HTML created: {marketplace_file}")
    
    async def _create_config_template(self, ui_dir: Path):
        """Create plugin configuration template."""
        template_file = ui_dir / "config-template.html"
        
        template_content = """
<!-- Plugin Configuration Template -->
<div class="config-form">
    <div class="form-group">
        <label class="form-label">Plugin Name</label>
        <input type="text" class="form-input" name="name" required>
    </div>
    
    <div class="form-group">
        <label class="form-label">Version</label>
        <input type="text" class="form-input" name="version" required>
    </div>
    
    <div class="form-group">
        <label class="form-label">Description</label>
        <textarea class="form-textarea" name="description" rows="3"></textarea>
    </div>
    
    <div class="form-group">
        <label class="form-label">Author</label>
        <input type="text" class="form-input" name="author">
    </div>
    
    <div class="form-group">
        <label class="form-label">Category</label>
        <select class="form-select" name="category">
            <option value="utility">Utility</option>
            <option value="security">Security</option>
            <option value="feature">Feature</option>
            <option value="demo">Demo</option>
        </select>
    </div>
    
    <div class="form-group">
        <label class="form-label">Enabled</label>
        <input type="checkbox" class="form-checkbox" name="enabled" checked>
    </div>
    
    <div class="form-group">
        <label class="form-label">Auto Start</label>
        <input type="checkbox" class="form-checkbox" name="auto_start">
    </div>
    
    <div class="plugin-actions">
        <button type="submit" class="btn btn-primary">Save Configuration</button>
        <button type="button" class="btn btn-warning">Cancel</button>
    </div>
</div>
"""
        
        with open(template_file, 'w') as f:
            f.write(template_content)
        
        self.logger.info(f"Configuration template created: {template_file}")


async def main():
    """Main function to create plugin UI."""
    creator = PluginUICreator()
    
    success = await creator.create_enhanced_plugin_ui()
    if success:
        print("✅ Enhanced plugin UI created successfully!")
        print("📁 Files created in: src/plexichat/interfaces/web/static/plugin-manager/")
        print("🌐 Access the plugin manager at: /plugin-manager")
    else:
        print("❌ Failed to create enhanced plugin UI")
        return 1
    
    return 0


if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code) 