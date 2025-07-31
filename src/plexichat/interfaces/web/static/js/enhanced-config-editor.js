/**
 * Enhanced Configuration Editor
 * Advanced configuration management with validation and hot-reload
 */

class EnhancedConfigEditor {
    constructor() {
        this.editor = null;
        this.currentConfig = null;
        this.configs = new Map();
        this.templates = new Map();
        this.validationTimer = null;
        this.autoSaveTimer = null;
        
        this.init();
    }

    init() {
        this.setupEditor();
        this.bindEvents();
        this.loadConfigurations();
        this.loadTemplates();
        
        console.log('🔧 Enhanced Configuration Editor initialized');
    }

    setupEditor() {
        const textarea = document.getElementById('editorTextarea');
        
        this.editor = CodeMirror.fromTextArea(textarea, {
            mode: 'yaml',
            theme: 'eclipse',
            lineNumbers: true,
            autoCloseBrackets: true,
            matchBrackets: true,
            indentUnit: 2,
            tabSize: 2,
            lineWrapping: true,
            foldGutter: true,
            gutters: ['CodeMirror-linenumbers', 'CodeMirror-foldgutter', 'CodeMirror-lint-markers'],
            lint: true,
            extraKeys: {
                'Ctrl-S': () => this.saveConfiguration(),
                'Ctrl-F': 'findPersistent',
                'Ctrl-H': 'replace',
                'F11': (cm) => {
                    cm.setOption('fullScreen', !cm.getOption('fullScreen'));
                },
                'Esc': (cm) => {
                    if (cm.getOption('fullScreen')) cm.setOption('fullScreen', false);
                }
            }
        });

        // Auto-validation on change
        this.editor.on('change', () => {
            this.scheduleValidation();
            this.scheduleAutoSave();
        });
    }

    bindEvents() {
        // Configuration list events
        document.getElementById('refreshConfigsBtn').addEventListener('click', () => {
            this.loadConfigurations();
        });

        document.getElementById('configSearch').addEventListener('input', (e) => {
            this.filterConfigurations(e.target.value);
        });

        // Editor actions
        document.getElementById('saveConfigBtn').addEventListener('click', () => {
            this.saveConfiguration();
        });

        document.getElementById('validateConfigBtn').addEventListener('click', () => {
            this.validateConfiguration();
        });

        document.getElementById('formatConfigBtn').addEventListener('click', () => {
            this.formatConfiguration();
        });

        // Editor mode and theme
        document.querySelectorAll('input[name="editorMode"]').forEach(radio => {
            radio.addEventListener('change', (e) => {
                this.changeEditorMode(e.target.value);
            });
        });

        document.querySelectorAll('input[name="editorTheme"]').forEach(radio => {
            radio.addEventListener('change', (e) => {
                this.changeEditorTheme(e.target.value);
            });
        });

        // Modal events
        document.getElementById('newConfigBtn').addEventListener('click', () => {
            this.showNewConfigModal();
        });

        document.getElementById('createConfigBtn').addEventListener('click', () => {
            this.createNewConfiguration();
        });

        document.getElementById('templatesBtn').addEventListener('click', () => {
            this.showTemplateModal();
        });

        // Hot reload
        document.getElementById('enableHotReloadBtn').addEventListener('click', () => {
            this.toggleHotReload();
        });

        // Backup
        document.getElementById('createBackupBtn').addEventListener('click', () => {
            this.createBackup();
        });

        // Delete
        document.getElementById('deleteConfigBtn').addEventListener('click', () => {
            this.deleteConfiguration();
        });
    }

    async loadConfigurations() {
        try {
            const response = await fetch('/api/admin/configs');
            const data = await response.json();
            
            if (data.success) {
                this.configs.clear();
                data.configs.forEach(config => {
                    this.configs.set(config.name, config);
                });
                
                this.renderConfigurationList();
            } else {
                this.showNotification('Failed to load configurations', 'error');
            }
        } catch (error) {
            console.error('Failed to load configurations:', error);
            this.showNotification('Failed to load configurations', 'error');
        }
    }

    async loadTemplates() {
        try {
            const response = await fetch('/api/admin/config-templates');
            const data = await response.json();
            
            if (data.success) {
                this.templates.clear();
                data.templates.forEach(template => {
                    this.templates.set(template.name, template);
                });
            }
        } catch (error) {
            console.error('Failed to load templates:', error);
        }
    }

    renderConfigurationList() {
        const configList = document.getElementById('configList');
        configList.innerHTML = '';

        this.configs.forEach((config, name) => {
            const listItem = document.createElement('div');
            listItem.className = 'list-group-item list-group-item-action d-flex justify-content-between align-items-center';
            listItem.innerHTML = `
                <div>
                    <div class="fw-bold">${name}</div>
                    <small class="text-muted">
                        ${config.scope} • ${config.format}
                        ${config.hot_reload_enabled ? '<i class="fas fa-fire text-warning ms-1" title="Hot Reload Enabled"></i>' : ''}
                    </small>
                </div>
                <div>
                    ${config.is_valid ? 
                        '<span class="badge bg-success">Valid</span>' : 
                        '<span class="badge bg-danger">Invalid</span>'
                    }
                </div>
            `;
            
            listItem.addEventListener('click', () => {
                this.selectConfiguration(name);
            });
            
            configList.appendChild(listItem);
        });
    }

    filterConfigurations(searchTerm) {
        const configList = document.getElementById('configList');
        const items = configList.querySelectorAll('.list-group-item');
        
        items.forEach(item => {
            const text = item.textContent.toLowerCase();
            const matches = text.includes(searchTerm.toLowerCase());
            item.style.display = matches ? 'flex' : 'none';
        });
    }

    async selectConfiguration(name) {
        try {
            const response = await fetch(`/api/admin/configs/${name}`);
            const data = await response.json();
            
            if (data.success) {
                this.currentConfig = data.config;
                this.displayConfiguration();
                this.showConfigInfo();
                
                // Update UI
                document.getElementById('welcomeScreen').style.display = 'none';
                document.getElementById('configEditor').style.display = 'block';
                document.getElementById('editorActions').style.display = 'block';
                document.getElementById('editorToolbar').style.display = 'block';
                document.getElementById('editorTitle').innerHTML = `
                    <i class="fas fa-edit"></i>
                    ${name}
                `;
                
                // Update active item in list
                document.querySelectorAll('#configList .list-group-item').forEach(item => {
                    item.classList.remove('active');
                });
                
                const activeItem = Array.from(document.querySelectorAll('#configList .list-group-item'))
                    .find(item => item.querySelector('.fw-bold').textContent === name);
                if (activeItem) {
                    activeItem.classList.add('active');
                }
                
            } else {
                this.showNotification('Failed to load configuration', 'error');
            }
        } catch (error) {
            console.error('Failed to select configuration:', error);
            this.showNotification('Failed to load configuration', 'error');
        }
    }

    displayConfiguration() {
        if (!this.currentConfig) return;
        
        const format = this.currentConfig.format;
        let content;
        
        if (format === 'yaml') {
            content = jsyaml.dump(this.currentConfig.data, { indent: 2 });
        } else {
            content = JSON.stringify(this.currentConfig.data, null, 2);
        }
        
        this.editor.setValue(content);
        this.changeEditorMode(format);
        
        // Update mode radio
        document.getElementById(`${format}Mode`).checked = true;
    }

    showConfigInfo() {
        if (!this.currentConfig) return;
        
        const configInfo = document.getElementById('configInfo');
        configInfo.innerHTML = `
            <div class="row g-2">
                <div class="col-6">
                    <strong>Name:</strong><br>
                    <span class="text-muted">${this.currentConfig.name}</span>
                </div>
                <div class="col-6">
                    <strong>Scope:</strong><br>
                    <span class="text-muted">${this.currentConfig.scope}</span>
                </div>
                <div class="col-6">
                    <strong>Format:</strong><br>
                    <span class="text-muted">${this.currentConfig.format.toUpperCase()}</span>
                </div>
                <div class="col-6">
                    <strong>Version:</strong><br>
                    <span class="text-muted">v${this.currentConfig.version}</span>
                </div>
                <div class="col-6">
                    <strong>Modified:</strong><br>
                    <span class="text-muted">${new Date(this.currentConfig.modified_at).toLocaleString()}</span>
                </div>
                <div class="col-6">
                    <strong>Status:</strong><br>
                    ${this.currentConfig.is_valid ? 
                        '<span class="badge bg-success">Valid</span>' : 
                        '<span class="badge bg-danger">Invalid</span>'
                    }
                </div>
            </div>
        `;
        
        document.getElementById('configInfoCard').style.display = 'block';
    }

    changeEditorMode(mode) {
        if (mode === 'yaml') {
            this.editor.setOption('mode', 'yaml');
        } else if (mode === 'json') {
            this.editor.setOption('mode', { name: 'javascript', json: true });
        }
    }

    changeEditorTheme(theme) {
        this.editor.setOption('theme', theme);
    }

    scheduleValidation() {
        if (this.validationTimer) {
            clearTimeout(this.validationTimer);
        }
        
        this.validationTimer = setTimeout(() => {
            this.validateConfiguration(false);
        }, 1000);
    }

    scheduleAutoSave() {
        if (this.autoSaveTimer) {
            clearTimeout(this.autoSaveTimer);
        }
        
        this.autoSaveTimer = setTimeout(() => {
            this.autoSaveConfiguration();
        }, 5000);
    }

    async validateConfiguration(showResults = true) {
        if (!this.currentConfig) return;
        
        try {
            const content = this.editor.getValue();
            const format = document.querySelector('input[name="editorMode"]:checked').value;
            
            let data;
            if (format === 'yaml') {
                data = jsyaml.load(content);
            } else {
                data = JSON.parse(content);
            }
            
            const response = await fetch(`/api/admin/configs/${this.currentConfig.name}/validate`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ data, format })
            });
            
            const result = await response.json();
            
            if (showResults) {
                this.showValidationResults(result);
            }
            
            return result.valid;
            
        } catch (error) {
            if (showResults) {
                this.showValidationResults({
                    valid: false,
                    errors: [error.message]
                });
            }
            return false;
        }
    }

    showValidationResults(result) {
        const validationResults = document.getElementById('validationResults');
        const validationContent = document.getElementById('validationContent');
        
        if (result.valid) {
            validationContent.innerHTML = `
                <div class="alert alert-success mb-0">
                    <i class="fas fa-check-circle"></i>
                    Configuration is valid
                </div>
            `;
        } else {
            const errors = result.errors || [];
            validationContent.innerHTML = `
                <div class="alert alert-danger mb-0">
                    <i class="fas fa-exclamation-triangle"></i>
                    Configuration has ${errors.length} error(s):
                    <ul class="mb-0 mt-2">
                        ${errors.map(error => `<li>${error}</li>`).join('')}
                    </ul>
                </div>
            `;
        }
        
        validationResults.style.display = 'block';
        
        // Hide after 5 seconds
        setTimeout(() => {
            validationResults.style.display = 'none';
        }, 5000);
    }

    showNotification(message, type = 'info') {
        if (window.PlexiUI) {
            window.PlexiUI.showNotification(message, type);
        } else {
            alert(message);
        }
    }
}

// Initialize when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
    window.configEditor = new EnhancedConfigEditor();
});
