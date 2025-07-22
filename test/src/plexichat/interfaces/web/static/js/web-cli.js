/**
 * Enhanced Chat API Web CLI
 * Interactive command-line interface in the browser
 */

class WebCLI {
    constructor() {
        this.commandHistory = [];
        this.historyIndex = -1;
        this.currentCommand = '';
        this.isExecuting = false;
        this.suggestions = [];
        this.selectedSuggestion = -1;
        
        this.initializeElements();
        this.setupEventListeners();
        this.loadCommandHistory();
        this.setupAutocompletion();
        
        // Focus input on load
        this.commandInput.focus();
    }
    
    initializeElements() {
        this.output = document.getElementById('output');
        this.commandInput = document.getElementById('commandInput');
        this.suggestionsContainer = document.getElementById('suggestions');
        this.historyContainer = document.getElementById('commandHistory');
        this.connectionStatus = document.getElementById('connectionStatus');
        this.connectionText = document.getElementById('connectionText');
        this.sidebar = document.getElementById('sidebar');
    }
    
    setupEventListeners() {
        // Command input handling
        this.commandInput.addEventListener('keydown', (e) => this.handleKeyDown(e));
        this.commandInput.addEventListener('input', (e) => this.handleInput(e));
        this.commandInput.addEventListener('blur', () => this.hideSuggestions());
        
        // Click outside to hide suggestions
        document.addEventListener('click', (e) => {
            if (!this.suggestionsContainer.contains(e.target) && e.target !== this.commandInput) {
                this.hideSuggestions();
            }
        });
        
        // Auto-scroll output
        this.output.addEventListener('DOMNodeInserted', () => {
            this.output.scrollTop = this.output.scrollHeight;
        });
    }
    
    handleKeyDown(e) {
        switch (e.key) {
            case 'Enter':
                e.preventDefault();
                this.executeCurrentCommand();
                break;
                
            case 'Tab':
                e.preventDefault();
                this.handleTabCompletion();
                break;
                
            case 'ArrowUp':
                e.preventDefault();
                if (this.suggestions.length > 0) {
                    this.navigateSuggestions(-1);
                } else {
                    this.navigateHistory(-1);
                }
                break;
                
            case 'ArrowDown':
                e.preventDefault();
                if (this.suggestions.length > 0) {
                    this.navigateSuggestions(1);
                } else {
                    this.navigateHistory(1);
                }
                break;
                
            case 'Escape':
                this.hideSuggestions();
                this.commandInput.value = '';
                break;
                
            case 'c':
                if (e.ctrlKey) {
                    this.interruptCommand();
                }
                break;
        }
    }
    
    handleInput(e) {
        const value = e.target.value;
        this.updateAutocompletion(value);
    }
    
    executeCurrentCommand() {
        const command = this.commandInput.value.trim();
        if (!command || this.isExecuting) return;
        
        this.addToHistory(command);
        this.displayCommand(command);
        this.commandInput.value = '';
        this.hideSuggestions();
        
        this.executeCommand(command);
    }
    
    async executeCommand(command) {
        this.isExecuting = true;
        this.showLoading();
        
        try {
            const response = await fetch('/api/v1/cli/execute', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${this.getAuthToken()}`
                },
                body: JSON.stringify({ command: command })
            });
            
            const result = await response.json();
            
            if (result.success) {
                this.displayOutput(result.output, result.output_type || 'info');
            } else {
                this.displayOutput(result.error || 'Command failed', 'error');
            }
            
        } catch (error) {
            this.displayOutput(`Error executing command: ${error.message}`, 'error');
        } finally {
            this.isExecuting = false;
            this.hideLoading();
        }
    }
    
    displayCommand(command) {
        const line = document.createElement('div');
        line.className = 'output-line output-command';
        line.innerHTML = `<span class="output-prompt">chatapi@web:~$</span> ${this.escapeHtml(command)}`;
        this.output.appendChild(line);
        this.scrollToBottom();
    }
    
    displayOutput(text, type = 'info') {
        const lines = text.split('\n');
        lines.forEach(line => {
            const lineElement = document.createElement('div');
            lineElement.className = `output-line output-${type}`;
            lineElement.textContent = line;
            this.output.appendChild(lineElement);
        });
        this.scrollToBottom();
    }
    
    showLoading() {
        const line = document.createElement('div');
        line.className = 'output-line';
        line.innerHTML = '<span class="loading-spinner"></span>Executing command...';
        line.id = 'loading-indicator';
        this.output.appendChild(line);
        this.scrollToBottom();
    }
    
    hideLoading() {
        const loading = document.getElementById('loading-indicator');
        if (loading) {
            loading.remove();
        }
    }
    
    addToHistory(command) {
        // Avoid duplicates
        const lastCommand = this.commandHistory[this.commandHistory.length - 1];
        if (lastCommand !== command) {
            this.commandHistory.push(command);
            
            // Limit history size
            if (this.commandHistory.length > 100) {
                this.commandHistory.shift();
            }
            
            this.saveCommandHistory();
            this.updateHistoryDisplay();
        }
        
        this.historyIndex = this.commandHistory.length;
    }
    
    navigateHistory(direction) {
        if (this.commandHistory.length === 0) return;
        
        this.historyIndex += direction;
        
        if (this.historyIndex < 0) {
            this.historyIndex = 0;
        } else if (this.historyIndex >= this.commandHistory.length) {
            this.historyIndex = this.commandHistory.length;
            this.commandInput.value = this.currentCommand;
            return;
        }
        
        this.commandInput.value = this.commandHistory[this.historyIndex];
    }
    
    updateHistoryDisplay() {
        const historyItems = this.commandHistory.slice(-10).reverse();
        
        this.historyContainer.innerHTML = '<div style="color: #8b949e; font-size: 11px; margin-bottom: 5px;">Command History</div>';
        
        historyItems.forEach(command => {
            const item = document.createElement('div');
            item.className = 'history-item';
            item.textContent = command;
            item.onclick = () => {
                this.commandInput.value = command;
                this.commandInput.focus();
            };
            this.historyContainer.appendChild(item);
        });
    }
    
    setupAutocompletion() {
        this.commands = [
            // System commands
            { name: 'status', description: 'Show system status' },
            { name: 'info', description: 'Show system information' },
            { name: 'version', description: 'Show version information' },
            { name: 'restart', description: 'Restart the application' },
            { name: 'shutdown', description: 'Shutdown the application' },
            
            // Database commands
            { name: 'db_status', description: 'Show database status' },
            { name: 'db_stats', description: 'Show database statistics' },
            { name: 'db_migrate', description: 'Run database migrations' },
            { name: 'db_backup', description: 'Create database backup' },
            
            // User commands
            { name: 'list_users', description: 'List all users' },
            { name: 'user_info', description: 'Show user information' },
            { name: 'user_stats', description: 'Show user statistics' },
            { name: 'create_admin', description: 'Create admin user' },
            
            // Message commands
            { name: 'list_messages', description: 'List recent messages' },
            { name: 'message_stats', description: 'Show message statistics' },
            { name: 'cleanup_messages', description: 'Clean up old messages' },
            
            // Testing commands
            { name: 'test', description: 'Run comprehensive tests' },
            { name: 'test_health', description: 'Run quick health check' },
            { name: 'test_suites', description: 'List available test suites' },
            { name: 'performance', description: 'Show performance metrics' },
            
            // Analytics commands
            { name: 'analytics', description: 'Show analytics dashboard' },
            { name: 'analytics --detailed', description: 'Show detailed analytics' },
            
            // Security commands
            { name: 'security scan', description: 'Run security scan' },
            { name: 'security status', description: 'Show security status' },
            { name: 'security logs', description: 'Show security events' },
            { name: 'security config', description: 'Show security configuration' },
            
            // Backup commands
            { name: 'backup create', description: 'Create new backup' },
            { name: 'backup list', description: 'List available backups' },
            { name: 'backup status', description: 'Show backup system status' },
            { name: 'backup restore', description: 'Restore from backup' },
            
            // Deployment commands
            { name: 'deploy status', description: 'Show deployment status' },
            { name: 'deploy config', description: 'Show deployment configuration' },
            { name: 'deploy docker', description: 'Docker deployment info' },
            { name: 'deploy k8s', description: 'Kubernetes deployment info' },
            { name: 'deploy scale', description: 'Scale deployment' },
            
            // Configuration commands
            { name: 'config show', description: 'Show current configuration' },
            { name: 'config get', description: 'Get configuration value' },
            { name: 'config validate', description: 'Validate configuration' },
            { name: 'config optimize', description: 'Optimize configuration' },
            
            // Monitoring commands
            { name: 'monitor start', description: 'Start monitoring' },
            { name: 'monitor stop', description: 'Stop monitoring' },
            { name: 'monitor status', description: 'Show monitoring status' },
            { name: 'monitor logs', description: 'Show recent logs' },
            { name: 'monitor alerts', description: 'Show system alerts' },
            
            // Utility commands
            { name: 'utils cleanup', description: 'Clean up temporary files' },
            { name: 'utils export', description: 'Export system data' },
            { name: 'utils import', description: 'Import system data' },
            { name: 'utils validate', description: 'Validate system integrity' },
            
            // Help commands
            { name: 'help', description: 'Show all commands' },
            { name: 'help_all', description: 'Show comprehensive help' },
            { name: 'examples', description: 'Show command examples' },
            
            // Basic commands
            { name: 'clear', description: 'Clear screen' },
            { name: 'exit', description: 'Exit CLI' },
            { name: 'quit', description: 'Exit CLI' }
        ];
    }
    
    updateAutocompletion(input) {
        if (!input.trim()) {
            this.hideSuggestions();
            return;
        }
        
        const matches = this.commands.filter(cmd => 
            cmd.name.toLowerCase().startsWith(input.toLowerCase())
        );
        
        if (matches.length > 0) {
            this.showSuggestions(matches.slice(0, 10));
        } else {
            this.hideSuggestions();
        }
    }
    
    showSuggestions(suggestions) {
        this.suggestions = suggestions;
        this.selectedSuggestion = -1;
        
        this.suggestionsContainer.innerHTML = '';
        
        suggestions.forEach((suggestion, index) => {
            const item = document.createElement('div');
            item.className = 'suggestion-item';
            item.innerHTML = `
                <div class="suggestion-command">${suggestion.name}</div>
                <div class="suggestion-desc">${suggestion.description}</div>
            `;
            
            item.onclick = () => {
                this.commandInput.value = suggestion.name;
                this.hideSuggestions();
                this.commandInput.focus();
            };
            
            this.suggestionsContainer.appendChild(item);
        });
        
        this.suggestionsContainer.style.display = 'block';
    }
    
    hideSuggestions() {
        this.suggestionsContainer.style.display = 'none';
        this.suggestions = [];
        this.selectedSuggestion = -1;
    }
    
    navigateSuggestions(direction) {
        if (this.suggestions.length === 0) return;
        
        this.selectedSuggestion += direction;
        
        if (this.selectedSuggestion < 0) {
            this.selectedSuggestion = this.suggestions.length - 1;
        } else if (this.selectedSuggestion >= this.suggestions.length) {
            this.selectedSuggestion = 0;
        }
        
        // Update visual selection
        const items = this.suggestionsContainer.querySelectorAll('.suggestion-item');
        items.forEach((item, index) => {
            item.classList.toggle('selected', index === this.selectedSuggestion);
        });
        
        // Update input value
        this.commandInput.value = this.suggestions[this.selectedSuggestion].name;
    }
    
    handleTabCompletion() {
        if (this.suggestions.length === 1) {
            this.commandInput.value = this.suggestions[0].name;
            this.hideSuggestions();
        } else if (this.suggestions.length > 1) {
            // Show common prefix
            const commonPrefix = this.findCommonPrefix(this.suggestions.map(s => s.name));
            if (commonPrefix.length > this.commandInput.value.length) {
                this.commandInput.value = commonPrefix;
            }
        }
    }
    
    findCommonPrefix(strings) {
        if (strings.length === 0) return '';
        
        let prefix = strings[0];
        for (let i = 1; i < strings.length; i++) {
            while (strings[i].indexOf(prefix) !== 0) {
                prefix = prefix.substring(0, prefix.length - 1);
                if (prefix === '') return '';
            }
        }
        return prefix;
    }
    
    interruptCommand() {
        if (this.isExecuting) {
            this.displayOutput('^C', 'warning');
            this.displayOutput('Command interrupted', 'warning');
            this.isExecuting = false;
            this.hideLoading();
        }
    }
    
    scrollToBottom() {
        this.output.scrollTop = this.output.scrollHeight;
    }
    
    escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }
    
    getAuthToken() {
        // Get token from localStorage or session
        return localStorage.getItem('authToken') || sessionStorage.getItem('authToken') || '';
    }
    
    saveCommandHistory() {
        try {
            localStorage.setItem('cliHistory', JSON.stringify(this.commandHistory));
        } catch (e) {
            console.warn('Failed to save command history:', e);
        }
    }
    
    loadCommandHistory() {
        try {
            const saved = localStorage.getItem('cliHistory');
            if (saved) {
                this.commandHistory = JSON.parse(saved);
                this.updateHistoryDisplay();
            }
        } catch (e) {
            console.warn('Failed to load command history:', e);
        }
    }
}

// Global functions for HTML onclick handlers
function executeCommand(command) {
    if (window.webCLI) {
        window.webCLI.commandInput.value = command;
        window.webCLI.executeCurrentCommand();
    }
}

function clearOutput() {
    if (window.webCLI) {
        window.webCLI.output.innerHTML = `
            <div class="output-line output-info">
                <strong>Enhanced Chat API Web CLI v2.0.0</strong>
            </div>
            <div class="output-line">
                Screen cleared. Type 'help' for available commands.
            </div>
            <div class="output-line"><br></div>
        `;
    }
}

function toggleSidebar() {
    const sidebar = document.getElementById('sidebar');
    if (sidebar.style.display === 'none') {
        sidebar.style.display = 'block';
    } else {
        sidebar.style.display = 'none';
    }
}

function exportSession() {
    if (window.webCLI) {
        const output = window.webCLI.output.textContent;
        const history = window.webCLI.commandHistory;
        
        const sessionData = {
            timestamp: new Date().toISOString(),
            output: output,
            history: history
        };
        
        const blob = new Blob([JSON.stringify(sessionData, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        
        const a = document.createElement('a');
        a.href = url;
        a.download = `cli-session-${new Date().toISOString().slice(0, 19)}.json`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    }
}

// Initialize CLI when page loads
document.addEventListener('DOMContentLoaded', () => {
    window.webCLI = new WebCLI();
});
