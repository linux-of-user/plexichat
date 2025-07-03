/**
 * Enhanced Terminal Interface with WebSocket support
 * Provides real-time log streaming and CLI functionality
 */

class TerminalInterface {
    constructor() {
        this.logSocket = null;
        this.cliSocket = null;
        this.isConnected = false;
        this.logsPaused = false;
        this.commandHistory = [];
        this.historyIndex = -1;
        this.currentFilter = '';
        
        this.initializeElements();
        this.setupEventListeners();
        this.connect();
        this.startClock();
    }

    initializeElements() {
        // Main elements
        this.logsContent = document.getElementById('logsContent');
        this.terminalContent = document.getElementById('terminalContent');
        this.commandInput = document.getElementById('commandInput');
        this.sendBtn = document.getElementById('sendBtn');
        
        // Status elements
        this.serverStatus = document.getElementById('serverStatus');
        this.serverStatusText = document.getElementById('serverStatusText');
        this.terminalStatus = document.getElementById('terminalStatus');
        this.connectionCount = document.getElementById('connectionCount');
        this.currentTime = document.getElementById('currentTime');
        
        // Control elements
        this.clearLogsBtn = document.getElementById('clearLogsBtn');
        this.pauseLogsBtn = document.getElementById('pauseLogsBtn');
        this.clearTerminalBtn = document.getElementById('clearTerminalBtn');
        this.historyBtn = document.getElementById('historyBtn');
        this.logLevelFilter = document.getElementById('logLevelFilter');
        this.commandHistory = document.getElementById('commandHistory');
    }

    setupEventListeners() {
        // Command input
        this.commandInput.addEventListener('keydown', (e) => {
            if (e.key === 'Enter') {
                this.sendCommand();
            } else if (e.key === 'ArrowUp') {
                e.preventDefault();
                this.navigateHistory(-1);
            } else if (e.key === 'ArrowDown') {
                e.preventDefault();
                this.navigateHistory(1);
            } else if (e.key === 'Tab') {
                e.preventDefault();
                this.autoComplete();
            }
        });

        this.sendBtn.addEventListener('click', () => this.sendCommand());

        // Control buttons
        this.clearLogsBtn.addEventListener('click', () => this.clearLogs());
        this.pauseLogsBtn.addEventListener('click', () => this.toggleLogsPause());
        this.clearTerminalBtn.addEventListener('click', () => this.clearTerminal());
        this.historyBtn.addEventListener('click', () => this.toggleCommandHistory());

        // Log level filter
        this.logLevelFilter.addEventListener('change', (e) => {
            this.currentFilter = e.target.value;
            this.filterLogs();
        });

        // Window events
        window.addEventListener('beforeunload', () => {
            this.disconnect();
        });
    }

    async connect() {
        try {
            // Get authentication token (in real app, this would be from login)
            const token = this.getAuthToken();
            
            if (!token) {
                this.showError('Authentication required. Please login first.');
                return;
            }

            // Connect to log stream
            await this.connectLogStream(token);
            
            // Connect to CLI interface
            await this.connectCLI(token);
            
        } catch (error) {
            console.error('Connection failed:', error);
            this.showError('Failed to connect to server');
        }
    }

    async connectLogStream(token) {
        const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        const wsUrl = `${protocol}//${window.location.host}/ws/logs?token=${token}`;
        
        this.logSocket = new WebSocket(wsUrl);
        
        this.logSocket.onopen = () => {
            console.log('Log stream connected');
            this.updateServerStatus(true);
        };
        
        this.logSocket.onmessage = (event) => {
            if (!this.logsPaused) {
                const logData = JSON.parse(event.data);
                this.displayLogEntry(logData);
            }
        };
        
        this.logSocket.onclose = () => {
            console.log('Log stream disconnected');
            this.updateServerStatus(false);
            // Attempt reconnection
            setTimeout(() => this.connectLogStream(token), 5000);
        };
        
        this.logSocket.onerror = (error) => {
            console.error('Log stream error:', error);
            this.showError('Log stream connection error');
        };
    }

    async connectCLI(token) {
        const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        const wsUrl = `${protocol}//${window.location.host}/ws/cli?token=${token}`;
        
        this.cliSocket = new WebSocket(wsUrl);
        
        this.cliSocket.onopen = () => {
            console.log('CLI connected');
            this.updateTerminalStatus('connected');
            this.commandInput.disabled = false;
            this.sendBtn.disabled = false;
        };
        
        this.cliSocket.onmessage = (event) => {
            const response = JSON.parse(event.data);
            this.handleCLIResponse(response);
        };
        
        this.cliSocket.onclose = () => {
            console.log('CLI disconnected');
            this.updateTerminalStatus('disconnected');
            this.commandInput.disabled = true;
            this.sendBtn.disabled = true;
            // Attempt reconnection
            setTimeout(() => this.connectCLI(token), 5000);
        };
        
        this.cliSocket.onerror = (error) => {
            console.error('CLI error:', error);
            this.showError('CLI connection error');
        };
    }

    getAuthToken() {
        // In a real application, this would get the token from localStorage, cookies, or session
        // For demo purposes, we'll use a placeholder
        return localStorage.getItem('auth_token') || 'demo_token';
    }

    displayLogEntry(logData) {
        if (logData.type === 'heartbeat') {
            return; // Skip heartbeat messages
        }

        const logEntry = document.createElement('div');
        logEntry.className = 'log-entry new';
        
        const timestamp = logData.timestamp ? new Date(logData.timestamp).toLocaleTimeString() : '';
        const level = logData.level || 'INFO';
        const message = logData.message || logData.formatted || '';
        
        // Apply filter
        if (this.currentFilter && level !== this.currentFilter) {
            return;
        }
        
        logEntry.innerHTML = `
            <span class="log-timestamp">[${timestamp}]</span>
            <span class="log-level-${level}">${level.padEnd(8)}</span>
            <span>${this.escapeHtml(message)}</span>
        `;
        
        this.logsContent.appendChild(logEntry);
        
        // Auto-scroll to bottom
        this.logsContent.scrollTop = this.logsContent.scrollHeight;
        
        // Limit number of log entries
        while (this.logsContent.children.length > 1000) {
            this.logsContent.removeChild(this.logsContent.firstChild);
        }
        
        // Remove animation class after animation completes
        setTimeout(() => logEntry.classList.remove('new'), 300);
    }

    handleCLIResponse(response) {
        const terminalLine = document.createElement('div');
        terminalLine.className = 'terminal-line new';
        
        if (response.type === 'output') {
            terminalLine.innerHTML = `<span class="terminal-output">${this.escapeHtml(response.data)}</span>`;
        } else if (response.type === 'result') {
            const result = response.data;
            if (result.error) {
                terminalLine.innerHTML = `<span class="terminal-error">Error: ${this.escapeHtml(result.error)}</span>`;
            } else if (result.output) {
                terminalLine.innerHTML = `<span class="terminal-output">${this.escapeHtml(result.output).replace(/\n/g, '<br>')}</span>`;
            } else if (result.action === 'clear') {
                this.clearTerminal();
                return;
            }
        } else if (response.type === 'error') {
            terminalLine.innerHTML = `<span class="terminal-error">${this.escapeHtml(response.data.error)}</span>`;
        }
        
        this.terminalContent.appendChild(terminalLine);
        this.terminalContent.scrollTop = this.terminalContent.scrollHeight;
        
        // Remove animation class
        setTimeout(() => terminalLine.classList.remove('new'), 300);
    }

    sendCommand() {
        const command = this.commandInput.value.trim();
        if (!command || !this.cliSocket || this.cliSocket.readyState !== WebSocket.OPEN) {
            return;
        }
        
        // Display command in terminal
        const commandLine = document.createElement('div');
        commandLine.className = 'terminal-line';
        commandLine.innerHTML = `
            <span class="terminal-prompt">chat-api$</span>
            <span class="terminal-command"> ${this.escapeHtml(command)}</span>
        `;
        this.terminalContent.appendChild(commandLine);
        
        // Add to history
        if (command !== this.commandHistory[this.commandHistory.length - 1]) {
            this.commandHistory.push(command);
            if (this.commandHistory.length > 100) {
                this.commandHistory.shift();
            }
        }
        this.historyIndex = this.commandHistory.length;
        
        // Send command
        this.cliSocket.send(JSON.stringify({
            type: 'command',
            command: command
        }));
        
        // Clear input
        this.commandInput.value = '';
        this.terminalContent.scrollTop = this.terminalContent.scrollHeight;
    }

    navigateHistory(direction) {
        if (this.commandHistory.length === 0) return;
        
        this.historyIndex += direction;
        
        if (this.historyIndex < 0) {
            this.historyIndex = 0;
        } else if (this.historyIndex >= this.commandHistory.length) {
            this.historyIndex = this.commandHistory.length;
            this.commandInput.value = '';
            return;
        }
        
        this.commandInput.value = this.commandHistory[this.historyIndex] || '';
    }

    autoComplete() {
        const input = this.commandInput.value;
        const commands = ['help', 'status', 'logs', 'users', 'files', 'system', 'config', 'selftest', 'restart', 'clear', 'version'];
        
        const matches = commands.filter(cmd => cmd.startsWith(input.toLowerCase()));
        if (matches.length === 1) {
            this.commandInput.value = matches[0];
        }
    }

    clearLogs() {
        this.logsContent.innerHTML = '';
    }

    clearTerminal() {
        this.terminalContent.innerHTML = '';
    }

    toggleLogsPause() {
        this.logsPaused = !this.logsPaused;
        this.pauseLogsBtn.textContent = this.logsPaused ? 'Resume' : 'Pause';
        this.pauseLogsBtn.classList.toggle('active', this.logsPaused);
    }

    toggleCommandHistory() {
        const historyDiv = document.getElementById('commandHistory');
        const isVisible = historyDiv.classList.contains('show');
        
        if (isVisible) {
            historyDiv.classList.remove('show');
        } else {
            this.updateCommandHistoryDisplay();
            historyDiv.classList.add('show');
        }
    }

    updateCommandHistoryDisplay() {
        const historyDiv = document.getElementById('commandHistory');
        historyDiv.innerHTML = '';
        
        this.commandHistory.slice(-20).reverse().forEach(cmd => {
            const item = document.createElement('div');
            item.className = 'history-item';
            item.textContent = cmd;
            item.addEventListener('click', () => {
                this.commandInput.value = cmd;
                historyDiv.classList.remove('show');
                this.commandInput.focus();
            });
            historyDiv.appendChild(item);
        });
    }

    filterLogs() {
        const logEntries = this.logsContent.querySelectorAll('.log-entry');
        logEntries.forEach(entry => {
            const levelSpan = entry.querySelector('[class^="log-level-"]');
            if (levelSpan) {
                const level = levelSpan.className.replace('log-level-', '');
                entry.style.display = (!this.currentFilter || level === this.currentFilter) ? 'block' : 'none';
            }
        });
    }

    updateServerStatus(connected) {
        this.isConnected = connected;
        this.serverStatus.classList.toggle('online', connected);
        this.serverStatusText.textContent = connected ? 'Connected' : 'Disconnected';
    }

    updateTerminalStatus(status) {
        this.terminalStatus.className = `connection-status ${status}`;
        this.terminalStatus.textContent = status.charAt(0).toUpperCase() + status.slice(1);
    }

    startClock() {
        const updateTime = () => {
            this.currentTime.textContent = new Date().toLocaleTimeString();
        };
        updateTime();
        setInterval(updateTime, 1000);
    }

    showError(message) {
        const errorLine = document.createElement('div');
        errorLine.className = 'terminal-line';
        errorLine.innerHTML = `<span class="terminal-error">Error: ${this.escapeHtml(message)}</span>`;
        this.terminalContent.appendChild(errorLine);
        this.terminalContent.scrollTop = this.terminalContent.scrollHeight;
    }

    escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    disconnect() {
        if (this.logSocket) {
            this.logSocket.close();
        }
        if (this.cliSocket) {
            this.cliSocket.close();
        }
    }
}

// Initialize terminal when page loads
document.addEventListener('DOMContentLoaded', () => {
    window.terminal = new TerminalInterface();
});

// Export for potential external use
window.TerminalInterface = TerminalInterface;
