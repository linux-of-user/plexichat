/**
 * Interactive API Documentation
 * Provides live testing capabilities and comprehensive documentation
 */

class InteractiveAPIDocs {
    constructor() {
        this.baseUrl = window.location.origin;
        this.authToken = localStorage.getItem('api_token') || '';
        this.endpoints = [];
        this.currentEndpoint = null;
        
        this.init();
    }
    
    async init() {
        await this.loadEndpoints();
        this.setupUI();
        this.bindEvents();
        this.loadTheme();
    }
    
    async loadEndpoints() {
        try {
            const response = await fetch(`${this.baseUrl}/openapi.json`);
            const openapi = await response.json();
            this.processOpenAPISpec(openapi);
        } catch (error) {
            console.error('Failed to load API specification:', error);
            this.showError('Failed to load API documentation');
        }
    }
    
    processOpenAPISpec(spec) {
        this.endpoints = [];
        
        for (const [path, methods] of Object.entries(spec.paths)) {
            for (const [method, details] of Object.entries(methods)) {
                if (typeof details === 'object' && details.operationId) {
                    this.endpoints.push({
                        id: details.operationId,
                        method: method.toUpperCase(),
                        path: path,
                        summary: details.summary || '',
                        description: details.description || '',
                        tags: details.tags || [],
                        parameters: details.parameters || [],
                        requestBody: details.requestBody || null,
                        responses: details.responses || {},
                        security: details.security || []
                    });
                }
            }
        }
        
        this.groupEndpointsByTag();
    }
    
    groupEndpointsByTag() {
        this.endpointGroups = {};
        
        this.endpoints.forEach(endpoint => {
            const tag = endpoint.tags[0] || 'General';
            if (!this.endpointGroups[tag]) {
                this.endpointGroups[tag] = [];
            }
            this.endpointGroups[tag].push(endpoint);
        });
    }
    
    setupUI() {
        this.createHeader();
        this.createSidebar();
        this.createMainContent();
        this.createTestPanel();
    }
    
    createHeader() {
        const header = document.createElement('header');
        header.className = 'api-docs-header';
        header.innerHTML = `
            <div class="header-content">
                <h1>🚀 Enhanced Chat API Documentation</h1>
                <div class="header-controls">
                    <div class="auth-section">
                        <input type="password" id="auth-token" placeholder="API Token" 
                               value="${this.authToken}" class="auth-input">
                        <button id="save-token" class="btn btn-primary">Save Token</button>
                    </div>
                    <button id="theme-toggle" class="btn btn-secondary">🌙</button>
                </div>
            </div>
        `;
        
        document.body.appendChild(header);
    }
    
    createSidebar() {
        const sidebar = document.createElement('aside');
        sidebar.className = 'api-docs-sidebar';
        sidebar.innerHTML = `
            <div class="sidebar-content">
                <div class="search-section">
                    <input type="text" id="endpoint-search" placeholder="Search endpoints..." class="search-input">
                </div>
                <nav class="endpoint-nav" id="endpoint-nav">
                    ${this.renderEndpointGroups()}
                </nav>
            </div>
        `;
        
        document.body.appendChild(sidebar);
    }
    
    renderEndpointGroups() {
        let html = '';
        
        for (const [tag, endpoints] of Object.entries(this.endpointGroups)) {
            html += `
                <div class="endpoint-group">
                    <h3 class="group-title">${tag}</h3>
                    <ul class="endpoint-list">
                        ${endpoints.map(endpoint => `
                            <li class="endpoint-item" data-endpoint-id="${endpoint.id}">
                                <span class="method method-${endpoint.method.toLowerCase()}">${endpoint.method}</span>
                                <span class="path">${endpoint.path}</span>
                                <span class="summary">${endpoint.summary}</span>
                            </li>
                        `).join('')}
                    </ul>
                </div>
            `;
        }
        
        return html;
    }
    
    createMainContent() {
        const main = document.createElement('main');
        main.className = 'api-docs-main';
        main.innerHTML = `
            <div class="main-content">
                <div class="welcome-section" id="welcome-section">
                    <h2>Welcome to PlexiChat API</h2>
                    <p>Select an endpoint from the sidebar to view documentation and test it live.</p>

                    <div class="quick-start">
                        <h3>Quick Start</h3>
                        <ol>
                            <li>Get your API token from the admin panel</li>
                            <li>Enter your token in the header above</li>
                            <li>Select an endpoint to view documentation</li>
                            <li>Use the test panel to make live API calls</li>
                        </ol>
                    </div>
                    
                    <div class="features-grid">
                        <div class="feature-card">
                            <h4>🔐 Authentication</h4>
                            <p>Secure JWT-based authentication with role-based access control</p>
                        </div>
                        <div class="feature-card">
                            <h4>💬 Real-time Messaging</h4>
                            <p>WebSocket-based real-time communication with channels and threads</p>
                        </div>
                        <div class="feature-card">
                            <h4>📁 File Management</h4>
                            <p>Upload, share, and manage files with advanced security features</p>
                        </div>
                        <div class="feature-card">
                            <h4>💾 Distributed Backups</h4>
                            <p>Intelligent backup system with encrypted distributed storage</p>
                        </div>
                    </div>
                </div>
                
                <div class="endpoint-details" id="endpoint-details" style="display: none;">
                    <!-- Endpoint details will be rendered here -->
                </div>
            </div>
        `;
        
        document.body.appendChild(main);
    }
    
    createTestPanel() {
        const testPanel = document.createElement('div');
        testPanel.className = 'test-panel';
        testPanel.innerHTML = `
            <div class="test-panel-header">
                <h3>🧪 Live API Testing</h3>
                <button id="close-test-panel" class="btn btn-secondary">×</button>
            </div>
            <div class="test-panel-content" id="test-panel-content">
                <!-- Test interface will be rendered here -->
            </div>
        `;
        
        document.body.appendChild(testPanel);
    }
    
    bindEvents() {
        // Endpoint selection
        document.addEventListener('click', (e) => {
            if (e.target.closest('.endpoint-item')) {
                const endpointId = e.target.closest('.endpoint-item').dataset.endpointId;
                this.showEndpointDetails(endpointId);
            }
        });
        
        // Auth token management
        document.getElementById('save-token').addEventListener('click', () => {
            this.authToken = document.getElementById('auth-token').value;
            localStorage.setItem('api_token', this.authToken);
            this.showSuccess('API token saved');
        });
        
        // Theme toggle
        document.getElementById('theme-toggle').addEventListener('click', () => {
            this.toggleTheme();
        });
        
        // Search functionality
        document.getElementById('endpoint-search').addEventListener('input', (e) => {
            this.filterEndpoints(e.target.value);
        });
        
        // Close test panel
        document.getElementById('close-test-panel').addEventListener('click', () => {
            document.querySelector('.test-panel').classList.remove('active');
        });
    }
    
    showEndpointDetails(endpointId) {
        const endpoint = this.endpoints.find(e => e.id === endpointId);
        if (!endpoint) return;
        
        this.currentEndpoint = endpoint;
        
        // Hide welcome section
        document.getElementById('welcome-section').style.display = 'none';
        
        // Show endpoint details
        const detailsContainer = document.getElementById('endpoint-details');
        detailsContainer.style.display = 'block';
        detailsContainer.innerHTML = this.renderEndpointDetails(endpoint);
        
        // Update active state in sidebar
        document.querySelectorAll('.endpoint-item').forEach(item => {
            item.classList.remove('active');
        });
        document.querySelector(`[data-endpoint-id="${endpointId}"]`).classList.add('active');
    }
    
    renderEndpointDetails(endpoint) {
        return `
            <div class="endpoint-header">
                <div class="endpoint-title">
                    <span class="method method-${endpoint.method.toLowerCase()}">${endpoint.method}</span>
                    <code class="path">${endpoint.path}</code>
                </div>
                <button class="btn btn-primary test-button" onclick="apiDocs.openTestPanel()">
                    🧪 Test This Endpoint
                </button>
            </div>
            
            <div class="endpoint-description">
                <h3>Description</h3>
                <p>${endpoint.description || endpoint.summary}</p>
            </div>
            
            ${this.renderParameters(endpoint)}
            ${this.renderRequestBody(endpoint)}
            ${this.renderResponses(endpoint)}
            ${this.renderExamples(endpoint)}
        `;
    }
    
    renderParameters(endpoint) {
        if (!endpoint.parameters || endpoint.parameters.length === 0) {
            return '';
        }
        
        return `
            <div class="parameters-section">
                <h3>Parameters</h3>
                <table class="params-table">
                    <thead>
                        <tr>
                            <th>Name</th>
                            <th>Type</th>
                            <th>Location</th>
                            <th>Required</th>
                            <th>Description</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${endpoint.parameters.map(param => `
                            <tr>
                                <td><code>${param.name}</code></td>
                                <td>${param.schema?.type || 'string'}</td>
                                <td>${param.in}</td>
                                <td>${param.required ? '✅' : '❌'}</td>
                                <td>${param.description || ''}</td>
                            </tr>
                        `).join('')}
                    </tbody>
                </table>
            </div>
        `;
    }
    
    renderRequestBody(endpoint) {
        if (!endpoint.requestBody) {
            return '';
        }
        
        const content = endpoint.requestBody.content;
        const jsonContent = content['application/json'];
        
        if (!jsonContent) {
            return '';
        }
        
        return `
            <div class="request-body-section">
                <h3>Request Body</h3>
                <p>${endpoint.requestBody.description || ''}</p>
                <div class="schema-example">
                    <h4>Schema</h4>
                    <pre><code>${JSON.stringify(jsonContent.schema, null, 2)}</code></pre>
                </div>
            </div>
        `;
    }
    
    renderResponses(endpoint) {
        return `
            <div class="responses-section">
                <h3>Responses</h3>
                ${Object.entries(endpoint.responses).map(([code, response]) => `
                    <div class="response-item">
                        <h4 class="response-code status-${code}">${code}</h4>
                        <p>${response.description}</p>
                        ${response.content ? `
                            <div class="response-schema">
                                <h5>Response Schema</h5>
                                <pre><code>${JSON.stringify(response.content['application/json']?.schema || {}, null, 2)}</code></pre>
                            </div>
                        ` : ''}
                    </div>
                `).join('')}
            </div>
        `;
    }
    
    renderExamples(endpoint) {
        const curlExample = this.generateCurlExample(endpoint);
        
        return `
            <div class="examples-section">
                <h3>Examples</h3>
                
                <div class="example-tabs">
                    <button class="tab-button active" data-tab="curl">cURL</button>
                    <button class="tab-button" data-tab="javascript">JavaScript</button>
                    <button class="tab-button" data-tab="python">Python</button>
                </div>
                
                <div class="example-content">
                    <div class="tab-panel active" data-tab="curl">
                        <pre><code>${curlExample}</code></pre>
                        <button class="copy-button" onclick="apiDocs.copyToClipboard(this)">📋 Copy</button>
                    </div>
                    
                    <div class="tab-panel" data-tab="javascript">
                        <pre><code>${this.generateJavaScriptExample(endpoint)}</code></pre>
                        <button class="copy-button" onclick="apiDocs.copyToClipboard(this)">📋 Copy</button>
                    </div>
                    
                    <div class="tab-panel" data-tab="python">
                        <pre><code>${this.generatePythonExample(endpoint)}</code></pre>
                        <button class="copy-button" onclick="apiDocs.copyToClipboard(this)">📋 Copy</button>
                    </div>
                </div>
            </div>
        `;
    }
    
    generateCurlExample(endpoint) {
        let curl = `curl -X ${endpoint.method} "${this.baseUrl}${endpoint.path}"`;
        
        if (this.authToken) {
            curl += ` \\\n  -H "Authorization: Bearer ${this.authToken}"`;
        }
        
        curl += ` \\\n  -H "Content-Type: application/json"`;
        
        if (endpoint.requestBody) {
            curl += ` \\\n  -d '{
    "example": "data"
  }'`;
        }
        
        return curl;
    }
    
    generateJavaScriptExample(endpoint) {
        return `const response = await fetch('${this.baseUrl}${endpoint.path}', {
  method: '${endpoint.method}',
  headers: {
    'Content-Type': 'application/json',${this.authToken ? `
    'Authorization': 'Bearer ${this.authToken}',` : ''}
  },${endpoint.requestBody ? `
  body: JSON.stringify({
    // Request data here
  })` : ''}
});

const data = await response.json();
console.log(data);`;
    }
    
    generatePythonExample(endpoint) {
        return `import requests

url = "${this.baseUrl}${endpoint.path}"
headers = {
    "Content-Type": "application/json",${this.authToken ? `
    "Authorization": "Bearer ${this.authToken}",` : ''}
}

${endpoint.requestBody ? `data = {
    # Request data here
}

response = requests.${endpoint.method.toLowerCase()}(url, headers=headers, json=data)` : `response = requests.${endpoint.method.toLowerCase()}(url, headers=headers)`}
print(response.json())`;
    }
    
    openTestPanel() {
        if (!this.currentEndpoint) return;
        
        const testPanel = document.querySelector('.test-panel');
        testPanel.classList.add('active');
        
        const content = document.getElementById('test-panel-content');
        content.innerHTML = this.renderTestInterface(this.currentEndpoint);
        
        this.bindTestEvents();
    }
    
    renderTestInterface(endpoint) {
        return `
            <div class="test-interface">
                <div class="test-header">
                    <span class="method method-${endpoint.method.toLowerCase()}">${endpoint.method}</span>
                    <code class="path">${endpoint.path}</code>
                </div>
                
                ${this.renderTestParameters(endpoint)}
                ${this.renderTestRequestBody(endpoint)}
                
                <div class="test-actions">
                    <button id="send-request" class="btn btn-primary">🚀 Send Request</button>
                    <button id="clear-form" class="btn btn-secondary">🗑️ Clear</button>
                </div>
                
                <div class="test-response" id="test-response">
                    <!-- Response will appear here -->
                </div>
            </div>
        `;
    }
    
    renderTestParameters(endpoint) {
        if (!endpoint.parameters || endpoint.parameters.length === 0) {
            return '';
        }
        
        return `
            <div class="test-parameters">
                <h4>Parameters</h4>
                ${endpoint.parameters.map(param => `
                    <div class="param-input">
                        <label for="param-${param.name}">
                            ${param.name} ${param.required ? '*' : ''}
                            <span class="param-type">(${param.schema?.type || 'string'})</span>
                        </label>
                        <input type="text" id="param-${param.name}" 
                               placeholder="${param.description || ''}"
                               ${param.required ? 'required' : ''}>
                    </div>
                `).join('')}
            </div>
        `;
    }
    
    renderTestRequestBody(endpoint) {
        if (!endpoint.requestBody) {
            return '';
        }
        
        return `
            <div class="test-request-body">
                <h4>Request Body</h4>
                <textarea id="request-body" rows="10" placeholder="Enter JSON request body">
{
  "example": "data"
}</textarea>
            </div>
        `;
    }
    
    bindTestEvents() {
        document.getElementById('send-request').addEventListener('click', () => {
            this.sendTestRequest();
        });
        
        document.getElementById('clear-form').addEventListener('click', () => {
            this.clearTestForm();
        });
        
        // Tab switching for examples
        document.addEventListener('click', (e) => {
            if (e.target.classList.contains('tab-button')) {
                this.switchTab(e.target.dataset.tab);
            }
        });
    }
    
    async sendTestRequest() {
        if (!this.currentEndpoint) return;
        
        const responseContainer = document.getElementById('test-response');
        responseContainer.innerHTML = '<div class="loading">Sending request...</div>';
        
        try {
            const url = this.buildRequestUrl();
            const options = this.buildRequestOptions();
            
            const startTime = Date.now();
            const response = await fetch(url, options);
            const endTime = Date.now();
            
            const responseData = await response.json();
            
            this.displayTestResponse(response, responseData, endTime - startTime);
            
        } catch (error) {
            this.displayTestError(error);
        }
    }
    
    buildRequestUrl() {
        let url = `${this.baseUrl}${this.currentEndpoint.path}`;
        
        // Replace path parameters
        const pathParams = this.currentEndpoint.parameters?.filter(p => p.in === 'path') || [];
        pathParams.forEach(param => {
            const value = document.getElementById(`param-${param.name}`)?.value || '';
            url = url.replace(`{${param.name}}`, encodeURIComponent(value));
        });
        
        // Add query parameters
        const queryParams = this.currentEndpoint.parameters?.filter(p => p.in === 'query') || [];
        const queryString = queryParams
            .map(param => {
                const value = document.getElementById(`param-${param.name}`)?.value;
                return value ? `${param.name}=${encodeURIComponent(value)}` : null;
            })
            .filter(Boolean)
            .join('&');
        
        if (queryString) {
            url += `?${queryString}`;
        }
        
        return url;
    }
    
    buildRequestOptions() {
        const options = {
            method: this.currentEndpoint.method,
            headers: {
                'Content-Type': 'application/json'
            }
        };
        
        if (this.authToken) {
            options.headers['Authorization'] = `Bearer ${this.authToken}`;
        }
        
        // Add header parameters
        const headerParams = this.currentEndpoint.parameters?.filter(p => p.in === 'header') || [];
        headerParams.forEach(param => {
            const value = document.getElementById(`param-${param.name}`)?.value;
            if (value) {
                options.headers[param.name] = value;
            }
        });
        
        // Add request body
        if (this.currentEndpoint.requestBody) {
            const bodyText = document.getElementById('request-body')?.value;
            if (bodyText) {
                try {
                    options.body = JSON.stringify(JSON.parse(bodyText));
                } catch (error) {
                    throw new Error('Invalid JSON in request body');
                }
            }
        }
        
        return options;
    }
    
    displayTestResponse(response, data, duration) {
        const responseContainer = document.getElementById('test-response');
        
        const statusClass = response.ok ? 'success' : 'error';
        
        responseContainer.innerHTML = `
            <div class="response-header">
                <span class="status ${statusClass}">${response.status} ${response.statusText}</span>
                <span class="duration">${duration}ms</span>
            </div>
            
            <div class="response-headers">
                <h5>Response Headers</h5>
                <pre><code>${Array.from(response.headers.entries())
                    .map(([key, value]) => `${key}: ${value}`)
                    .join('\n')}</code></pre>
            </div>
            
            <div class="response-body">
                <h5>Response Body</h5>
                <pre><code>${JSON.stringify(data, null, 2)}</code></pre>
            </div>
        `;
    }
    
    displayTestError(error) {
        const responseContainer = document.getElementById('test-response');
        responseContainer.innerHTML = `
            <div class="response-error">
                <h5>Error</h5>
                <p>${error.message}</p>
            </div>
        `;
    }
    
    clearTestForm() {
        document.querySelectorAll('.test-interface input, .test-interface textarea').forEach(input => {
            input.value = '';
        });
        
        document.getElementById('test-response').innerHTML = '';
    }
    
    switchTab(tabName) {
        // Update tab buttons
        document.querySelectorAll('.tab-button').forEach(btn => {
            btn.classList.remove('active');
        });
        document.querySelector(`[data-tab="${tabName}"]`).classList.add('active');
        
        // Update tab panels
        document.querySelectorAll('.tab-panel').forEach(panel => {
            panel.classList.remove('active');
        });
        document.querySelector(`.tab-panel[data-tab="${tabName}"]`).classList.add('active');
    }
    
    filterEndpoints(query) {
        const items = document.querySelectorAll('.endpoint-item');
        
        items.forEach(item => {
            const text = item.textContent.toLowerCase();
            const matches = text.includes(query.toLowerCase());
            item.style.display = matches ? 'block' : 'none';
        });
    }
    
    copyToClipboard(button) {
        const code = button.previousElementSibling.textContent;
        navigator.clipboard.writeText(code).then(() => {
            button.textContent = '✅ Copied!';
            setTimeout(() => {
                button.textContent = '📋 Copy';
            }, 2000);
        });
    }
    
    toggleTheme() {
        document.body.classList.toggle('dark-theme');
        const isDark = document.body.classList.contains('dark-theme');
        localStorage.setItem('theme', isDark ? 'dark' : 'light');
        
        const themeButton = document.getElementById('theme-toggle');
        themeButton.textContent = isDark ? '☀️' : '🌙';
    }
    
    loadTheme() {
        const savedTheme = localStorage.getItem('theme');
        if (savedTheme === 'dark') {
            document.body.classList.add('dark-theme');
            document.getElementById('theme-toggle').textContent = '☀️';
        }
    }
    
    showSuccess(message) {
        this.showNotification(message, 'success');
    }
    
    showError(message) {
        this.showNotification(message, 'error');
    }
    
    showNotification(message, type) {
        const notification = document.createElement('div');
        notification.className = `notification ${type}`;
        notification.textContent = message;
        
        document.body.appendChild(notification);
        
        setTimeout(() => {
            notification.classList.add('show');
        }, 100);
        
        setTimeout(() => {
            notification.classList.remove('show');
            setTimeout(() => {
                document.body.removeChild(notification);
            }, 300);
        }, 3000);
    }
}

// Initialize when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    window.apiDocs = new InteractiveAPIDocs();
});

// Export for module usage
if (typeof module !== 'undefined' && module.exports) {
    module.exports = InteractiveAPIDocs;
}
