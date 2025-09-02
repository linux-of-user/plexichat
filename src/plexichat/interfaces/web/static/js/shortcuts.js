/**
 * PlexiChat Keyboard Shortcuts Manager
 * Advanced keyboard shortcut system with platform detection and conflict resolution
 */

class KeyboardShortcutsManager {
    constructor() {
        this.shortcuts = new Map();
        this.platform = this.detectPlatform();
        this.isRecording = false;
        this.recordingCallback = null;
        this.conflicts = new Map();
        this.categories = new Map();

        // Initialize default shortcuts
        this.initializeDefaultShortcuts();

        // Setup event listeners
        this.setupEventListeners();

        // Load user preferences
        this.loadUserPreferences();

        console.log(`Keyboard shortcuts initialized for ${this.platform} platform`);
    }

    detectPlatform() {
        const userAgent = navigator.userAgent.toLowerCase();

        if (userAgent.includes('mac')) {
            return 'mac';
        } else if (userAgent.includes('win')) {
            return 'windows';
        } else if (userAgent.includes('linux')) {
            return 'linux';
        } else {
            return 'unknown';
        }
    }

    initializeDefaultShortcuts() {
        // Messaging shortcuts
        this.registerShortcut('send_message', {
            keys: ['Enter'],
            description: 'Send message',
            category: 'messaging',
            context: 'message_input'
        });

        this.registerShortcut('new_line', {
            keys: ['Shift', 'Enter'],
            description: 'New line in message',
            category: 'messaging',
            context: 'message_input'
        });

        // Navigation shortcuts
        this.registerShortcut('focus_message_input', {
            keys: this.getPlatformKey('focus_input'),
            description: 'Focus message input',
            category: 'navigation',
            global: true
        });

        this.registerShortcut('open_search', {
            keys: this.getPlatformKey('open_search'),
            description: 'Open search',
            category: 'navigation',
            global: true
        });

        this.registerShortcut('next_channel', {
            keys: ['Alt', 'ArrowDown'],
            description: 'Next channel',
            category: 'navigation',
            global: true
        });

        this.registerShortcut('previous_channel', {
            keys: ['Alt', 'ArrowUp'],
            description: 'Previous channel',
            category: 'navigation',
            global: true
        });

        // Interface shortcuts
        this.registerShortcut('toggle_sidebar', {
            keys: this.getPlatformKey('toggle_sidebar'),
            description: 'Toggle sidebar',
            category: 'interface',
            global: true
        });

        this.registerShortcut('show_shortcuts', {
            keys: this.getPlatformKey('show_shortcuts'),
            description: 'Show keyboard shortcuts',
            category: 'interface',
            global: true
        });

        this.registerShortcut('toggle_theme', {
            keys: this.getPlatformKey('toggle_theme'),
            description: 'Toggle theme',
            category: 'interface',
            global: true
        });

        // File operations
        this.registerShortcut('upload_file', {
            keys: this.getPlatformKey('upload_file'),
            description: 'Upload file',
            category: 'files',
            global: true
        });

        // User actions
        this.registerShortcut('edit_profile', {
            keys: this.getPlatformKey('edit_profile'),
            description: 'Edit profile',
            category: 'user',
            global: true
        });
    }

    getPlatformKey(action) {
        const platformKeys = {
            mac: {
                focus_input: ['Control', '/'],
                open_search: ['Control', 'k'],
                toggle_sidebar: ['Control', 'b'],
                show_shortcuts: ['Control', 'Shift', '/'],
                toggle_theme: ['Control', 'Shift', 't'],
                upload_file: ['Control', 'u'],
                edit_profile: ['Control', 'Shift', 'p']
            },
            windows: {
                focus_input: ['Control', '/'],
                open_search: ['Control', 'k'],
                toggle_sidebar: ['Control', 'b'],
                show_shortcuts: ['Control', 'Shift', '/'],
                toggle_theme: ['Control', 'Shift', 't'],
                upload_file: ['Control', 'u'],
                edit_profile: ['Control', 'Shift', 'p']
            },
            linux: {
                focus_input: ['Control', '/'],
                open_search: ['Control', 'k'],
                toggle_sidebar: ['Control', 'b'],
                show_shortcuts: ['Control', 'Shift', '/'],
                toggle_theme: ['Control', 'Shift', 't'],
                upload_file: ['Control', 'u'],
                edit_profile: ['Control', 'Shift', 'p']
            }
        };

        return platformKeys[this.platform]?.[action] || platformKeys.windows[action];
    }

    setupEventListeners() {
        document.addEventListener('keydown', this.handleKeyDown.bind(this));
        document.addEventListener('keyup', this.handleKeyUp.bind(this));

        // Listen for WebSocket keyboard shortcut events
        if (window.websocketClient) {
            window.websocketClient.on('keyboardShortcutUpdate', this.handleShortcutUpdate.bind(this));
            window.websocketClient.on('keyboardShortcutConflict', this.handleShortcutConflict.bind(this));
        }
    }

    handleKeyDown(event) {
        if (this.isRecording && this.recordingCallback) {
            event.preventDefault();
            const keys = this.getPressedKeys(event);
            this.recordingCallback(keys);
            return;
        }

        const keys = this.getPressedKeys(event);
        const shortcut = this.findShortcut(keys);

        if (shortcut) {
            event.preventDefault();
            this.executeShortcut(shortcut);
        }
    }

    handleKeyUp(event) {
        // Handle key up events if needed
    }

    getPressedKeys(event) {
        const keys = [];

        if (event.ctrlKey || event.metaKey) {
            keys.push(this.platform === 'mac' ? 'Control' : 'Control');
        }
        if (event.altKey) {
            keys.push('Alt');
        }
        if (event.shiftKey) {
            keys.push('Shift');
        }

        if (!['Control', 'Alt', 'Shift'].includes(event.key)) {
            keys.push(event.key);
        }

        return keys;
    }

    findShortcut(keys) {
        for (const [id, shortcut] of this.shortcuts) {
            if (this.keysMatch(shortcut.keys, keys)) {
                return { id, ...shortcut };
            }
        }
        return null;
    }

    keysMatch(shortcutKeys, pressedKeys) {
        if (shortcutKeys.length !== pressedKeys.length) {
            return false;
        }

        return shortcutKeys.every(key => pressedKeys.includes(key));
    }

    executeShortcut(shortcut) {
        console.log(`Executing shortcut: ${shortcut.id}`);

        // Emit event for other components to handle
        this.emit('shortcutExecuted', {
            shortcutId: shortcut.id,
            shortcut: shortcut
        });

        // Execute the shortcut action if defined
        if (shortcut.action) {
            try {
                shortcut.action();
            } catch (error) {
                console.error(`Error executing shortcut ${shortcut.id}:`, error);
            }
        }
    }

    registerShortcut(id, options) {
        const shortcut = {
            id,
            keys: options.keys,
            description: options.description,
            category: options.category || 'general',
            context: options.context,
            global: options.global !== false,
            action: options.action,
            enabled: options.enabled !== false
        };

        // Check for conflicts
        const conflict = this.checkConflict(shortcut);
        if (conflict) {
            this.conflicts.set(id, conflict);
            console.warn(`Shortcut conflict detected for ${id}:`, conflict);
        }

        this.shortcuts.set(id, shortcut);

        // Add to category
        if (!this.categories.has(shortcut.category)) {
            this.categories.set(shortcut.category, []);
        }
        this.categories.get(shortcut.category).push(shortcut);

        console.log(`Registered shortcut: ${id} (${this.formatKeys(shortcut.keys)})`);
    }

    unregisterShortcut(id) {
        const shortcut = this.shortcuts.get(id);
        if (shortcut) {
            this.shortcuts.delete(id);
            this.conflicts.delete(id);

            // Remove from category
            const category = this.categories.get(shortcut.category);
            if (category) {
                const index = category.findIndex(s => s.id === id);
                if (index > -1) {
                    category.splice(index, 1);
                }
            }

            console.log(`Unregistered shortcut: ${id}`);
        }
    }

    checkConflict(newShortcut) {
        for (const [id, existingShortcut] of this.shortcuts) {
            if (id !== newShortcut.id && this.keysMatch(existingShortcut.keys, newShortcut.keys)) {
                return {
                    conflictingShortcut: id,
                    keys: existingShortcut.keys
                };
            }
        }
        return null;
    }

    startRecording(callback) {
        this.isRecording = true;
        this.recordingCallback = callback;
        this.showRecordingIndicator();

        console.log('Started recording keyboard shortcut');
    }

    stopRecording() {
        this.isRecording = false;
        this.recordingCallback = null;
        this.hideRecordingIndicator();

        console.log('Stopped recording keyboard shortcut');
    }

    showRecordingIndicator() {
        let indicator = document.getElementById('shortcut-recording-indicator');
        if (!indicator) {
            indicator = document.createElement('div');
            indicator.id = 'shortcut-recording-indicator';
            indicator.className = 'shortcut-recording-indicator';
            indicator.innerHTML = `
                <div class="recording-content">
                    <i class="fas fa-circle recording-dot"></i>
                    <span>Recording shortcut...</span>
                    <button class="recording-cancel" onclick="shortcutsManager.stopRecording()">
                        <i class="fas fa-times"></i>
                    </button>
                </div>
            `;
            document.body.appendChild(indicator);
        }

        indicator.style.display = 'block';
    }

    hideRecordingIndicator() {
        const indicator = document.getElementById('shortcut-recording-indicator');
        if (indicator) {
            indicator.style.display = 'none';
        }
    }

    formatKeys(keys) {
        return keys.map(key => {
            switch (key) {
                case 'Control':
                    return this.platform === 'mac' ? '⌘' : 'Ctrl';
                case 'Alt':
                    return this.platform === 'mac' ? '⌥' : 'Alt';
                case 'Shift':
                    return '⇧';
                case 'ArrowUp':
                    return '↑';
                case 'ArrowDown':
                    return '↓';
                case 'ArrowLeft':
                    return '←';
                case 'ArrowRight':
                    return '→';
                default:
                    return key;
            }
        }).join(' + ');
    }

    getShortcutsByCategory() {
        const result = {};
        for (const [category, shortcuts] of this.categories) {
            result[category] = shortcuts.filter(s => s.enabled);
        }
        return result;
    }

    getAllShortcuts() {
        return Array.from(this.shortcuts.values()).filter(s => s.enabled);
    }

    loadUserPreferences() {
        try {
            const preferences = localStorage.getItem('plexichat_shortcuts');
            if (preferences) {
                const userShortcuts = JSON.parse(preferences);
                // Apply user customizations
                Object.entries(userShortcuts).forEach(([id, customShortcut]) => {
                    if (this.shortcuts.has(id)) {
                        const shortcut = this.shortcuts.get(id);
                        Object.assign(shortcut, customShortcut);
                    }
                });
            }
        } catch (error) {
            console.error('Failed to load shortcut preferences:', error);
        }
    }

    saveUserPreferences() {
        try {
            const preferences = {};
            for (const [id, shortcut] of this.shortcuts) {
                preferences[id] = {
                    keys: shortcut.keys,
                    enabled: shortcut.enabled
                };
            }
            localStorage.setItem('plexichat_shortcuts', JSON.stringify(preferences));
        } catch (error) {
            console.error('Failed to save shortcut preferences:', error);
        }
    }

    handleShortcutUpdate(data) {
        // Handle shortcut updates from server
        console.log('Received shortcut update from server:', data);
    }

    handleShortcutConflict(data) {
        // Handle shortcut conflicts from server
        console.warn('Received shortcut conflict from server:', data);
        this.showConflictNotification(data);
    }

    showConflictNotification(conflictData) {
        if (window.plexichat && window.plexichat.showNotification) {
            window.plexichat.showNotification(
                `Keyboard shortcut conflict detected: ${conflictData.message}`,
                'warning',
                5000
            );
        }
    }

    emit(eventName, data = {}) {
        const event = new CustomEvent('shortcuts:' + eventName, {
            detail: data,
            bubbles: true
        });
        document.dispatchEvent(event);
    }

    on(eventName, callback) {
        document.addEventListener('shortcuts:' + eventName, (e) => {
            callback(e.detail);
        });
    }
}

// Create global shortcuts manager instance
const shortcutsManager = new KeyboardShortcutsManager();

// Export for global access
window.shortcutsManager = shortcutsManager;