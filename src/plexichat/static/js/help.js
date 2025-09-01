/**
 * PlexiChat Help System JavaScript
 * Provides interactive help functionality, tutorials, and contextual assistance
 */

class HelpSystem {
    constructor() {
        this.currentTutorial = null;
        this.currentStep = 0;
        this.searchTimeout = null;
        this.contextualHelp = new Map();
        this.keyboardShortcuts = new Map();
        this.init();
    }

    init() {
        this.setupEventListeners();
        this.loadKeyboardShortcuts();
        this.setupContextualHelp();
        this.initializeAccessibility();
    }

    setupEventListeners() {
        // Search functionality
        const searchInput = document.getElementById('help-search');
        if (searchInput) {
            searchInput.addEventListener('input', (e) => this.handleSearch(e.target.value));
            searchInput.addEventListener('keydown', (e) => this.handleSearchKeydown(e));
        }

        // Tutorial navigation
        const prevBtn = document.getElementById('prevStep');
        const nextBtn = document.getElementById('nextStep');
        if (prevBtn) prevBtn.addEventListener('click', () => this.previousTutorialStep());
        if (nextBtn) nextBtn.addEventListener('click', () => this.nextTutorialStep());

        // Modal events
        const tutorialModal = document.getElementById('tutorialModal');
        if (tutorialModal) {
            tutorialModal.addEventListener('hidden.bs.modal', () => this.resetTutorial());
        }

        // Keyboard shortcuts
        document.addEventListener('keydown', (e) => this.handleKeyboardShortcut(e));

        // Content loading
        document.addEventListener('click', (e) => this.handleContentClick(e));
    }

    async handleSearch(query) {
        if (this.searchTimeout) {
            clearTimeout(this.searchTimeout);
        }

        if (query.length < 2) {
            this.hideSearchResults();
            return;
        }

        this.searchTimeout = setTimeout(async () => {
            await this.performSearch(query);
        }, 300);
    }

    handleSearchKeydown(e) {
        if (e.key === 'Enter') {
            e.preventDefault();
            const query = e.target.value.trim();
            if (query) {
                this.performSearch(query);
            }
        } else if (e.key === 'Escape') {
            this.hideSearchResults();
            e.target.blur();
        }
    }

    async performSearch(query) {
        try {
            const response = await fetch(`/help/api/search?q=${encodeURIComponent(query)}`);
            const data = await response.json();

            if (data.results && data.results.length > 0) {
                this.showSearchResults(data.results);
            } else {
                this.showNoResults();
            }
        } catch (error) {
            console.error('Search error:', error);
            this.showSearchError();
        }
    }

    showSearchResults(results) {
        const resultsDiv = document.getElementById('search-results');
        if (!resultsDiv) return;

        let html = '<div class="search-results-list">';
        results.forEach(result => {
            html += `
                <div class="search-result-item" onclick="helpSystem.showContent('${result.id}')">
                    <div class="result-title">${this.escapeHtml(result.title)}</div>
                    <div class="result-category">${this.escapeHtml(result.category)}</div>
                    <div class="result-snippet">${this.escapeHtml(result.snippet)}</div>
                </div>
            `;
        });
        html += '</div>';

        resultsDiv.innerHTML = html;
        resultsDiv.style.display = 'block';
    }

    showNoResults() {
        const resultsDiv = document.getElementById('search-results');
        if (!resultsDiv) return;

        resultsDiv.innerHTML = '<div class="no-results">No results found. Try different keywords.</div>';
        resultsDiv.style.display = 'block';
    }

    showSearchError() {
        const resultsDiv = document.getElementById('search-results');
        if (!resultsDiv) return;

        resultsDiv.innerHTML = '<div class="search-error">Search is temporarily unavailable. Please try again later.</div>';
        resultsDiv.style.display = 'block';
    }

    hideSearchResults() {
        const resultsDiv = document.getElementById('search-results');
        if (resultsDiv) {
            resultsDiv.style.display = 'none';
        }
    }

    async showContent(contentId) {
        try {
            const response = await fetch(`/help/api/content/${contentId}`);
            const data = await response.json();

            const modal = new bootstrap.Modal(document.getElementById('contentModal'));
            document.getElementById('contentTitle').textContent = data.title;
            document.getElementById('contentBody').innerHTML = data.content;

            modal.show();
            this.hideSearchResults();
        } catch (error) {
            console.error('Error loading content:', error);
            this.showNotification('Failed to load content', 'error');
        }
    }

    async startTutorial(tutorialId) {
        try {
            const response = await fetch(`/help/api/tutorial/${tutorialId}`);
            const tutorial = await response.json();

            this.currentTutorial = tutorial;
            this.currentStep = 0;
            this.showTutorialStep();

            const modal = new bootstrap.Modal(document.getElementById('tutorialModal'));
            modal.show();
        } catch (error) {
            console.error('Error loading tutorial:', error);
            this.showNotification('Failed to load tutorial', 'error');
        }
    }

    showTutorialStep() {
        if (!this.currentTutorial) return;

        const step = this.currentTutorial.steps[this.currentStep];
        const contentDiv = document.getElementById('tutorialContent');
        const titleDiv = document.getElementById('tutorialTitle');

        if (titleDiv) titleDiv.textContent = this.currentTutorial.title;
        if (contentDiv) {
            contentDiv.innerHTML = `
                <h4>${this.escapeHtml(step.title)}</h4>
                <p>${this.escapeHtml(step.content)}</p>
            `;
        }

        this.updateTutorialProgress();
        this.updateTutorialNavigation();
    }

    updateTutorialProgress() {
        const progressDiv = document.getElementById('tutorialProgress');
        if (!progressDiv || !this.currentTutorial) return;

        let dotsHtml = '';
        for (let i = 0; i < this.currentTutorial.steps.length; i++) {
            dotsHtml += `<div class="tutorial-dot ${i === this.currentStep ? 'active' : ''}"></div>`;
        }
        progressDiv.innerHTML = dotsHtml;
    }

    updateTutorialNavigation() {
        const prevBtn = document.getElementById('prevStep');
        const nextBtn = document.getElementById('nextStep');

        if (prevBtn) {
            prevBtn.disabled = this.currentStep === 0;
        }

        if (nextBtn) {
            if (this.currentStep === this.currentTutorial.steps.length - 1) {
                nextBtn.innerHTML = 'Finish <i class="fas fa-check"></i>';
            } else {
                nextBtn.innerHTML = 'Next <i class="fas fa-chevron-right"></i>';
            }
        }
    }

    previousTutorialStep() {
        if (this.currentStep > 0) {
            this.currentStep--;
            this.showTutorialStep();
        }
    }

    nextTutorialStep() {
        if (!this.currentTutorial) return;

        if (this.currentStep < this.currentTutorial.steps.length - 1) {
            this.currentStep++;
            this.showTutorialStep();
        } else {
            // Tutorial finished
            this.finishTutorial();
        }
    }

    finishTutorial() {
        const modal = bootstrap.Modal.getInstance(document.getElementById('tutorialModal'));
        if (modal) {
            modal.hide();
        }
        this.showNotification('Tutorial completed!', 'success');
        this.resetTutorial();
    }

    resetTutorial() {
        this.currentTutorial = null;
        this.currentStep = 0;
    }

    loadKeyboardShortcuts() {
        // Load shortcuts from API
        fetch('/help/api/keyboard-shortcuts')
            .then(response => response.json())
            .then(data => {
                this.keyboardShortcuts = new Map(Object.entries(data.shortcuts));
                this.setupKeyboardListeners();
            })
            .catch(error => {
                console.error('Failed to load keyboard shortcuts:', error);
            });
    }

    setupKeyboardListeners() {
        document.addEventListener('keydown', (e) => this.handleKeyboardShortcut(e));
    }

    handleKeyboardShortcut(e) {
        const key = e.key.toLowerCase();
        const ctrl = e.ctrlKey || e.metaKey;
        const shift = e.shiftKey;
        const alt = e.altKey;

        // Help shortcut (Ctrl+/)
        if (ctrl && (key === '/' || key === '?')) {
            e.preventDefault();
            window.location.href = '/help';
            return;
        }

        // Command palette (Ctrl+K)
        if (ctrl && key === 'k') {
            e.preventDefault();
            this.showCommandPalette();
            return;
        }

        // Other shortcuts can be handled here
        // This would be expanded based on the shortcuts data
    }

    showCommandPalette() {
        // Placeholder for command palette functionality
        this.showNotification('Command palette feature coming soon!', 'info');
    }

    setupContextualHelp() {
        // Setup contextual help for different pages/elements
        this.contextualHelp.set('dashboard', {
            title: 'Dashboard Help',
            content: 'The dashboard shows your recent activity, server status, and quick actions.'
        });

        this.contextualHelp.set('messages', {
            title: 'Messaging Help',
            content: 'Use the message input to send messages. Press Enter to send, Shift+Enter for new line.'
        });

        // Add more contextual help as needed
    }

    showContextualHelp(context) {
        const help = this.contextualHelp.get(context);
        if (help) {
            this.showNotification(`${help.title}: ${help.content}`, 'info');
        }
    }

    handleContentClick(e) {
        const target = e.target;

        // Handle help buttons
        if (target.classList.contains('help-trigger')) {
            e.preventDefault();
            const context = target.dataset.helpContext;
            if (context) {
                this.showContextualHelp(context);
            }
        }

        // Handle tutorial starts
        if (target.classList.contains('start-tutorial') || target.closest('.start-tutorial')) {
            e.preventDefault();
            const tutorialId = target.dataset.tutorialId || target.closest('.start-tutorial').dataset.tutorialId;
            if (tutorialId) {
                this.startTutorial(tutorialId);
            }
        }
    }

    initializeAccessibility() {
        // Add ARIA labels and keyboard navigation
        const searchInput = document.getElementById('help-search');
        if (searchInput) {
            searchInput.setAttribute('aria-label', 'Search help topics');
            searchInput.setAttribute('role', 'searchbox');
        }

        // Make tutorial steps focusable
        const tutorialSteps = document.querySelectorAll('.tutorial-step');
        tutorialSteps.forEach(step => {
            step.setAttribute('tabindex', '0');
        });
    }

    showNotification(message, type = 'info') {
        // Create a simple notification system
        const notification = document.createElement('div');
        notification.className = `alert alert-${type === 'error' ? 'danger' : type} notification`;
        notification.style.cssText = `
            position: fixed;
            top: 20px;
            right: 20px;
            z-index: 9999;
            max-width: 300px;
            padding: 15px;
            border-radius: 5px;
            box-shadow: 0 4px 12px rgba(0,0,0,0.3);
            opacity: 0;
            transition: opacity 0.3s ease;
        `;
        notification.innerHTML = `
            ${message}
            <button type="button" class="btn-close" onclick="this.parentElement.remove()" style="float: right;"></button>
        `;

        document.body.appendChild(notification);

        // Animate in
        setTimeout(() => {
            notification.style.opacity = '1';
        }, 10);

        // Auto remove after 5 seconds
        setTimeout(() => {
            if (notification.parentElement) {
                notification.style.opacity = '0';
                setTimeout(() => notification.remove(), 300);
            }
        }, 5000);
    }

    scrollToSection(sectionId) {
        const element = document.querySelector(`[data-section="${sectionId}"]`) ||
                       document.getElementById(sectionId) ||
                       document.querySelector(`.${sectionId}-section`);
        if (element) {
            element.scrollIntoView({ behavior: 'smooth', block: 'start' });
        }
    }

    escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    // Public API methods
    search(query) {
        return this.performSearch(query);
    }

    showTutorial(tutorialId) {
        return this.startTutorial(tutorialId);
    }

    showHelpContent(contentId) {
        return this.showContent(contentId);
    }

    getContextualHelp(context) {
        return this.showContextualHelp(context);
    }
}

// Initialize help system when DOM is ready
let helpSystem;
document.addEventListener('DOMContentLoaded', function() {
    helpSystem = new HelpSystem();

    // Add section data attributes for navigation
    document.querySelectorAll('.help-section').forEach((section, index) => {
        const id = section.querySelector('h3').textContent.toLowerCase()
            .replace(/\s+/g, '-')
            .replace(/[^a-z0-9-]/g, '');
        section.setAttribute('data-section', id);
    });

    // Global functions for onclick handlers
    window.showContent = (contentId) => helpSystem.showContent(contentId);
    window.startTutorial = (tutorialId) => helpSystem.startTutorial(tutorialId);
    window.scrollToSection = (sectionId) => helpSystem.scrollToSection(sectionId);
});

// Export for global access
window.HelpSystem = HelpSystem;
window.helpSystem = helpSystem;