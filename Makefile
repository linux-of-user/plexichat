# PlexiChat Makefile
# ==================
#
# This Makefile provides convenient targets for common development tasks,
# with a focus on documentation operations and build automation.
#
# Usage:
#   make <target>
#
# Documentation Targets:
#   docs          - Build documentation for production
#   docs-serve    - Serve documentation locally for development
#   docs-lint     - Lint documentation files
#   docs-clean    - Clean generated documentation files
#   docs-install  - Install documentation dependencies
#   docs-dev      - Build and serve docs in development mode
#   docs-check    - Check documentation for issues
#
# General Targets:
#   help          - Show this help message
#   clean         - Clean all generated files
#   install       - Install all dependencies
#   test          - Run tests (placeholder)
#   lint          - Run all linting tasks
#
# Environment Variables:
#   PYTHON        - Python command to use (default: python3)
#   DOCS_PORT     - Port for documentation server (default: 8000)
#   VERBOSE       - Enable verbose output (default: false)

# Configuration
SHELL := /bin/bash
.DEFAULT_GOAL := help
.PHONY: help docs docs-serve docs-lint docs-clean docs-install docs-dev docs-check clean install test lint

# Project paths
PROJECT_ROOT := $(shell pwd)
DOCS_DIR := $(PROJECT_ROOT)/docs
SCRIPTS_DIR := $(PROJECT_ROOT)/scripts
BUILD_SCRIPT := $(SCRIPTS_DIR)/build_docs.sh
DOCS_REQUIREMENTS := $(DOCS_DIR)/requirements.txt
GENERATED_DIR := $(DOCS_DIR)/_generated
SITE_DIR := $(PROJECT_ROOT)/site

# Commands
PYTHON ?= python3
PIP ?= pip
DOCS_PORT ?= 8000
VERBOSE ?= false

# Colors for output
RED := \033[0;31m
GREEN := \033[0;32m
YELLOW := \033[1;33m
BLUE := \033[0;34m
NC := \033[0m

# Helper functions
define log_info
	@echo -e "$(BLUE)[INFO]$(NC) $(1)"
endef

define log_success
	@echo -e "$(GREEN)[SUCCESS]$(NC) $(1)"
endef

define log_warning
	@echo -e "$(YELLOW)[WARNING]$(NC) $(1)"
endef

define log_error
	@echo -e "$(RED)[ERROR]$(NC) $(1)"
endef

# Help target
help: ## Show this help message
	@echo "PlexiChat Development Makefile"
	@echo "=============================="
	@echo ""
	@echo "Available targets:"
	@echo ""
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  $(BLUE)%-15s$(NC) %s\n", $$1, $$2}' $(MAKEFILE_LIST)
	@echo ""
	@echo "Documentation targets:"
	@echo "  $(BLUE)docs$(NC)          Build documentation for production"
	@echo "  $(BLUE)docs-serve$(NC)    Serve documentation locally (port $(DOCS_PORT))"
	@echo "  $(BLUE)docs-lint$(NC)     Lint documentation files"
	@echo "  $(BLUE)docs-clean$(NC)    Clean generated documentation files"
	@echo "  $(BLUE)docs-install$(NC)  Install documentation dependencies"
	@echo "  $(BLUE)docs-dev$(NC)      Build and serve docs in development mode"
	@echo "  $(BLUE)docs-check$(NC)    Check documentation for issues"
	@echo ""
	@echo "Docker targets:"
	@echo "  $(BLUE)docker-build$(NC)   Build Docker image for development"
	@echo "  $(BLUE)docker-cythonize$(NC) Run Cython compilation in Docker"
	@echo "  $(BLUE)docker-test$(NC)    Run tests in Docker container"
	@echo "  $(BLUE)docker-serve$(NC)   Serve application in Docker"
	@echo "  $(BLUE)docker-dev$(NC)     Start Docker development environment"
	@echo ""
	@echo "Environment variables:"
	@echo "  PYTHON=$(PYTHON)     Python command to use"
	@echo "  DOCS_PORT=$(DOCS_PORT)      Port for documentation server"
	@echo "  VERBOSE=$(VERBOSE)    Enable verbose output"
	@echo ""

# Documentation targets
docs: ## Build documentation for production
	$(call log_info,Building documentation for production...)
	@if [ ! -f "$(BUILD_SCRIPT)" ]; then \
		$(call log_error,Build script not found: $(BUILD_SCRIPT)); \
		exit 1; \
	fi
	@chmod +x "$(BUILD_SCRIPT)"
	@if [ "$(VERBOSE)" = "true" ]; then \
		"$(BUILD_SCRIPT)" --prod --verbose; \
	else \
		"$(BUILD_SCRIPT)" --prod; \
	fi
	$(call log_success,Documentation built successfully)
	@if [ -d "$(SITE_DIR)" ]; then \
		$(call log_info,Documentation available in: $(SITE_DIR)); \
	fi

docs-serve: ## Serve documentation locally for development
	$(call log_info,Starting documentation development server...)
	@if [ ! -f "$(BUILD_SCRIPT)" ]; then \
		$(call log_error,Build script not found: $(BUILD_SCRIPT)); \
		exit 1; \
	fi
	@chmod +x "$(BUILD_SCRIPT)"
	@$(call log_info,Documentation will be available at: http://localhost:$(DOCS_PORT))
	@$(call log_info,Press Ctrl+C to stop the server)
	@if [ "$(VERBOSE)" = "true" ]; then \
		DOCS_PORT=$(DOCS_PORT) "$(BUILD_SCRIPT)" --dev --verbose; \
	else \
		DOCS_PORT=$(DOCS_PORT) "$(BUILD_SCRIPT)" --dev; \
	fi

docs-dev: docs-serve ## Alias for docs-serve

docs-lint: ## Lint documentation files
	$(call log_info,Linting documentation files...)
	@if [ ! -f "$(DOCS_REQUIREMENTS)" ]; then \
		$(call log_error,Documentation requirements not found: $(DOCS_REQUIREMENTS)); \
		exit 1; \
	fi
	@# Check if markdownlint is available
	@if ! command -v markdownlint >/dev/null 2>&1; then \
		$(call log_warning,markdownlint not found, installing documentation dependencies...); \
		$(MAKE) docs-install; \
	fi
	@# Lint markdown files
	@$(call log_info,Running markdownlint on documentation files...)
	@if [ "$(VERBOSE)" = "true" ]; then \
		markdownlint "$(DOCS_DIR)"/**/*.md --config "$(DOCS_DIR)/.markdownlint.json" || true; \
	else \
		markdownlint "$(DOCS_DIR)"/**/*.md --config "$(DOCS_DIR)/.markdownlint.json" --quiet || true; \
	fi
	@# Check for broken links (basic check)
	@$(call log_info,Checking for basic documentation issues...)
	@find "$(DOCS_DIR)" -name "*.md" -exec grep -l "TODO\|FIXME\|XXX" {} \; | while read file; do \
		$(call log_warning,Found TODO/FIXME in: $$file); \
	done || true
	@# Check for missing files referenced in documentation
	@$(call log_info,Checking for missing file references...)
	@find "$(DOCS_DIR)" -name "*.md" -exec grep -o '\[.*\]([^)]*\.md)' {} \; | \
		sed 's/.*(\([^)]*\)).*/\1/' | sort -u | while read ref; do \
		if [ ! -f "$(DOCS_DIR)/$$ref" ] && [ ! -f "$(PROJECT_ROOT)/$$ref" ]; then \
			$(call log_warning,Missing referenced file: $$ref); \
		fi; \
	done || true
	$(call log_success,Documentation linting completed)

docs-clean: ## Clean generated documentation files
	$(call log_info,Cleaning generated documentation files...)
	@if [ -d "$(GENERATED_DIR)" ]; then \
		$(call log_info,Removing generated directory: $(GENERATED_DIR)); \
		rm -rf "$(GENERATED_DIR)"; \
	fi
	@if [ -d "$(SITE_DIR)" ]; then \
		$(call log_info,Removing site directory: $(SITE_DIR)); \
		rm -rf "$(SITE_DIR)"; \
	fi
	@# Remove MkDocs cache
	@if [ -d "$(PROJECT_ROOT)/.mkdocs_cache" ]; then \
		$(call log_info,Removing MkDocs cache); \
		rm -rf "$(PROJECT_ROOT)/.mkdocs_cache"; \
	fi
	@# Remove any temporary files
	@find "$(DOCS_DIR)" -name "*.tmp" -delete 2>/dev/null || true
	@find "$(DOCS_DIR)" -name ".DS_Store" -delete 2>/dev/null || true
	$(call log_success,Documentation files cleaned)

docs-install: ## Install documentation dependencies
	$(call log_info,Installing documentation dependencies...)
	@if [ ! -f "$(DOCS_REQUIREMENTS)" ]; then \
		$(call log_error,Documentation requirements not found: $(DOCS_REQUIREMENTS)); \
		exit 1; \
	fi
	@# Check if we're in a virtual environment
	@if [ -z "$$VIRTUAL_ENV" ]; then \
		$(call log_warning,No virtual environment detected. Consider using a virtual environment.); \
	fi
	@# Install requirements
	@$(call log_info,Installing from: $(DOCS_REQUIREMENTS))
	@if [ "$(VERBOSE)" = "true" ]; then \
		$(PIP) install -r "$(DOCS_REQUIREMENTS)"; \
	else \
		$(PIP) install -r "$(DOCS_REQUIREMENTS)" --quiet; \
	fi
	@# Verify installation
	@if command -v mkdocs >/dev/null 2>&1; then \
		$(call log_success,MkDocs installed: $$(mkdocs --version)); \
	else \
		$(call log_error,MkDocs installation failed); \
		exit 1; \
	fi
	@if command -v markdownlint >/dev/null 2>&1; then \
		$(call log_success,markdownlint installed: $$(markdownlint --version)); \
	else \
		$(call log_warning,markdownlint not available); \
	fi
	# Also install the application package in editable mode so docs extraction can import the app
	@$(call log_info,Installing application package (editable) for docs extraction...)
	@if [ -f "setup.py" ] || [ -f "pyproject.toml" ]; then \
		if [ "$(VERBOSE)" = "true" ]; then \
			$(PIP) install -e .; \
		else \
			$(PIP) install -e . --quiet; \
		fi; \
		$(call log_success,Application package installed in editable mode); \
	else \
		$(call log_warning,No setup.py or pyproject.toml found - skipping editable install); \
	fi
	$(call log_success,Documentation dependencies installed successfully)

docs-check: ## Check documentation for issues
	$(call log_info,Checking documentation for issues...)
	@# Check if required files exist
	@$(call log_info,Checking for required documentation files...)
	@required_files=("README.md" "GETTING_STARTED.md" "ARCHITECTURE.md" "SECURITY.md" "API.md" "DEPLOYMENT.md"); \
	for file in "$${required_files[@]}"; do \
		if [ ! -f "$(DOCS_DIR)/$$file" ]; then \
			$(call log_error,Required documentation file missing: $$file); \
		else \
			$(call log_info,Found: $$file); \
		fi; \
	done
	@# Check if build script exists and is executable
	@if [ ! -f "$(BUILD_SCRIPT)" ]; then \
		$(call log_error,Build script not found: $(BUILD_SCRIPT)); \
	elif [ ! -x "$(BUILD_SCRIPT)" ]; then \
		$(call log_warning,Build script not executable: $(BUILD_SCRIPT)); \
		chmod +x "$(BUILD_SCRIPT)"; \
	else \
		$(call log_success,Build script found and executable); \
	fi
	@# Check if MkDocs config exists
	@if [ ! -f "$(PROJECT_ROOT)/mkdocs.yml" ]; then \
		$(call log_error,MkDocs configuration not found: mkdocs.yml); \
	else \
		$(call log_success,MkDocs configuration found); \
	fi
	@# Check Python availability
	@if command -v $(PYTHON) >/dev/null 2>&1; then \
		$(call log_success,Python found: $$($(PYTHON) --version)); \
	else \
		$(call log_error,Python not found: $(PYTHON)); \
	fi
	@# Run basic documentation lint
	@$(MAKE) docs-lint
	$(call log_success,Documentation check completed)

# General targets
clean: docs-clean ## Clean all generated files
	$(call log_info,Cleaning all generated files...)
	@# Add other clean tasks here as needed
	$(call log_success,All generated files cleaned)

install: docs-install ## Install all dependencies
	$(call log_info,Installing all dependencies...)
	@# Add other install tasks here as needed
	$(call log_success,All dependencies installed)

test: ## Run tests (placeholder)
	$(call log_info,Running tests...)
	@# Add test commands here
	$(call log_warning,Test target not yet implemented)

lint: docs-lint ## Run all linting tasks
	$(call log_info,Running all linting tasks...)
	@# Add other lint tasks here as needed
	$(call log_success,All linting tasks completed)

# Compilation targets
cythonize: ## Cythonize all .pyx files in src/plexichat
	$(call log_info,Cythonizing Python files...)
	@if ! command -v cythonize >/dev/null 2>&1; then \
		$(call log_error,Cython not available. Run: pip install cython); \
		exit 1; \
	fi
	@cythonize -i src/plexichat/**/*.pyx
	$(call log_success,Cythonization completed)

numba-compile: ## Compile Numba JIT functions (placeholder - JIT at runtime)
	$(call log_info,Numba JIT compilation (runtime)...
	@echo "Numba functions will be JIT-compiled on first use."
	$(call log_success,Numba ready)

compile-all: cythonize numba-compile ## Build all compiled extensions
	$(call log_success,All compilation targets completed)

# Advanced documentation targets
docs-rebuild: docs-clean docs ## Clean and rebuild documentation
	$(call log_success,Documentation rebuilt successfully)

docs-quick: ## Quick documentation build (skip dependency check)
	$(call log_info,Quick documentation build...)
	@if [ ! -f "$(BUILD_SCRIPT)" ]; then \
		$(call log_error,Build script not found: $(BUILD_SCRIPT)); \
		exit 1; \
	fi
	@chmod +x "$(BUILD_SCRIPT)"
	@"$(BUILD_SCRIPT)" --prod --verbose
	$(call log_success,Quick documentation build completed)

docs-validate: ## Validate documentation build
	$(call log_info,Validating documentation...)
	@$(MAKE) docs-check
	@$(MAKE) docs-lint
	@$(MAKE) docs
	@if [ -f "$(SITE_DIR)/index.html" ]; then \
		$(call log_success,Documentation validation passed); \
	else \
		$(call log_error,Documentation validation failed - no index.html found); \
		exit 1; \
	fi

# Development convenience targets
dev-docs: docs-install docs-serve ## Install dependencies and serve docs

watch-docs: ## Watch for changes and rebuild docs (requires entr)
	$(call log_info,Watching for documentation changes...)
	@if ! command -v entr >/dev/null 2>&1; then \
		$(call log_error,entr not found. Install with: brew install entr (macOS) or apt-get install entr (Ubuntu)); \
		exit 1; \
	fi
	@find "$(DOCS_DIR)" -name "*.md" -o -name "*.yml" -o -name "*.yaml" | entr -r $(MAKE) docs-quick

# CI/CD targets
ci-docs: ## Build documentation for CI/CD
	$(call log_info,Building documentation for CI/CD...)
	@$(MAKE) docs-install
	@$(MAKE) docs-check
	@$(MAKE) docs-lint
	@$(MAKE) docs
	$(call log_success,CI/CD documentation build completed)

# Debug targets
debug-docs: ## Debug documentation build issues
	$(call log_info,Debugging documentation build...)
	@echo "Project root: $(PROJECT_ROOT)"
	@echo "Docs directory: $(DOCS_DIR)"
	@echo "Build script: $(BUILD_SCRIPT)"
	@echo "Python command: $(PYTHON)"
	@echo "Docs port: $(DOCS_PORT)"
	@echo "Verbose mode: $(VERBOSE)"
	@echo ""
	@$(MAKE) docs-check VERBOSE=true

# Show documentation statistics
docs-stats: ## Show documentation statistics
	$(call log_info,Documentation statistics...)
	@echo "Documentation files:"
	@find "$(DOCS_DIR)" -name "*.md" | wc -l | xargs echo "  Markdown files:"
	@find "$(DOCS_DIR)" -name "*.md" -exec wc -l {} + | tail -1 | awk '{print "  Total lines: " $$1}'
	@echo "Generated files:"
	@if [ -d "$(GENERATED_DIR)" ]; then \
		find "$(GENERATED_DIR)" -type f | wc -l | xargs echo "  Generated files:"; \
	else \
		echo "  Generated files: 0 (directory not found)"; \
	fi
	@if [ -d "$(SITE_DIR)" ]; then \
		echo "  Site directory size: $$(du -sh "$(SITE_DIR)" | cut -f1)"; \
	else \
		echo "  Site directory: not built"; \
	fi

# Docker targets
docker-build: ## Build Docker image for development
$(call log_info,Building Docker image for development...)
@if ! command -v docker >/dev/null 2>&1; then \
	$(call log_error,Docker not found. Please install Docker.); \
	exit 1; \
fi
docker build --platform linux/amd64,linux/arm64 -t plexichat-dev:latest . --target dev
$(call log_success,Docker image built successfully)

docker-cythonize: docker-build ## Run Cython compilation in Docker
$(call log_info,Running Cython compilation in Docker...)
docker run --rm -v $(PWD):/app -w /app plexichat-dev:latest make cythonize
$(call log_success,Cython compilation completed in Docker)

docker-test: docker-build ## Run tests in Docker container
$(call log_info,Running tests in Docker container...)
docker run --rm -v $(PWD):/app -w /app plexichat-dev:latest pytest tests/ --cov=src/plexichat --cov-report=term-missing --cov-fail-under=80
$(call log_success,Tests completed in Docker)

docker-serve: docker-build ## Serve application in Docker
$(call log_info,Starting application server in Docker...)
@if [ -f ".env" ]; then \
	$(call log_info,Using environment from .env file); \
else \
	$(call log_warning,No .env file found, using default POSTGRES_URL); \
fi
docker run -p 8000:8000 --rm -v $(PWD):/app -w /app \
	-e POSTGRES_URL=postgresql://postgres:password@host.docker.internal:5432/plexichat \
	plexichat-dev:latest uvicorn plexichat.main:app --reload --host 0.0.0.0 --port 8000
$(call log_success,Application server stopped)

docker-dev: docker-build ## Start Docker development environment
$(call log_info,Starting Docker development environment...)
docker run -it --rm -p 8000:8000 -v $(PWD):/app -w /app plexichat-dev:latest bash
$(call log_success,Development environment stopped)

# Update .PHONY list
.PHONY: help docs docs-serve docs-lint docs-clean docs-install docs-dev docs-check clean install test lint cythonize numba-compile compile-all docs-rebuild docs-quick docs-validate dev-docs watch-docs ci-docs debug-docs docs-stats docker-build docker-cythonize docker-test docker-serve docker-dev