# NetLink Testing Makefile
# Convenient commands for running tests and development tasks

.PHONY: help test test-unit test-integration test-e2e test-performance test-security test-all
.PHONY: coverage coverage-html coverage-xml lint format install-deps clean

# Default target
help:
	@echo "NetLink Testing Commands:"
	@echo ""
	@echo "Testing:"
	@echo "  test              Run all tests"
	@echo "  test-unit         Run unit tests only"
	@echo "  test-integration  Run integration tests only"
	@echo "  test-e2e          Run end-to-end tests only"
	@echo "  test-performance  Run performance tests only"
	@echo "  test-security     Run security tests only"
	@echo "  test-parallel     Run tests in parallel"
	@echo ""
	@echo "Coverage:"
	@echo "  coverage          Generate coverage report"
	@echo "  coverage-html     Generate HTML coverage report"
	@echo "  coverage-xml      Generate XML coverage report"
	@echo ""
	@echo "Code Quality:"
	@echo "  lint              Run code linting"
	@echo "  format            Format code"
	@echo "  security-scan     Run security scanning"
	@echo ""
	@echo "Setup:"
	@echo "  install-deps      Install dependencies"
	@echo "  install-test-deps Install test dependencies"
	@echo "  setup-ci          Setup CI/CD configuration"
	@echo ""
	@echo "Cleanup:"
	@echo "  clean             Clean test artifacts"
	@echo "  clean-coverage    Clean coverage reports"

# Test commands
test:
	python tests/run_tests.py

test-unit:
	pytest tests/unit/ -v

test-integration:
	pytest tests/integration/ -v

test-e2e:
	pytest tests/e2e/ -v

test-performance:
	pytest tests/performance/ -v -m performance

test-security:
	pytest tests/security/ -v -m security

test-parallel:
	python tests/run_tests.py --parallel

test-all:
	python tests/run_tests.py --coverage --parallel --output results/test_results.json

# Coverage commands
coverage:
	pytest --cov=src --cov-report=term-missing

coverage-html:
	pytest --cov=src --cov-report=html
	@echo "Coverage report generated: tests/coverage/html/index.html"

coverage-xml:
	pytest --cov=src --cov-report=xml
	@echo "Coverage XML generated: tests/coverage/coverage.xml"

# Code quality commands
lint:
	flake8 src/ tests/
	pylint src/ tests/
	mypy src/

format:
	black src/ tests/
	isort src/ tests/

security-scan:
	bandit -r src/
	safety check
	semgrep --config=auto src/

# Setup commands
install-deps:
	pip install -r requirements.txt

install-test-deps:
	pip install -r tests/requirements.txt

setup-ci:
	python tests/run_tests.py --create-ci
	@echo "CI/CD configuration created"

# Cleanup commands
clean:
	find . -type f -name "*.pyc" -delete
	find . -type d -name "__pycache__" -delete
	find . -type d -name "*.egg-info" -exec rm -rf {} +
	rm -rf .pytest_cache/
	rm -rf tests/results/
	rm -rf .coverage

clean-coverage:
	rm -rf tests/coverage/
	rm -rf htmlcov/
	rm -f coverage.xml
	rm -f .coverage

# Development commands
dev-setup: install-deps install-test-deps
	@echo "Development environment setup complete"

quick-test:
	pytest tests/unit/ -x --tb=short

watch-tests:
	pytest-watch tests/unit/

# CI/CD simulation
ci-test:
	python tests/run_tests.py --coverage --parallel --output results/ci_results.json
	@echo "CI test simulation complete"

# Performance benchmarking
benchmark:
	pytest tests/performance/ --benchmark-only --benchmark-sort=mean

# Documentation
docs-test:
	pytest --doctest-modules src/

# Database testing
test-db:
	pytest tests/unit/test_database.py tests/integration/test_database.py -v

# API testing
test-api:
	pytest tests/unit/test_api.py tests/integration/test_api.py tests/e2e/test_api.py -v

# Authentication testing
test-auth:
	pytest -m auth -v

# Backup testing
test-backup:
	pytest -m backup -v

# Full quality check
quality-check: lint security-scan test-all coverage-html
	@echo "Full quality check complete"

# Release preparation
pre-release: clean quality-check
	@echo "Pre-release checks complete"
