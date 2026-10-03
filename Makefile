.PHONY: help install setup run test clean lint format init-db reset-db freeze

help:
	@echo "SecureVault Development Commands"
	@echo "================================="
	@echo ""
	@echo "Setup Commands:"
	@echo "  make install       - Install dependencies"
	@echo "  make setup         - Complete setup (install + init-db)"
	@echo "  make venv          - Create virtual environment"
	@echo ""
	@echo "Database Commands:"
	@echo "  make init-db       - Initialize database"
	@echo "  make reset-db      - Reset database (drop and recreate)"
	@echo "  make drop-db       - Drop all database tables"
	@echo ""
	@echo "Running Commands:"
	@echo "  make run           - Run development server"
	@echo "  make run-prod      - Run production server"
	@echo ""
	@echo "Testing Commands:"
	@echo "  make test          - Run all tests"
	@echo "  make test-coverage - Run tests with coverage report"
	@echo "  make test-auth     - Test authentication module"
	@echo "  make test-vault    - Test vault module"
	@echo "  make test-security - Test security module"
	@echo ""
	@echo "Code Quality:"
	@echo "  make lint          - Run linter (flake8)"
	@echo "  make format        - Format code with black"
	@echo "  make check         - Run all checks (lint + format check)"
	@echo ""
	@echo "Utility Commands:"
	@echo "  make clean         - Remove cache and temporary files"
	@echo "  make freeze        - Freeze dependencies to requirements.txt"
	@echo "  make help          - Show this help message"

venv:
	python -m venv .venv
	@echo "Virtual environment created. Activate with:"
	@echo "  On macOS/Linux: source .venv/bin/activate"
	@echo "  On Windows: .venv\\Scripts\\activate"

install:
	pip install --upgrade pip
	pip install -r requirements.txt

setup: install init-db
	@echo "✅ Setup complete! Run 'make run' to start the server."

run:
	python src/app.py

run-prod:
	python -c "from src.app import create_app; app = create_app(); app.run(debug=False)"

init-db:
	python scripts/init_db.py init

reset-db:
	python scripts/init_db.py reset

drop-db:
	python scripts/init_db.py drop

test:
	pytest -v

test-coverage:
	pytest --cov=src --cov-report=html --cov-report=term
	@echo "Coverage report generated in htmlcov/index.html"

test-auth:
	pytest tests/test_auth.py -v

test-vault:
	pytest tests/test_vault.py -v

test-security:
	pytest tests/test_security.py -v

lint:
	flake8 src tests --max-line-length=100 --exclude=__pycache__

format:
	black src tests --line-length=100

format-check:
	black src tests --line-length=100 --check

check: lint format-check
	@echo "✅ All checks passed!"

clean:
	find . -type f -name '*.pyc' -delete
	find . -type d -name '__pycache__' -delete
	find . -type d -name '.pytest_cache' -delete
	find . -type d -name '.coverage' -delete
	find . -type d -name 'htmlcov' -delete
	find . -type f -name '.DS_Store' -delete
	@echo "✅ Cleaned up cache and temporary files"

freeze:
	pip freeze > requirements.txt
	@echo "✅ Dependencies frozen to requirements.txt"

.DEFAULT_GOAL := help
