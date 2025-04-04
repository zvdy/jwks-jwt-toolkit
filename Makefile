# Makefile for the JWKS server and JWT client

.PHONY: help install test run-server run-client clean setup-dev ci-local

help:
	@echo "JWKS Server and JWT Client"
	@echo ""
	@echo "Available targets:"
	@echo "  install     - Install dependencies"
	@echo "  test        - Run tests"
	@echo "  run-server  - Run the JWKS server"
	@echo "  run-client  - Run the JWT client (pass args with ARGS='...')"
	@echo "  clean       - Clean up temporary files"
	@echo "  setup-dev   - Setup development environment with pre-commit hooks"
	@echo "  ci-local    - Run CI pipeline locally"

install:
	pip install -r requirements.txt
	pip install -e .

test:
	python -m unittest discover -s tests

run-server:
	python run_server.py

run-client:
	python run_client.py $(ARGS)

clean:
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete
	find . -type f -name "*.pyo" -delete
	find . -type f -name "*.pyd" -delete
	find . -type f -name ".coverage" -delete
	find . -type d -name "*.egg-info" -exec rm -rf {} +
	find . -type d -name "*.egg" -exec rm -rf {} +
	find . -type d -name ".pytest_cache" -exec rm -rf {} +
	find . -type d -name ".coverage" -exec rm -rf {} +
	find . -type d -name "htmlcov" -exec rm -rf {} +
	find . -type d -name "dist" -exec rm -rf {} +
	find . -type d -name "build" -exec rm -rf {} +

setup-dev:
	pip install pre-commit
	pre-commit install

ci-local:
	mkdir -p scripts
	chmod +x scripts/run_ci_locally.sh
	bash scripts/run_ci_locally.sh
