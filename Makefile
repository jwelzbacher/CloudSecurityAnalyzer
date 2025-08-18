.PHONY: dev test lint type format clean install help

help:
	@echo "Available targets:"
	@echo "  dev      - Install development dependencies"
	@echo "  test     - Run tests with coverage"
	@echo "  lint     - Run ruff linter"
	@echo "  type     - Run mypy type checker"
	@echo "  format   - Format code with black and ruff"
	@echo "  clean    - Clean build artifacts"
	@echo "  install  - Install project dependencies"

dev:
	poetry install --with dev
	poetry run pre-commit install

install:
	poetry install

test:
	poetry run pytest

lint:
	poetry run ruff check .

type:
	poetry run mypy .

format:
	poetry run black .
	poetry run ruff check --fix .

clean:
	rm -rf build/
	rm -rf dist/
	rm -rf *.egg-info/
	rm -rf .coverage
	rm -rf htmlcov/
	rm -rf .pytest_cache/
	rm -rf .mypy_cache/
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete