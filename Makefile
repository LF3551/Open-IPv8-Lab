.PHONY: install dev lint typecheck test cov docs clean

install:
	pip install -e .

dev:
	pip install -e ".[dev]"
	pre-commit install

lint:
	ruff check src/ tests/
	ruff format --check src/ tests/

format:
	ruff check --fix src/ tests/
	ruff format src/ tests/

typecheck:
	mypy src/ipv8lab/ --ignore-missing-imports

test:
	pytest -v

cov:
	pytest -v --cov=ipv8lab --cov-report=term-missing --cov-report=xml

docs:
	pip install -r docs/requirements.txt
	mkdocs build --strict

clean:
	rm -rf build/ dist/ *.egg-info .mypy_cache .pytest_cache .ruff_cache htmlcov coverage.xml site/
