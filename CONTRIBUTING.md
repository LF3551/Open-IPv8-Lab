# Contributing to Open-IPv8-Lab

Thank you for considering contributing to Open-IPv8-Lab!

## How to contribute

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-feature`
3. Make your changes
4. Add tests for new functionality
5. Run the test suite: `pytest -v`
6. Run the linter: `ruff check src/ tests/`
7. Commit your changes with a clear message
8. Push to your fork and submit a pull request

## Development setup

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

## Code style

- Line length: 100 characters
- Linter: [ruff](https://docs.astral.sh/ruff/)
- Type checker: [mypy](https://mypy-lang.org/)

## License

By contributing, you agree that your contributions will be licensed under the Apache License 2.0.

## Copyright header

Every source file must include:

```python
# Copyright 2026 Aleksei Aleinikov
# SPDX-License-Identifier: Apache-2.0
```
