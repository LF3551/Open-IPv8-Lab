# Contributing to Open-IPv8-Lab

Thank you for considering contributing to Open-IPv8-Lab!

## Development setup

```bash
git clone https://github.com/LF3551/Open-IPv8-Lab.git
cd Open-IPv8-Lab
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest -v          # 1827 tests must pass
ruff check src/ tests/
mypy src/
```

## Project structure

```
src/ipv8lab/
├── address.py              # Core module (example)
├── packet.py
├── route.py
├── …                       # 58 modules total — one per spec section
├── cli/
│   ├── main.py             # Typer root app — registers all sub-commands
│   ├── addr.py             # CLI wrapper for address.py
│   ├── route_cli.py        # CLI wrapper for route.py
│   └── …                   # One *_cli.py per CLI-enabled module
└── utils/
    ├── __init__.py
    └── formatting.py       # Shared output helpers
tests/
├── test_address.py         # 1:1 mapping to src modules
├── test_route.py
└── …
examples/                   # YAML configs, demo scripts
docs/                       # Markdown documentation
```

**Convention:** every core module lives at `src/ipv8lab/<module>.py`, its CLI wrapper at `src/ipv8lab/cli/<module>_cli.py`, and tests at `tests/test_<module>.py`.

## How to add a new CLI command

### 1. Create the core module

```python
# src/ipv8lab/my_feature.py
# Copyright 2026 Aleksei Aleinikov
# SPDX-License-Identifier: Apache-2.0

"""My Feature — brief description per spec section."""

def do_something(arg: str) -> dict:
    """Pure logic, no CLI dependencies."""
    return {"result": arg}
```

### 2. Create the CLI wrapper

```python
# src/ipv8lab/cli/my_feature_cli.py
# Copyright 2026 Aleksei Aleinikov
# SPDX-License-Identifier: Apache-2.0

"""CLI commands for my_feature."""

import json
import typer
from ipv8lab.my_feature import do_something

app = typer.Typer(no_args_is_help=True)

@app.command()
def demo(
    arg: str = typer.Argument(..., help="Input value"),
    as_json: bool = typer.Option(False, "--json", help="JSON output"),
) -> None:
    """Run a demo of My Feature."""
    result = do_something(arg)
    if as_json:
        typer.echo(json.dumps(result, indent=2))
    else:
        typer.echo(f"Result: {result}")
```

### 3. Register in main.py

```python
# src/ipv8lab/cli/main.py — add two lines:
from ipv8lab.cli.my_feature_cli import app as my_feature_app
# …
app.add_typer(my_feature_app, name="myfeature", help="My Feature description.")
```

### 4. Add tests

```python
# tests/test_my_feature.py
# Copyright 2026 Aleksei Aleinikov
# SPDX-License-Identifier: Apache-2.0

from ipv8lab.my_feature import do_something

def test_do_something():
    assert do_something("hello") == {"result": "hello"}
```

### 5. Verify

```bash
ipv8lab myfeature --help       # CLI works
ipv8lab myfeature demo test    # Command runs
pytest tests/test_my_feature.py -v
ruff check src/ipv8lab/my_feature.py src/ipv8lab/cli/my_feature_cli.py
mypy src/ipv8lab/my_feature.py
```

## Commit conventions

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<scope>): <short summary>
```

| Type | When |
|------|------|
| `feat` | New feature or module |
| `fix` | Bug fix |
| `docs` | Documentation only |
| `test` | Adding/fixing tests |
| `chore` | Version bumps, CI, tooling |
| `refactor` | Code change with no new feature or fix |

Examples:
```
feat: standalone WHOIS8 protocol (draft-thain-whois8-00)
fix: use randint instead of randbelow for Python 3.11 compat
docs: fix 33 broken CLI examples across all docs
chore: bump v0.12.0
```

**Rules:**
- One logical change per commit
- Reference spec sections where applicable (e.g. "per Section 19.4")
- Keep the subject line under 72 characters

## Pull request checklist

- [ ] All tests pass: `pytest -v`
- [ ] No lint errors: `ruff check src/ tests/`
- [ ] No type errors: `mypy src/`
- [ ] New module has tests (`tests/test_<module>.py`)
- [ ] CLI wrapper supports `--json` flag
- [ ] Copyright header on every new `.py` file
- [ ] Updated docs if adding a user-facing command

## Code style

- Line length: 100 characters
- Linter: [ruff](https://docs.astral.sh/ruff/)
- Type checker: [mypy](https://mypy-lang.org/)
- CLI framework: [Typer](https://typer.tiangolo.com/) (positional `Argument`, not `--option` for main params)

## CLI conventions

- Every sub-app uses `typer.Typer(no_args_is_help=True)`
- All commands support `--json` for machine-readable output
- Use `typer.Argument(...)` for required positional params
- Use `typer.Option(...)` for flags and optional params
- Print human-readable output by default, JSON only with `--json`

## License

By contributing, you agree that your contributions will be licensed under the Apache License 2.0.

## Copyright header

Every source file must include:

```python
# Copyright 2026 Aleksei Aleinikov
# SPDX-License-Identifier: Apache-2.0
```
