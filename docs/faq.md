[← Home](index.md)

# FAQ & Troubleshooting

## General

### What is Open-IPv8-Lab?

An experimental userspace toolkit implementing [draft-thain-ipv8-02](https://www.ietf.org/archive/id/draft-thain-ipv8-02.html) — the Internet Protocol Version 8 specification. It is **not** production networking software and does **not** modify your system's network stack. See [Overview](overview.md) for a full description and [IPv8 vs IPv4/IPv6 comparison](overview.md#why-ipv8--comparison-with-ipv4-and-ipv6).

### Does IPv8 replace IPv6?

No. IPv8 is an independent experimental protocol for research and education. IPv6 remains the IETF production standard for next-generation Internet addressing.

### Does this require root / raw sockets?

No. Everything runs in userspace as a normal user process. No kernel modules, no raw sockets, no privilege escalation.

### What operating systems are supported?

Linux, macOS, and Windows (including WSL2). Any platform with Python 3.11+ should work.

### Where is the spec?

[draft-thain-ipv8-02](https://www.ietf.org/archive/id/draft-thain-ipv8-02.html) — the full IETF Internet-Draft. The [Spec Coverage](spec-coverage.md) doc maps every section to source code.

---

## Installation

### `pip install` fails with "requires Python >= 3.11"

Upgrade Python. On macOS: `brew install python@3.13`. On Ubuntu: `sudo apt install python3.13`. Then recreate the venv:

```bash
python3.13 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
```

### `ipv8lab: command not found` after install

The entry point is installed into the venv's `bin/`. Make sure the venv is activated:

```bash
source .venv/bin/activate
which ipv8lab   # should print .venv/bin/ipv8lab
```

If you installed without `-e`, reinstall in editable mode:

```bash
pip install -e ".[dev]"
```

### `ModuleNotFoundError: No module named 'ipv8lab'`

You're running Python outside the venv. Activate it first:

```bash
source .venv/bin/activate
```

### Dependency conflict with `typer` / `rich` / `textual`

Minimum versions: `typer>=0.12.0`, `rich>=13.0.0`, `textual>=0.60.0`, `pyyaml>=6.0.0`. If you have older versions:

```bash
pip install --upgrade typer rich textual pyyaml
```

---

## CLI Usage

### How do I see all available commands?

```bash
ipv8lab --help
```

This lists all 35 sub-commands. For a specific command:

```bash
ipv8lab addr --help
ipv8lab zone --help
```

### Commands fail with `Error: Missing argument`

Most commands use **positional arguments**, not `--option` flags. Check `--help` for the correct syntax:

```bash
# Wrong:
ipv8lab addr parse --address 64496.192.0.2.1

# Right:
ipv8lab addr parse 64496.192.0.2.1
```

### How do I get JSON output?

Add `--json` to any command:

```bash
ipv8lab addr parse 64496.192.0.2.1 --json
ipv8lab zone status --json
ipv8lab bench run --json
```

### `zone oauth-issue` / `zone dhcp8-lease` fails

Zone Server commands are **stateful** — they require `zone init` first. However, module-level state is lost between separate CLI process invocations. For quick demos, use:

```bash
ipv8lab zone status --json
```

For the full lifecycle, see [Examples — Zone Server workflow](examples.md).

### `route simulate` says "config file not found"

The config must be a `.yaml` file. Check it exists:

```bash
ipv8lab route simulate --config examples/two_asn_demo.yaml
```

### TUI dashboard doesn't render properly

Ensure your terminal supports 256 colors and Unicode. Try:

```bash
export TERM=xterm-256color
ipv8lab tui run
```

On Windows, use Windows Terminal (not cmd.exe).

---

## Testing

### How do I run all tests?

```bash
pytest -v
```

All 1827 tests should pass. To run tests for a specific module:

```bash
pytest tests/test_address.py -v
pytest tests/test_route.py -v
```

### Tests pass locally but fail in CI

Check Python version — CI uses 3.11+. Also ensure all dev dependencies are installed:

```bash
pip install -e ".[dev]"
```

### How do I run linting and type checks?

```bash
ruff check src/ tests/
mypy src/
```

---

## Common Errors

| Error | Cause | Fix |
|-------|-------|-----|
| `command not found: ipv8lab` | venv not activated | `source .venv/bin/activate` |
| `Missing argument 'ADDRESS'` | Using `--option` instead of positional arg | Check `--help`, use positional args |
| `No such file or directory: '*.yaml'` | Wrong config path | Use `examples/two_asn_demo.yaml` |
| `ModuleNotFoundError` | Wrong Python / no venv | Activate venv or reinstall |
| `TypeError: randbelow()` | Python < 3.11 | Upgrade to Python 3.11+ |
| `ImportError: typer` | Missing dependency | `pip install -e ".[dev]"` |

---

## Still stuck?

1. Check [CLI Reference](cli-reference.md) for exact command syntax
2. Check [Examples](examples.md) for step-by-step walkthroughs
3. Check [Glossary](glossary.md) for unfamiliar terms
4. Open an [issue on GitHub](https://github.com/LF3551/Open-IPv8-Lab/issues)
