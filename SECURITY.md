# Security Policy

## Scope

Open-IPv8-Lab is an **experimental, educational, userspace-only** toolkit. It does not:

- Handle production network traffic
- Process real authentication credentials or sensitive data
- Modify the kernel, network stack, or system configuration
- Require root, raw sockets, or elevated privileges
- Open external network connections (all demos use localhost)

### In scope

- Packet parser vulnerabilities (malformed input, buffer overflows in pure Python)
- CLI injection via crafted arguments
- Denial-of-service in simulation loops (infinite recursion, memory exhaustion)
- Logic errors in security modules: ingress filtering, ACL8, prefix enforcement
- Dependency vulnerabilities in `typer`, `rich`, `textual`, `pyyaml`

### Out of scope

- Kernel or OS-level network exploits (this is userspace only)
- Vulnerabilities in the IPv8 specification itself (report to the IETF draft author)
- Social engineering or phishing
- Physical access attacks

## Known limitations

1. **No real cryptography** — mTLS and OAuth8 use mock implementations with placeholder keys. Do not use for production authentication.
2. **No input sanitization on YAML configs** — `pyyaml.safe_load()` is used (no arbitrary code execution), but malicious YAML can cause excessive memory usage.
3. **Stateful CLI is process-scoped** — commands like `zone init` store state in module-level variables, lost between process invocations. Not a security issue, but may surprise users.
4. **No rate limiting on CLI** — the fuzzer and benchmark tools can consume significant CPU. This is by design for testing.
5. **WHOIS8/NetLog8 are mocks** — they simulate protocol behaviour without real network I/O or persistent storage.

## Fuzz testing

The built-in packet fuzzer (`ipv8lab fuzz`) tests protocol robustness with 9 mutation strategies:

| Strategy | Description |
|----------|-------------|
| `bit_flip` | Random bit flips in packet bytes |
| `byte_random` | Replace random bytes with random values |
| `boundary` | Insert boundary values (0x00, 0xFF, max int) |
| `truncate` | Truncate packets to random lengths |
| `extend` | Append random data beyond expected length |
| `checksum` | Corrupt CRC32 checksums |
| `field_mutate` | Mutate individual header fields |
| `fragment` | Generate invalid fragmentation combinations |
| `combined` | All strategies combined (default) |

### Running the fuzzer

```bash
# Default: 100 cases, combined strategy, parser target
ipv8lab fuzz run

# Heavy fuzz: 10,000 cases against all targets
ipv8lab fuzz run --count 10000 --target all

# Reproducible run with seed
ipv8lab fuzz run --count 1000 --seed 42 --json

# Specific strategy
ipv8lab fuzz run --strategy bit_flip --count 500

# List available strategies and targets
ipv8lab fuzz strategies
ipv8lab fuzz targets
```

### Fuzz targets

| Target | What it tests |
|--------|---------------|
| `parser` | Packet deserialization — malformed headers, invalid fields |
| `security` | Ingress filtering, prefix validation, ASN spoofing detection |
| `fragment` | Fragmentation/reassembly — overlapping fragments, invalid offsets |
| `routing` | Route table lookup — invalid prefixes, unreachable destinations |
| `all` | All targets combined |

## Reporting a vulnerability

If you discover a security issue, please report it via email:

**contact@alekseialeinikov.com**

Please **do not** open a public GitHub issue for security vulnerabilities.

Include:
- Description of the issue
- Steps to reproduce (CLI command, input data, or Python snippet)
- Expected vs actual behaviour
- Impact assessment

## Response

I will acknowledge receipt within 72 hours and provide a timeline for a fix.
