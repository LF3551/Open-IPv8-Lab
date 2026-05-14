# Overview

Open-IPv8-Lab is an experimental userspace toolkit for exploring IPv8 concepts.

## What it does

- Parses IPv8-style addresses (ASN dot notation and full 8-octet format)
- Converts ASN values to 4-octet routing prefixes and back
- Builds and parses experimental IPv8 Lab packets
- Simulates IPv8-style routing in userspace
- Provides local testbed demos with multi-node topologies

## What it does NOT do

- Does not modify the Linux kernel or network stack
- Does not require raw sockets or root access
- Does not implement any IETF standard
- Is not production networking software
- Does not claim official IPv8 compatibility

## Design principles

1. **Userspace only** — everything runs as a normal user process
2. **Educational** — clear code, good documentation, simple examples
3. **Extensible** — clean module structure for future experiments
4. **Safe** — no system modifications, no privilege escalation
