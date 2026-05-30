# ADR-001: Library-first evaluator architecture

**Status:** accepted  
**Date:** 2026-05-27  
**Deciders:** Ishan Singh  

## Context

OAP needs a policy evaluator that works in multiple deployment modes: embedded in SDKs (Python, TypeScript), embedded in gateways/proxies (Go), and behind an HTTP API. If the evaluator is only a server, every tool call requires a remote HTTP round-trip, adding latency and creating a single point of failure.

## Decision

The policy evaluator is built as a Go library first. The HTTP server wraps the library. SDKs can embed the evaluator (via subprocess, FFI, or WASM) or call the server remotely. The same evaluation code runs in all modes, ensuring consistent decisions.

## Consequences

- **Easier:** Sub-millisecond embedded evaluation; no remote dependency on the critical path; high availability (last-known-good policy works if control plane is down).
- **Harder:** Must maintain a clean library API surface; SDK embedding adds complexity for non-Go languages; policy bundle sync needed for embedded mode.
