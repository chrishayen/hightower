# Decision Log

This log records noteworthy decisions made while developing the project. Documenting them keeps context close at hand and makes future changes easier to reason about.

## Entries

- **2025-02-20** — Refactored startup flow: common bootstrap runs once, then dispatches to dedicated node/root modules for mode-specific work while main handles shared shutdown.
- **2025-02-20** — Node mode now generates a random `ht-<adjective>-<noun>-<suffix>` name (suffix length 5) using `hightower-naming` and stores it in KV for reuse.
- **2025-02-20** — Persist `HT_AUTH_KEY` in the KV store under `secrets/ht_auth_key` for reuse across restarts, accepting plaintext storage until encryption is implemented.
- **2025-02-20** — Persist node certificates in the key-value store as JSON payloads under `certificates/node` so restarts reuse the same storage layer; revisit encryption later (see TODO).
- **2025-02-20** — Deferred encrypting KV-stored certificates; captured follow-up tasks in `TODO.md` to explore using the crate’s AES-GCM helpers when we’re ready.
- **2025-02-20** — Introduced a runtime key-value store initialiser: the app now honours a `--kv` flag for specifying the data directory and otherwise creates a managed temp directory using `hightower-kv`, emitting the resolved location at debug level for troubleshooting.
- **2025-02-20** — Application now blocks after startup waiting for Ctrl-C in both root and node modes, using a tested shutdown helper to ensure graceful exits.
- **2025-02-20** — Added a `Makefile` dev target that expects GNU Make (`gmake`) and runs node mode with `HT_AUTH_KEY=test-auth-key` plus `RUST_LOG=debug` to make local debugging a single command.
- **2025-02-20** — When running in node debug mode we emit WireGuard key material at debug log level to aid diagnostics, logging the generated public and private keys separately as summarised hex (first/last 6 chars).
- **2025-02-20** — Introduced structured logging via the `tracing` and `tracing-subscriber` crates; main now initialises a scoped subscriber and runtime events are emitted as log records instead of direct stdout prints.
- **2025-02-20** — Node startup now issues WireGuard certificates using the `hightower-wireguard` crate whenever running in node mode, ensuring fresh key material is derived before service work begins.
- **2025-02-20** — Adopted a modular architecture mandate: each logical component lives in its own file, functions stay small, and every function receives a corresponding test to keep behaviour explicit and verifiable.
- **2025-02-20** — Enforced presence of the `HT_AUTH_KEY` environment variable for both root and node execution paths; the application now exits early if the key is missing to prevent unauthenticated operation.
- **2025-02-20** — Initialised the repository as a Rust binary crate (`cargo init --bin`). Provides a conventional Cargo layout with `src/main.rs` as the primary entry point.
- **2025-02-20** — Adopted the `clap` crate (v4 with `derive`) for CLI parsing. Gives structured argument handling, help generation, and an easy path for environment variable integration. Introduced mutually exclusive `--node` and `--root` flags with node as the default behaviour to reflect the expected primary use case.
- **2025-02-20** — Removed the secondary binary scaffold under `src/bin/`. Focus narrows to the main executable until additional binaries deliver concrete value.

## Adding New Decisions

When a new project-wide choice is made, append a brief entry explaining the context and rationale. Aim for enough detail that someone revisiting the project later understands why the decision was made.
