# Decision Log

This log records noteworthy decisions made while developing the project. Documenting them keeps context close at hand and makes future changes easier to reason about.

## Entries

- **2025-02-20** — Initialised the repository as a Rust binary crate (`cargo init --bin`). Provides a conventional Cargo layout with `src/main.rs` as the primary entry point.
- **2025-02-20** — Adopted the `clap` crate (v4 with `derive`) for CLI parsing. Gives structured argument handling, help generation, and an easy path for environment variable integration. Introduced mutually exclusive `--node` and `--root` flags with node as the default behaviour to reflect the expected primary use case.
- **2025-02-20** — Removed the secondary binary scaffold under `src/bin/`. Focus narrows to the main executable until additional binaries deliver concrete value.

## Adding New Decisions

When a new project-wide choice is made, append a brief entry explaining the context and rationale. Aim for enough detail that someone revisiting the project later understands why the decision was made.
