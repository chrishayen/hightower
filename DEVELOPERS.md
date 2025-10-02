# Hightower KV – Developer Guide

## Overview
This guide captures the extension points and conventions for working on the
storage engine, authentication module, and future replication layer. It augments
the README by describing how components compose and where new functionality
should hook in.

## Storage Engine Extension Points

### Log Segments and Index
- `log_segment.rs` maintains append-only segments with sparse indexes and Bloom
  filters. Use `LogSegment::append` for writes and `LogSegment::locate` for
  targeted reads based on sparse metadata.
- The in-memory `Index` (`index.rs`) is copy-on-write. Rebuilds should use
  `IndexBuilder` so readers can continue using the old snapshot while a new map
  is constructed.

### Compaction
- `compactor.rs` exposes `Compactor` and `CompactionConfig`. Provide min-bytes,
  max segments, tombstone grace, and `emit_snapshot` options.
- `Storage::compact_all` consumes `CompactionOptions`. When extending compaction
  logic (e.g., segment selection heuristics), update `SuspendedCompaction` to
  preserve atomic snapshots.
- `SingleNodeEngine` schedules compaction via `maybe_run_compaction` after
  mutations, and `run_compaction_now` triggers a manual pass. Hook additional
  maintenance (e.g., metrics, log trimming) around these entry points.

### Snapshots
- `snapshot.rs` serializes `KvState` and persists the highest observed version.
- `Storage::state_snapshot` materializes snapshot state via the index; large
  scale work may replace this with streaming writers.
- Engine restart (`SingleNodeEngine::with_config`) loads the snapshot before
  replaying the write-ahead log. When altering the file format, add versioning
  checks to `Snapshot::load`.

## Authentication Module

### AuthService
- `AuthService` isolates auth logic from core key-value operations. Public
  methods (`create_user`, `verify_password`, `create_api_key`, etc.) should
  remain small orchestrators that combine crypto, indexing, and engine writes.
- Metadata helpers (`create_user_with_metadata`, decrypt functions) ensure all
  sensitive blobs are encrypted via the injected `EnvelopeEncryptor`.
- Use the `run_compaction_now` engine helper to manage persistent auth data in
  tests that need deterministic storage layout.

### Crypto
- Implement additional `SecretHasher` or `EnvelopeEncryptor` variants in
  `crypto.rs`. Keep constructors explicit and prefer `Result`-returning builders
  if inputs might be invalid (e.g., key size checks).

## Replication Preparation

### Traits
- `replication.rs` defines `CommandSubmitter`, `SnapshotProvider`, and
  `ReplicationHandle`. New replication implementations (Raft, custom consensus)
  should implement these traits to stay decoupled from storage.

### Local Adapter
- `LocalReplication` wraps any `KvEngine + SnapshotEngine`, providing a shim for
  higher layers that expect the replication interface. Extend or replace this
  adapter when integrating real consensus modules.

### Engine Hooks
- `SingleNodeEngine` implements `SnapshotEngine` and retains the ability to run
  compaction/snapshots on demand. Replication layers should call
  `snapshot_state` / `latest_version` before streaming snapshots and use
  `submit_batch` for atomic log replication.

## Tooling & Testing Conventions

- Unit tests for each module live alongside the code and should cover both happy
  paths and failure modes. Integration tests reside in `tests.rs` for cross-
  component flows.
- `cargo test` remains the canonical verification step; introducing new tooling
  should avoid interfering with existing tests (use feature flags or dedicated
  binaries as needed).
- Keep additions ASCII-friendly unless the module already depends on Unicode
  data.

## Contributing Checklist

1. Update `PLAN.md` and README when introducing new capabilities or completing
   milestones.
2. Ensure `cargo fmt` and `cargo test` pass locally.
3. Provide developer-facing documentation for new extension points here or in
   module-level comments.
4. When touching storage/log replication, consider adding instrumentation hooks
   (see `metrics.rs`) to keep observability consistent.
