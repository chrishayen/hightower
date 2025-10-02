# Hightower KV

## Overview
Hightower KV is a lightweight, embedded key-value store designed for nodes in a custom container orchestration platform. The initial milestone targets single-node deployments with strong consistency and a clear upgrade path to replicated clusters.

## Goals
- Fast, append-friendly writes with predictable resource usage.
- Tunable memory footprint and IO characteristics suitable for shared worker nodes.
- Deterministic state machine interface so consensus can be layered on later.
- Integrated authentication helper that remains isolated from core get/put APIs.

## Core Decisions
### Storage Engine
- Log-structured segments with sequential append-only writes and periodic compaction.
- In-memory hash index for hot keys backed by sparse on-disk segment metadata (including Bloom filters) for cold lookups.
- Copy-on-write rebuild of the index during compaction to avoid blocking reads/writes.
- Snapshot support (`serialize_snapshot` / `restore_snapshot`) so recovery avoids replaying the entire log.
- Single-node deployments schedule compaction opportunistically after batches and can be forced via `run_compaction_now`, automatically emitting snapshots when enabled.

### Command & State Machine
- `Command` enum captures set/delete/batch operations. Each command applies deterministically to the `KvState` state machine.
- `KvEngine` facade routes commands to storage and provides read contexts; today it invokes storage directly, later it can submit via consensus.
- Writes support batching and configurable fsync cadence to balance durability vs. latency.
- `SingleNodeEngine` exposes `submit_batch` for grouped writes and `read_with` for consistent read snapshots built on the in-memory state.

### Replication Readiness
- Define neutral traits (`CommandSubmitter`, `SnapshotProvider`) under `replication.rs` that the single-node engine fulfills trivially.
- Plan to swap in a Raft (or similar) implementation without changing storage or higher layers by conforming to these traits.
- Reads currently execute locally; future leader-leases/read-index checks can plug into the existing read context abstraction.

### Indexing Strategy
- Primary in-memory map: `key -> (segment_id, offset, length, version)` with configurable load factor.
- Segment-level sparse index + Bloom filter to accelerate cold lookups and enable promotion of entries back into the hot map.
- Background compactor regenerates segment metadata and rebuilds the in-memory map atomically.

### Authentication Layer
- Separate `AuthService` module that depends only on the `KvEngine` plus crypto traits.
- Key space namespaced under `auth/*` (e.g., `auth/user/<id>`, `auth/apikey/<id>`) with secondary indexes for lookups (`auth/user_by_name/<username>`).
- Passwords/API keys stored as hashes using configurable `SecretHasher` (Argon2/Bcrypt). Encrypted metadata blobs handled by `EnvelopeEncryptor` (e.g., AES-GCM).
- API produces helpers like `create_user`, `verify_password`, `create_api_key`, each maintaining indexes via batched writes.
- Metadata passed to `create_user_with_metadata` / `create_api_key_with_metadata` is envelope-encrypted and stored alongside the record (`UserRecord.metadata`, `ApiKeyRecord.metadata`), ensuring sensitive attributes never hit disk in plaintext; callers can recover it through the service-level decrypt helpers without touching cipher primitives.

### Configuration & Telemetry
- Central `config.rs` defines storage paths, compaction thresholds, flush cadence, auth crypto settings.
- `StoreConfig::emit_snapshot_after_compaction` controls whether scheduled compaction writes a fresh snapshot.
- `metrics.rs` provides hooks for counters/timers so operational visibility stays consistent when clustering arrives.

## File Layout
Each logical component lives in its own file in a flat module structure:
- `lib.rs` – module declarations and re-exports.
- `config.rs` – runtime configuration knobs.
- `error.rs` – shared error types and `Result` alias.
- `command.rs` – command definitions and serialization.
- `state.rs` – deterministic KV state machine + snapshot helpers.
- `engine.rs` – `KvEngine` trait, single-node engine, batching, read contexts.
- `storage.rs` – storage facade orchestrating log/index/compaction.
- `log_segment.rs` – segment IO, sparse index, Bloom filters.
- `index.rs` – in-memory index management and rebuild logic.
- `compactor.rs` – background compaction pipeline and atomically swapping state.
- `snapshot.rs` – checkpoint format and persistence helpers.
- `replication.rs` – future-facing consensus traits with single-node stubs.
- `id_generator.rs` – ID/token generation utilities.
- `crypto.rs` – `SecretHasher`/`EnvelopeEncryptor` abstractions + implementations.
- `auth_types.rs` – user and API-key record structs, serialization helpers.
- `auth_service.rs` – standalone authentication interface backed by KV storage.
- `metrics.rs` – instrumentation helpers.
- `tests.rs` – integration smoke tests for engine and auth flows.

## Testing Philosophy
- Favor small, single-purpose functions that are easy to reason about and validate in isolation.
- Every function should come with direct unit coverage; each component/module should also expose higher-level tests that exercise its public surface.
- Prefer deterministic tests by injecting traits or mocks for IO, crypto, and timing dependencies.
- Maintain fast test execution to encourage frequent runs; heavier integration scenarios live alongside the crate’s integration suite.

## Future Work
- Integrate a consensus module (likely Raft) implementing `CommandSubmitter` to enable clustered deployments.
- Leader-read optimizations once consensus is in place (read index, leases).
- Optional range-scan support via sorted segment variants if workloads demand it.
- Extended auth features (permissions, audit trails) once use cases are clarified.
- Operational tooling: benchmarks, chaos testing hooks, and CLI inspector.
