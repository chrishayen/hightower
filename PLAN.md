# Implementation Plan

## Phase 1 – Project Scaffolding
1. Initialize Cargo crate, add dependencies (`hashbrown`, `serde`, `argon2`, `aes-gcm`, etc.).
2. Create module files listed in the README with minimal struct/trait definitions and placeholder implementations.
3. Establish basic error handling (`error.rs`) and config loading (`config.rs`).
4. Set up CI/test harness to run unit + integration suites.

## Phase 2 – Storage Core
1. Implement append-only segment writer/reader in `log_segment.rs` with sparse index and Bloom filter metadata.
2. Build in-memory index manager in `index.rs`, including promotion from segment lookups and copy-on-write rebuilds.
3. Wire `storage.rs` to coordinate segments, index, and recovery; add snapshot support via `snapshot.rs`.
4. Introduce background compaction loop in `compactor.rs`, including atomically swapping rebuilt indexes.
5. Cover all storage components with unit tests and integration tests that verify basic CRUD, crash-replay, and compaction.

## Phase 3 – Engine Layer
1. Define `Command` enum and serialization in `command.rs`.
2. Implement deterministic `KvState` in `state.rs` applying commands, producing snapshots, and validating invariants.
3. Provide `KvEngine` trait and single-node implementation in `engine.rs`, including batching, read contexts, and write durability controls.
4. Integrate metrics hooks (no-op counters initially) and configuration knobs for batch/fsync/compaction cadence.
5. Add component tests covering command application, batching behavior, and snapshot round-trips.

## Phase 4 – Auth Module
1. Implement crypto abstractions in `crypto.rs` with concrete Argon2 + AES-GCM adapters.
2. Define user and API key record types plus serialization helpers in `auth_types.rs`.
3. Build `AuthService` in `auth_service.rs`, covering user creation, password verification, API key lifecycle, and metadata encryption.
4. Ensure batched writes keep secondary indexes consistent; add tests for concurrency/error paths via engine mocks.
5. Provide integration tests leveraging `KvEngine` to validate end-to-end auth flows.

## Phase 5 – Replication Hooks & Future Prep
1. Flesh out `replication.rs` traits (`CommandSubmitter`, `SnapshotProvider`, `ReplicationHandle`).
2. Implement single-node passthrough adapter satisfying the traits.
3. Document extension points for consensus integration and outline required state machine contracts.
4. Add smoke tests ensuring engine + auth work unchanged through the replication shim.

## Phase 6 – Polish & Tooling
1. Expand metrics to export via chosen backend (e.g., Prometheus) or leave hooks ready.
2. Add CLI/utility tooling for inspecting segments, running compaction manually, and dumping auth users.
3. Write developer guides for extending storage, adding auth features, and integrating consensus.
4. Finalize documentation and ensure README/PLAN stay in sync.

# TODO Checklist
- [x] Initialize Cargo project and baseline modules.
- [x] Define shared error handling and config structures.
- [x] Implement log segments with sparse index + Bloom filter.
- [x] Build in-memory index manager with rebuild support.
- [x] Wire storage facade with compaction and snapshots.
- [x] Implement deterministic state machine and command serialization.
- [x] Provide single-node engine with batching + read contexts.
- [x] Add metrics scaffolding and configuration hooks.
- [x] Implement crypto abstractions (hasher + encryptor).
- [x] Create auth data types and serialization helpers.
- [x] Build AuthService with secondary indexes.
- [x] Write unit/component/integration tests for storage, engine, and auth.
- [x] Flesh out replication traits and single-node adapter.
- [ ] Document extension points and developer guidance.
- [ ] Add tooling/CLI utilities for debugging and inspection.
