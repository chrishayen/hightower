# Changelog

All notable changes to this project will be documented in this file.

## [0.1.3] - 2025-10-06
- Added efficient prefix query support via `KvEngine::get_prefix()`.
- Implemented radix trie-based prefix index for O(prefix_length + results) lookups.
- Added benchmarks demonstrating ~14% performance improvement over manual scanning.
- Prefix queries work across storage and state layers with automatic cache warming.

## [0.1.2] - 2025-10-06
- Added `SingleNodeEngine::into_argon2_hasher_aes_gcm_auth_service` to return
  a shared engine handle alongside a preconfigured `AuthService`.
- Implemented `KvEngine` for `Arc<E>` so shared engine handles can be used with
  existing APIs.
- Updated README and developer guide with the new auth bundling helper.

## [0.1.1] - 2024-??-??
- Previous release.
