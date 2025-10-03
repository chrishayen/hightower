# TODO

## Encryption for KV-stored certificates
- [ ] Evaluate encrypting certificate payloads once the KV crate exposes built-in encryption support.
- [ ] Wrap that future KV encryption API (e.g., `AesGcmEncryptor`) so certificate writes/readers stay transparent.
- [ ] Add tests ensuring encrypted certificates round-trip only with the proper key material.

## Encryption for HT token
- [ ] Migrate `HT_TOKEN` storage to the KV crate's upcoming encryption API.
- [ ] Ensure fallback logging/rotation paths continue to work when the token is encrypted.
- [ ] Add coverage that confirms encrypted tokens remain unreadable without the configured key.
