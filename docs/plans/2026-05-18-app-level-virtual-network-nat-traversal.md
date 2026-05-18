# App-Level Virtual Network and NAT Traversal Implementation Plan

> **For Hermes:** Use subagent-driven-development skill to implement this plan task-by-task.

**Goal:** Make `hightower-client` resolve logical peers through the gateway, authorize public keys on both sides, select a working local/public/NAT-punched endpoint, and open app-level encrypted streams without relying on kernel-level routing for `100.64.x.x` virtual IPs.

**Architecture:** Keep the existing WireGuard-like transport as the encrypted session/stream layer. Add a client-side virtual network/control layer that maps endpoint IDs or virtual IPs to gateway-resolved peer public keys and endpoint candidates, then tries local/public/hole-punch candidates with ordered fallback before calling `Connection::connect`. Add gateway connection-intent APIs so responders learn and authorize initiator public keys before handshakes arrive.

**Tech Stack:** Rust workspace, `axum` gateway API, existing `hightower-client`, existing `hightower-wireguard`, existing `hightower-stun`, KV-backed gateway persistence, Tokio async tests.

---

## Current Evidence / Problem Statement

Manual frank -> shotgun probing proved:

- Registration works when `HT_STUN_SERVER=5.78.219.236:3478` is set.
- Peer lookup returns public key, assigned IP, public STUN endpoint, and local endpoint.
- Direct LAN endpoint handshake works when both sides pre-authorize each other.
- Current `HightowerConnection::dial(peer)` must not dial an assigned virtual IP directly; virtual IPs are logical addresses, not OS routes.
- Responder rejects unknown initiators with `ProtocolError("Unknown peer")` unless the peer public key is pre-added.

Therefore the fix is not to make `100.64.x.x` routable at kernel level. The fix is an app-level virtual network layer:

```text
endpoint id / virtual IP
  -> gateway resolution
  -> peer public key authorization
  -> endpoint candidate exchange
  -> local/public/hole-punch/relay path selection
  -> WireGuard encrypted session
  -> app-level stream
```

---

## Design Constraints

- Preserve existing registration and lookup endpoints while adding new fields/routes.
- Avoid replacing `hightower-wireguard`; use it only after path selection chooses a real `SocketAddr`.
- Keep virtual IPs as logical identities in the client/gateway API, not socket destinations.
- Use TDD for each implementation task.
- Add integration examples/tests that reproduce the frank/shotgun success case locally with two clients.
- Defer full relay implementation to a follow-up milestone, but design the candidate model with `Relay` support.

---

## Phase 1: Shared Candidate Types and Gateway Persistence

### Task 1: Add endpoint candidate types to client and gateway API models

**Objective:** Represent local, STUN public, hole-punch, and future relay candidates explicitly instead of only `public_ip/public_port/local_ip/local_port`.

**Files:**
- Modify: `client/src/types.rs`
- Modify: `gateway/src/api/types.rs`
- Test: `client/src/types.rs`
- Test: `gateway/src/api/types.rs`

**Step 1: Write serialization tests**

Add candidate model tests in both crates:

```rust
#[test]
fn endpoint_candidate_round_trips_json() {
    let candidate = EndpointCandidate {
        kind: CandidateKind::Local,
        addr: "192.168.4.63:33565".parse().unwrap(),
        priority: 100,
    };

    let json = serde_json::to_string(&candidate).unwrap();
    assert!(json.contains("Local"));
    assert!(json.contains("192.168.4.63:33565"));

    let decoded: EndpointCandidate = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded.kind, CandidateKind::Local);
    assert_eq!(decoded.addr.to_string(), "192.168.4.63:33565");
    assert_eq!(decoded.priority, 100);
}
```

**Step 2: Run tests to verify failure**

```bash
cargo test -p hightower-client endpoint_candidate_round_trips_json
cargo test -p hightower-gateway endpoint_candidate_round_trips_json
```

Expected: fail because `EndpointCandidate` and `CandidateKind` do not exist.

**Step 3: Implement types**

In `client/src/types.rs` add public types:

```rust
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum CandidateKind {
    Local,
    StunPublic,
    HolePunch,
    Relay,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct EndpointCandidate {
    pub kind: CandidateKind,
    pub addr: std::net::SocketAddr,
    pub priority: u32,
}
```

In `gateway/src/api/types.rs` add matching crate-visible types:

```rust
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(crate) enum CandidateKind {
    Local,
    StunPublic,
    HolePunch,
    Relay,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(crate) struct EndpointCandidate {
    pub(crate) kind: CandidateKind,
    pub(crate) addr: std::net::SocketAddr,
    pub(crate) priority: u32,
}
```

**Step 4: Verify pass**

```bash
cargo test -p hightower-client endpoint_candidate_round_trips_json
cargo test -p hightower-gateway endpoint_candidate_round_trips_json
```

**Step 5: Commit**

```bash
git add client/src/types.rs gateway/src/api/types.rs
git commit -m "feat: add endpoint candidate types"
```

---

### Task 2: Extend registration and peer response with candidates

**Objective:** Let clients submit and retrieve `candidates: Vec<EndpointCandidate>` while keeping old fields temporarily for compatibility.

**Files:**
- Modify: `client/src/types.rs`
- Modify: `gateway/src/api/types.rs`
- Modify: `gateway/src/api/handlers/endpoints.rs`
- Test: `gateway/src/api/handlers/endpoints.rs`

**Step 1: Write gateway persistence test**

Add/extend a test in `gateway/src/api/handlers/endpoints.rs`:

```rust
#[tokio::test]
async fn register_endpoint_persists_candidates() {
    let temp = TempDir::new().expect("tempdir");
    let kv = initialize_kv(Some(temp.path())).expect("kv init");
    super::super::certificates::persist_gateway_key_for_tests(&kv).expect("gateway key");
    super::auth_keys::store_legacy_key(&kv, "test-auth").expect("auth key");

    let state = ApiState {
        kv: Arc::new(RwLock::new(kv.clone())),
        auth: Arc::new(CommonContext::with_kv(kv.clone()).auth),
    };

    let mut headers = HeaderMap::new();
    headers.insert(HeaderName::from_static("x-ht-auth"), "test-auth".parse().unwrap());

    let body = EndpointRegistrationRequest {
        endpoint_id: None,
        public_key_hex: "00".repeat(32),
        token: None,
        assigned_ip: None,
        public_ip: Some("71.179.92.242".into()),
        public_port: Some(50963),
        local_ip: Some("192.168.4.63".into()),
        local_port: Some(33565),
        candidates: vec![
            EndpointCandidate { kind: CandidateKind::Local, addr: "192.168.4.63:33565".parse().unwrap(), priority: 100 },
            EndpointCandidate { kind: CandidateKind::StunPublic, addr: "71.179.92.242:50963".parse().unwrap(), priority: 50 },
        ],
    };

    let response = register_endpoint(State(state.clone()), headers, Json(body))
        .await
        .expect("registration succeeds");

    let endpoint = get_endpoint_by_id(
        State(state),
        AxumPath(response.0.endpoint_id),
        HeaderMap::from_iter([(HeaderName::from_static("x-ht-auth"), "test-auth".parse().unwrap())]),
    )
    .await
    .expect("lookup succeeds")
    .0;

    assert_eq!(endpoint.candidates.len(), 2);
    assert_eq!(endpoint.candidates[0].kind, CandidateKind::Local);
}
```

Adjust helper names to match existing test helpers in `endpoints.rs` if they differ.

**Step 2: Run test to verify failure**

```bash
cargo test -p hightower-gateway register_endpoint_persists_candidates
```

Expected: fail because registration structs do not include `candidates`.

**Step 3: Add candidate fields**

In both registration/peer structs, add:

```rust
#[serde(default)]
pub candidates: Vec<EndpointCandidate>,
```

For gateway crate-visible fields use `pub(crate)`.

**Step 4: Require candidates as the canonical schema**

Do not keep parallel `public_ip` / `local_ip` fields or compatibility normalization. Registration submits a single canonical `candidates` list; peer lookup returns that same list.

After assigning endpoint ID/IP, persist the registration as-is:

```rust
let mut registration = body.clone();
registration.endpoint_id = Some(endpoint_id.clone());
registration.assigned_ip = Some(assigned_ip.clone());
```

**Step 5: Verify**

```bash
cargo test -p hightower-gateway register_endpoint_persists_candidates
cargo test -p hightower-gateway endpoints
```

**Step 6: Commit**

```bash
git add client/src/types.rs gateway/src/api/types.rs gateway/src/api/handlers/endpoints.rs
git commit -m "feat: persist endpoint candidates"
```

---

## Phase 2: Gateway Connection Intent / Peer Authorization

### Task 3: Add connection intent API types

**Objective:** Model “A wants to connect to B” so the responder can learn A’s public key and candidates before accepting the handshake.

**Files:**
- Modify: `gateway/src/api/types.rs`
- Test: `gateway/src/api/types.rs`

**Step 1: Add tests**

```rust
#[test]
fn connection_intent_round_trips_json() {
    let request = ConnectionIntentRequest {
        target: "ht-unlimited-machine-6327".to_string(),
    };
    let json = serde_json::to_string(&request).unwrap();
    let decoded: ConnectionIntentRequest = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded.target, "ht-unlimited-machine-6327");
}
```

**Step 2: Implement types**

In `gateway/src/api/types.rs`:

```rust
pub(crate) const CONNECTION_INTENT_PREFIX: &str = "connections/intents";

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub(crate) struct ConnectionIntentRequest {
    pub(crate) target: String,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub(crate) struct ConnectionIntent {
    pub(crate) connection_id: String,
    pub(crate) initiator_endpoint_id: String,
    pub(crate) target_endpoint_id: String,
    pub(crate) initiator: EndpointRegistrationRequest,
    pub(crate) target: EndpointRegistrationRequest,
    pub(crate) created_at_ms: u64,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub(crate) struct ConnectionIntentResponse {
    pub(crate) connection_id: String,
    pub(crate) initiator: EndpointRegistrationRequest,
    pub(crate) target: EndpointRegistrationRequest,
}
```

**Step 3: Verify**

```bash
cargo test -p hightower-gateway connection_intent_round_trips_json
```

**Step 4: Commit**

```bash
git add gateway/src/api/types.rs
git commit -m "feat: add connection intent API types"
```

---

### Task 4: Implement gateway connection intent routes

**Objective:** Allow an initiator to create a connection intent and a responder to poll pending intents.

**Files:**
- Create: `gateway/src/api/handlers/connections.rs`
- Modify: `gateway/src/api/handlers/mod.rs`
- Modify: `gateway/src/api/mod.rs`
- Test: `gateway/src/api/handlers/connections.rs`

**API shape:**

```text
POST /api/connections/intent/:initiator_endpoint_id
GET  /api/connections/pending/:endpoint_id
```

Both routes require `X-HT-Auth` for MVP. Later, narrow this to endpoint token or signed session auth.

**Step 1: Write route handler tests**

Test expectations:

- Creating an intent with a valid initiator and target returns both endpoint records.
- Pending lookup for the target returns that intent.
- Unknown target returns 404.
- Missing auth returns 401.

**Step 2: Implement storage keys**

In `connections.rs`:

```rust
fn intent_storage_key(connection_id: &str) -> Vec<u8> {
    format!("{CONNECTION_INTENT_PREFIX}/{connection_id}").into_bytes()
}

fn pending_target_prefix(target_endpoint_id: &str) -> Vec<u8> {
    format!("{CONNECTION_INTENT_PREFIX}/pending/{target_endpoint_id}/").into_bytes()
}

fn pending_target_key(target_endpoint_id: &str, connection_id: &str) -> Vec<u8> {
    format!("{CONNECTION_INTENT_PREFIX}/pending/{target_endpoint_id}/{connection_id}").into_bytes()
}
```

**Step 3: Reuse endpoint lookup helpers**

Refactor `registration_storage_key` and endpoint decode helpers in `endpoints.rs` to be `pub(crate)` if needed:

```rust
pub(crate) fn registration_storage_key(endpoint_id: &str) -> Vec<u8> { ... }
pub(crate) fn load_registration(kv: &NamespacedKv, endpoint_id: &str) -> Result<EndpointRegistrationRequest, RootApiError> { ... }
```

**Step 4: Implement create intent**

Pseudo-code:

```rust
pub(crate) async fn create_connection_intent(
    State(state): State<ApiState>,
    AxumPath(initiator_endpoint_id): AxumPath<String>,
    headers: HeaderMap,
    Json(body): Json<ConnectionIntentRequest>,
) -> Result<Json<ConnectionIntentResponse>, RootApiError> {
    let kv = clone_kv(&state);
    validate_auth(&kv, &headers)?;

    let initiator = load_registration(&kv, &initiator_endpoint_id)?;
    let target = resolve_registration_by_id_or_ip(&kv, &body.target)?;
    let target_endpoint_id = target.endpoint_id.clone().ok_or(RootApiError::NotFound)?;
    let connection_id = generate_connection_id();

    let intent = ConnectionIntent { ... };
    kv.put_bytes(&intent_storage_key(&connection_id), &serde_json::to_vec(&intent)?)?;
    kv.put_bytes(&pending_target_key(&target_endpoint_id, &connection_id), connection_id.as_bytes())?;

    Ok(Json(ConnectionIntentResponse { connection_id, initiator, target }))
}
```

**Step 5: Implement pending intents**

```rust
pub(crate) async fn get_pending_connection_intents(
    State(state): State<ApiState>,
    AxumPath(endpoint_id): AxumPath<String>,
    headers: HeaderMap,
) -> Result<Json<Vec<ConnectionIntent>>, RootApiError> { ... }
```

**Step 6: Wire routes**

In `gateway/src/api/handlers/mod.rs` export:

```rust
pub(crate) mod connections;
pub(crate) use connections::{create_connection_intent, get_pending_connection_intents};
```

In `gateway/src/api/mod.rs` add:

```rust
.route("/connections/intent/:initiator_endpoint_id", post(create_connection_intent))
.route("/connections/pending/:endpoint_id", get(get_pending_connection_intents))
```

**Step 7: Verify**

```bash
cargo test -p hightower-gateway connections
cargo test -p hightower-gateway
```

**Step 8: Commit**

```bash
git add gateway/src/api/handlers/connections.rs gateway/src/api/handlers/mod.rs gateway/src/api/mod.rs gateway/src/api/handlers/endpoints.rs gateway/src/api/types.rs
git commit -m "feat: add connection intent coordination API"
```

---

## Phase 3: Client Gateway APIs and Candidate Gathering

### Task 5: Export candidate and intent client types

**Objective:** Make the client crate expose candidate and intent structs needed by app code and internal connection broker.

**Files:**
- Modify: `client/src/types.rs`
- Modify: `client/src/lib.rs`
- Test: `client/src/types.rs`

**Step 1: Add public types**

Mirror gateway intent response types in `client/src/types.rs`:

```rust
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ConnectionIntentRequest {
    pub target: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ConnectionIntentResponse {
    pub connection_id: String,
    pub initiator: PeerInfo,
    pub target: PeerInfo,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ConnectionIntent {
    pub connection_id: String,
    pub initiator_endpoint_id: String,
    pub target_endpoint_id: String,
    pub initiator: PeerInfo,
    pub target: PeerInfo,
    pub created_at_ms: u64,
}
```

**Step 2: Export in `client/src/lib.rs`**

```rust
pub use types::{CandidateKind, ConnectionIntent, ConnectionIntentRequest, ConnectionIntentResponse, EndpointCandidate, PeerInfo};
```

**Step 3: Verify**

```bash
cargo test -p hightower-client
```

**Step 4: Commit**

```bash
git add client/src/types.rs client/src/lib.rs
git commit -m "feat: expose client connection coordination types"
```

---

### Task 6: Generate registration candidates from discovered network info

**Objective:** The client should register candidates, not only legacy public/local fields.

**Files:**
- Modify: `client/src/ip_discovery.rs`
- Modify: `client/src/connection.rs`
- Test: `client/src/ip_discovery.rs`

**Step 1: Add candidate-building unit test**

```rust
#[test]
fn network_info_builds_ordered_candidates() {
    let info = crate::NetworkInfo {
        public_ip: "71.179.92.242".to_string(),
        public_port: 50963,
        local_ip: "192.168.4.63".to_string(),
        local_port: 33565,
    };

    let candidates = info.to_candidates();
    assert_eq!(candidates.len(), 2);
    assert_eq!(candidates[0].kind, CandidateKind::Local);
    assert_eq!(candidates[0].priority, 100);
    assert_eq!(candidates[1].kind, CandidateKind::StunPublic);
    assert_eq!(candidates[1].priority, 50);
}
```

**Step 2: Implement candidate builder**

In `client/src/types.rs` or `client/src/ip_discovery.rs`:

```rust
impl NetworkInfo {
    pub(crate) fn to_candidates(&self) -> Vec<EndpointCandidate> {
        let mut candidates = Vec::new();
        if let Ok(addr) = format!("{}:{}", self.local_ip, self.local_port).parse() {
            candidates.push(EndpointCandidate { kind: CandidateKind::Local, addr, priority: 100 });
        }
        if let Ok(addr) = format!("{}:{}", self.public_ip, self.public_port).parse() {
            candidates.push(EndpointCandidate { kind: CandidateKind::StunPublic, addr, priority: 50 });
        }
        candidates
    }
}
```

**Step 3: Include candidates in registration request**

In `client/src/connection.rs`, update `register_with_gateway` payload:

```rust
let candidates = network_info.to_candidates();
let payload = RegistrationRequest {
    public_key_hex,
    public_ip: Some(network_info.public_ip.as_str()),
    public_port: Some(network_info.public_port),
    local_ip: Some(network_info.local_ip.as_str()),
    local_port: Some(network_info.local_port),
    candidates,
};
```

**Step 4: Verify**

```bash
cargo test -p hightower-client network_info_builds_ordered_candidates
cargo test -p hightower-client
```

**Step 5: Commit**

```bash
git add client/src/types.rs client/src/ip_discovery.rs client/src/connection.rs
git commit -m "feat: register endpoint candidates from client"
```

---

### Task 7: Add client methods for connection intents and pending peer sync

**Objective:** Let clients create connection intents and responders poll pending intents to authorize peers before handshakes.

**Files:**
- Modify: `client/src/connection.rs`
- Test: `client/src/connection.rs`

**Step 1: Add method signatures**

```rust
impl HightowerConnection {
    pub async fn create_connection_intent(&self, target: &str) -> Result<ConnectionIntentResponse, ClientError> { ... }

    pub async fn get_pending_connection_intents(&self) -> Result<Vec<ConnectionIntent>, ClientError> { ... }

    pub async fn sync_pending_peers(&self) -> Result<usize, ClientError> { ... }
}
```

**Step 2: Implement `create_connection_intent`**

POST to:

```text
{gateway_url}/api/connections/intent/{self.endpoint_id}
```

with body:

```rust
ConnectionIntentRequest { target: target.to_string() }
```

**Step 3: Implement `get_pending_connection_intents`**

GET:

```text
{gateway_url}/api/connections/pending/{self.endpoint_id}
```

**Step 4: Implement `sync_pending_peers`**

For each pending intent where `target_endpoint_id == self.endpoint_id`, add initiator public key and best known candidate to the underlying WireGuard connection:

```rust
let key = parse_public_key(&intent.initiator.public_key_hex)?;
let endpoint = intent.initiator.best_candidate_addr();
self.transport.connection().add_peer(key, endpoint).await?;
```

**Step 5: Add a helper to parse public keys**

Extract existing parse logic from `dial()` into:

```rust
fn parse_public_key_hex(hex_key: &str) -> Result<PublicKey25519, ClientError> { ... }
```

**Step 6: Verify**

```bash
cargo test -p hightower-client
```

**Step 7: Commit**

```bash
git add client/src/connection.rs client/src/types.rs
git commit -m "feat: add client connection intent sync"
```

---

## Phase 4: Client Virtual Router and Candidate Racing

### Task 8: Add peer candidate selection helpers

**Objective:** Prefer local candidates, then public STUN candidates, then future hole-punch/relay candidates.

**Files:**
- Modify: `client/src/types.rs`
- Test: `client/src/types.rs`

**Step 1: Write tests**

```rust
#[test]
fn peer_info_orders_candidates_by_priority() {
    let peer = PeerInfo {
        endpoint_id: Some("ht-peer".into()),
        public_key_hex: "00".repeat(32),
        token: None,
        assigned_ip: Some("100.64.0.13".into()),
        public_ip: None,
        candidates: vec![
            EndpointCandidate { kind: CandidateKind::StunPublic, addr: "71.179.92.242:50963".parse().unwrap(), priority: 50 },
            EndpointCandidate { kind: CandidateKind::Local, addr: "192.168.4.63:33565".parse().unwrap(), priority: 100 },
        ],
    };

    let ordered = peer.ordered_candidates();
    assert_eq!(ordered[0].kind, CandidateKind::Local);
}
```

**Step 2: Implement helpers**

```rust
impl PeerInfo {
    pub fn ordered_candidates(&self) -> Vec<EndpointCandidate> {
        let mut candidates = self.candidates.clone();
        candidates.sort_by_key(|candidate| std::cmp::Reverse(candidate.priority));
        candidates
    }
}
```

**Step 3: Verify**

```bash
cargo test -p hightower-client peer_info_orders_candidates_by_priority
```

**Step 4: Commit**

```bash
git add client/src/types.rs
git commit -m "feat: rank peer endpoint candidates"
```

---

### Task 9: Add connection broker module

**Objective:** Encapsulate ordered candidate fallback so `dial()` stops using virtual IPs as socket addresses.

**Files:**
- Create: `client/src/broker.rs`
- Modify: `client/src/lib.rs`
- Modify: `client/src/connection.rs`
- Test: `client/src/broker.rs`

**Step 1: Create module skeleton**

```rust
pub(crate) struct ConnectionBroker<'a> {
    connection: &'a HightowerConnection,
}

impl<'a> ConnectionBroker<'a> {
    pub(crate) fn new(connection: &'a HightowerConnection) -> Self { Self { connection } }

    pub(crate) async fn connect_to_peer(
        &self,
        peer: &PeerInfo,
    ) -> Result<wireguard::connection::Stream, ClientError> { ... }
}
```

**Step 2: Add single-candidate failure test using unreachable local port**

Use Tokio timeout and assert a `ClientError::Transport` is returned. Keep this test ignored initially if it is too timing-sensitive:

```rust
#[tokio::test]
async fn broker_reports_all_candidates_failed() { ... }
```

**Step 3: Implement sequential candidate attempts**

MVP implementation:

```rust
let key = parse_public_key_hex(&peer.public_key_hex)?;
let mut errors = Vec::new();
for candidate in peer.ordered_candidates() {
    self.connection
        .transport()
        .connection()
        .add_peer(key, Some(candidate.addr))
        .await?;

    match tokio::time::timeout(Duration::from_secs(5), self.connection.transport().connection().connect(candidate.addr, key)).await {
        Ok(Ok(stream)) => return Ok(stream),
        Ok(Err(err)) => errors.push(format!("{}: {}", candidate.addr, err)),
        Err(_) => errors.push(format!("{}: timeout", candidate.addr)),
    }
}
Err(ClientError::Transport(format!("all candidates failed: {}", errors.join(", "))))
```

Sequential candidate fallback is green. The next slice sends bounded NAT punch probes over the same UDP socket before trying public/hole-punch candidates.

**Step 4: Verify**

```bash
cargo test -p hightower-client broker
```

**Step 5: Commit**

```bash
git add client/src/broker.rs client/src/lib.rs client/src/connection.rs
git commit -m "feat: add client connection broker"
```

---

### Task 10: Rewrite `HightowerConnection::dial` to use gateway resolution and broker

**Objective:** Make `dial(peer, port)` resolve public key/candidates and connect to real endpoints instead of `assigned_ip:port`.

**Files:**
- Modify: `client/src/connection.rs`
- Test: `client/examples/peer_to_peer.rs`

**Step 1: Update `dial` flow**

Replace the current block:

```rust
let peer_addr: SocketAddr = format!("{}:{}", assigned_ip, port).parse()?;
let stream = self.transport.connection().connect(peer_addr, peer_public_key).await?;
```

with:

```rust
let intent = self.create_connection_intent(peer).await?;
let target = intent.target;
let stream = ConnectionBroker::new(self).connect_to_peer(&target).await?;
```

For MVP, `port` remains a logical app port and is not sent inside the stream yet. Add a TODO to send an app-level open-stream frame in Phase 6.

**Step 2: Keep `get_peer_info` available**

Do not remove `get_peer_info`; the broker and examples still need it.

**Step 3: Verify unit tests**

```bash
cargo test -p hightower-client
```

**Step 4: Commit**

```bash
git add client/src/connection.rs client/src/broker.rs
git commit -m "feat: dial peers through endpoint candidates"
```

---

## Phase 5: Basic Hole Punching

### Task 11: Add NAT punch probe message type outside encrypted transport

**Objective:** Add a small unauthenticated-but-self-identifying UDP probe that opens NAT mappings before WireGuard handshake.

**Files:**
- Create: `client/src/nat.rs`
- Modify: `client/src/lib.rs`
- Test: `client/src/nat.rs`

**Step 1: Add probe struct tests**

```rust
#[test]
fn hole_punch_probe_round_trips() {
    let probe = HolePunchProbe {
        connection_id: "conn-123".into(),
        endpoint_id: "ht-frank".into(),
        public_key_hex: "00".repeat(32),
    };
    let bytes = probe.to_bytes().unwrap();
    let decoded = HolePunchProbe::from_bytes(&bytes).unwrap();
    assert_eq!(decoded.connection_id, "conn-123");
}
```

**Step 2: Implement JSON probe initially**

```rust
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub(crate) struct HolePunchProbe { ... }
```

Prefix bytes with `b"HTPUNCH1\n"` so WireGuard actor can ignore it if seen accidentally.

**Step 3: Verify**

```bash
cargo test -p hightower-client nat
```

**Step 4: Commit**

```bash
git add client/src/nat.rs client/src/lib.rs
git commit -m "feat: add hole punch probe format"
```

---

### Task 12: Add simple public endpoint hole-punch attempt

**Objective:** Before candidate connect, send short bursts to the peer’s public endpoint to open NAT mappings.

**Files:**
- Modify: `client/src/broker.rs`
- Modify: `client/src/nat.rs`
- Test: `client/src/nat.rs`

**Step 1: Implement punch sender**

```rust
pub(crate) async fn send_hole_punch_burst(
    socket_addr: SocketAddr,
    probe: HolePunchProbe,
    duration: Duration,
) -> Result<(), ClientError> { ... }
```

Note: because the WireGuard `Connection` owns its UDP socket and does not currently expose `send_to`, this task has two options:

1. Add a `Connection::send_probe(addr, bytes)` command in `wireguard/src/connection.rs` and actor.
2. Use a short-lived UDP socket only for NAT probing.

Prefer option 1 if the punch must use the same source port as WireGuard. Option 2 is simpler but less useful for NAT mapping. The correct production direction is option 1.

**Step 2: Add `SendRaw` command to WireGuard connection actor**

Files:
- Modify: `wireguard/src/connection/stream.rs`
- Modify: `wireguard/src/connection/actor.rs`
- Modify: `wireguard/src/connection.rs`

Command:

```rust
Command::SendRaw { addr: SocketAddr, data: Vec<u8>, reply: oneshot::Sender<Result<(), Error>> }
```

Public method:

```rust
pub async fn send_raw(&self, addr: SocketAddr, data: Vec<u8>) -> Result<(), Error>
```

**Step 3: Ignore hole-punch probes in actor packet loop**

In `wireguard/src/connection/actor.rs`, before message-type parsing:

```rust
if data.starts_with(b"HTPUNCH1\n") {
    debug!(from = %from, "Received hole punch probe");
    return;
}
```

**Step 4: Integrate with broker**

Before trying a `CandidateKind::StunPublic` candidate, call:

```rust
self.connection.transport().connection().send_raw(candidate.addr, probe_bytes).await?;
```

Repeat every 200ms for 2 seconds while the peer is expected to do the same after pending intent sync.

**Step 5: Verify**

```bash
cargo test -p hightower-wireguard send_raw
cargo test -p hightower-client nat
cargo test -p hightower-client broker
```

**Step 6: Commit**

```bash
git add wireguard/src/connection.rs wireguard/src/connection/actor.rs wireguard/src/connection/stream.rs client/src/nat.rs client/src/broker.rs
git commit -m "feat: add udp hole punch probes"
```

---

## Phase 6: App-Level Virtual Network API

### Task 13: Add app-level endpoint identity API

**Objective:** Provide a clean app SDK that hides virtual IP/candidate details from applications.

**Files:**
- Create: `client/src/node.rs`
- Modify: `client/src/lib.rs`
- Test: `client/src/node.rs`

**Target app API:**

```rust
let node = HightowerNode::connect("http://gateway:8008", token).await?;
let mut incoming = node.listen().await?;
let mut stream = node.dial("ht-unlimited-machine-6327", 8080).await?;
```

**Step 1: Implement wrapper**

```rust
pub struct HightowerNode {
    connection: HightowerConnection,
}

impl HightowerNode {
    pub async fn connect(gateway_url: impl AsRef<str>, auth_token: impl AsRef<str>) -> Result<Self, ClientError> { ... }
    pub fn endpoint_id(&self) -> &str { self.connection.endpoint_id() }
    pub fn assigned_ip(&self) -> &str { self.connection.assigned_ip() }
    pub async fn dial(&self, peer: &str, port: u16) -> Result<wireguard::connection::Stream, ClientError> { ... }
    pub async fn listen(&self) -> Result<tokio::sync::mpsc::UnboundedReceiver<wireguard::connection::Stream>, ClientError> { ... }
}
```

**Step 2: Add listener peer sync loop helper**

```rust
pub async fn sync_pending_peers_once(&self) -> Result<usize, ClientError> {
    self.connection.sync_pending_peers().await
}
```

Do not spawn background tasks silently in MVP; make sync explicit or document it.

**Step 3: Verify**

```bash
cargo test -p hightower-client node
```

**Step 4: Commit**

```bash
git add client/src/node.rs client/src/lib.rs
git commit -m "feat: add app-level hightower node sdk"
```

---

### Task 14: Add logical open-stream frame for service/port

**Objective:** Preserve `port` as an app-level logical destination once a transport stream is established.

**Files:**
- Create: `client/src/frame.rs`
- Modify: `client/src/broker.rs`
- Modify: `client/src/connection.rs`
- Test: `client/src/frame.rs`

**Step 1: Define frame**

```rust
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub(crate) enum ControlFrame {
    OpenStream { port: u16 },
    OpenService { name: String },
}
```

Use length-prefixed JSON for MVP.

**Step 2: Add tests**

```rust
#[test]
fn open_stream_frame_round_trips() { ... }
```

**Step 3: Send frame after broker connect**

In `dial(peer, port)`:

```rust
let mut stream = ConnectionBroker::new(self).connect_to_peer(&target).await?;
frame::send_control_frame(&mut stream, ControlFrame::OpenStream { port }).await?;
Ok(stream)
```

**Step 4: Listener reads first frame**

Add a higher-level listener API in `HightowerNode` later to parse `OpenStream`. Do not force raw `Connection::listen()` users to consume frames automatically.

**Step 5: Verify**

```bash
cargo test -p hightower-client frame
cargo test -p hightower-client
```

**Step 6: Commit**

```bash
git add client/src/frame.rs client/src/broker.rs client/src/connection.rs
git commit -m "feat: add app-level stream open frame"
```

---

## Phase 7: End-to-End Tests and Examples

### Task 15: Add local two-client broker integration test

**Objective:** Prove two local clients can register, sync authorization, connect through candidates, handshake, and exchange app data.

**Files:**
- Create: `client/tests/two_client_broker.rs`
- Modify: `gateway/src/api/mod.rs` only if test helper visibility is needed

**Step 1: Build test around existing gateway test server helper**

Use `gateway::api` test utilities if already exposed. If not, add a crate-visible test helper under `#[cfg(test)]` that starts a router on a random local port.

**Step 2: Test flow**

```text
1. Start test gateway.
2. Connect client A and client B with ephemeral identities.
3. B starts listener and calls sync_pending_peers in a loop.
4. A calls dial(B.endpoint_id(), 8080).
5. B accepts stream.
6. A sends "hello".
7. B replies "world".
8. Assert A receives "world".
```

**Step 3: Verify**

```bash
cargo test -p hightower-client --test two_client_broker -- --nocapture
```

**Step 4: Commit**

```bash
git add client/tests/two_client_broker.rs gateway/src/api/mod.rs
git commit -m "test: add two-client broker integration coverage"
```

---

### Task 16: Update peer-to-peer example

**Objective:** Make `client/examples/peer_to_peer.rs` demonstrate the intended app-level path, not direct assigned-IP routing.

**Files:**
- Modify: `client/examples/peer_to_peer.rs`
- Create: `client/examples/app_level_dial.rs` if clearer

**Step 1: Update example behavior**

Responder:

```rust
let node = HightowerNode::connect(gateway, auth).await?;
loop {
    node.sync_pending_peers_once().await?;
    if let Ok(Some(stream)) = timeout(Duration::from_millis(500), incoming.recv()).await { ... }
}
```

Initiator:

```rust
let mut stream = node.dial(peer_endpoint_id, 8080).await?;
stream.send(b"hello").await?;
```

**Step 2: Verify compile**

```bash
cargo build -p hightower-client --examples
```

**Step 3: Commit**

```bash
git add client/examples/peer_to_peer.rs client/examples/app_level_dial.rs
git commit -m "docs: update peer example for app-level dialing"
```

---

## Phase 8: Deployment Verification Against frank and shotgun

### Task 17: Re-run frank/shotgun test using product APIs only

**Objective:** Verify the manual probe is no longer needed.

**Files:**
- No source changes unless the test reveals a bug.

**Step 1: Build current branch on frank**

```bash
cd /home/chris/coding-projects/hightower
cargo build -p hightower-client --examples
```

**Step 2: Sync/build on shotgun**

```bash
ssh shotgun 'cd /home/frank/coding-projects/hightower && git fetch && git checkout <branch> && cargo build -p hightower-client --examples'
```

**Step 3: Start responder on shotgun**

```bash
ssh shotgun 'cd /home/frank/coding-projects/hightower && HT_GATEWAY_URL=http://5.78.219.236:8008 HT_STUN_SERVER=5.78.219.236:3478 HT_AUTH_TOKEN=<token> cargo run -p hightower-client --example app_level_dial -- listen'
```

**Step 4: Dial from frank**

```bash
cd /home/chris/coding-projects/hightower
HT_GATEWAY_URL=http://5.78.219.236:8008 HT_STUN_SERVER=5.78.219.236:3478 HT_AUTH_TOKEN=<token> cargo run -p hightower-client --example app_level_dial -- dial <shotgun_endpoint_id>
```

**Expected evidence:**

```text
REGISTERED label=frank ...
CONNECTION_INTENT_CREATED ...
CANDIDATE_SELECTED kind=Local addr=192.168.4.63:...
SESSION: New session created (initiator)
SENT hello
REPLY reply from shotgun
```

Shotgun expected:

```text
PENDING_INTENT peer=frank
PEER_ADDED peer=frank
ACCEPTED
RECEIVED hello
REPLIED
```

**Step 5: Verify no probe processes remain**

```bash
pgrep -af hightower-probe || true
ssh shotgun 'pgrep -af hightower-probe || true'
```

**Step 6: Commit fixes if needed**

Only commit if verification revealed source changes.

---

## Phase 9: Hardening / Follow-Up Milestones

These are important but should follow the MVP above.

### Task 18: Replace auth-key intent routes with endpoint-scoped auth

**Objective:** Prevent any holder of the network auth key from creating intents for arbitrary endpoint IDs.

**Approach:** Include endpoint registration token or signed endpoint challenge in connection-intent routes.

### Task 19: Add candidate freshness and endpoint update API

**Objective:** Clients should refresh candidates when network changes without full deregister/register.

**API shape:**

```text
PUT /api/endpoints/:endpoint_id/candidates
```

### Task 20: Add relay fallback

**Objective:** Provide guaranteed connectivity when local/public/hole-punch all fail.

**Candidate shape already supports:**

```rust
CandidateKind::Relay
```

Implement later as gateway relay or DERP-like service.

### Task 21: Parallel candidate racing

**Objective:** Reduce connection latency by racing candidates instead of trying sequentially.

Start only after sequential broker is reliable.

---

## Final Verification Checklist

Run before PR:

```bash
cargo fmt --all --check
cargo test --workspace
cargo build --workspace --examples
```

Manual verification:

- [ ] Two local clients register and exchange messages through `HightowerNode`.
- [ ] frank -> shotgun works with product example, no `/tmp/hightower-probe-*` helper.
- [ ] Responder no longer logs `ProtocolError("Unknown peer")` during valid connection attempts.
- [ ] `dial(peer, port)` no longer attempts to connect to `100.64.x.x:port` as a socket destination.
- [ ] Gateway still supports old clients sending only `public_ip/public_port/local_ip/local_port`.
- [ ] Public STUN candidate failure falls back to local candidate when available.

## PR Scope Recommendation

Split implementation into three PRs:

1. **PR 1:** Candidate model + registration persistence + client candidate registration.
2. **PR 2:** Connection intents + responder peer sync.
3. **PR 3:** Client broker + `dial()` rewrite + two-client example/test.

Keep hole punching and relay fallback as follow-up PRs unless PR 3 is already stable and small.


### Task 22: Minimal UDP NAT punch probes

**Objective:** Open NAT mappings on both sides before public-candidate handshakes without adding relay infrastructure yet.

Implemented in this slice:

- `wireguard::connection::Connection::send_probe(addr, payload)` sends a small unauthenticated UDP probe from the same socket used by the encrypted transport.
- The client broker sends `HTPUNCH/1 <connection_id>` probes before attempting `StunPublic` or `HolePunch` candidates.
- The responder side sends the same probes when `sync_pending_peers()` consumes a gateway connection intent, giving both peers a bounded simultaneous punching window keyed by the gateway `connection_id`.
- `dial()` no longer takes an unused app port; apps get a peer stream and define any app-level protocol inside that stream.

Still future work:

- true concurrent candidate racing instead of ordered fallback,
- punch status reporting through the gateway,
- relay/DERP fallback for NATs that cannot be traversed directly.
