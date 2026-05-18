use crate::connection::{parse_public_key_hex, HightowerConnection};
use crate::error::ClientError;
use crate::types::{CandidateKind, EndpointCandidate, PeerInfo};
use std::time::Duration;
use tracing::{debug, warn};

const NAT_PROBE_ATTEMPTS: usize = 3;
const NAT_PROBE_INTERVAL: Duration = Duration::from_millis(75);

pub(crate) struct ConnectionBroker<'a> {
    connection: &'a HightowerConnection,
}

impl<'a> ConnectionBroker<'a> {
    pub(crate) fn new(connection: &'a HightowerConnection) -> Self {
        Self { connection }
    }

    pub(crate) async fn connect_to_peer(
        &self,
        peer: &PeerInfo,
        connection_id: &str,
    ) -> Result<wireguard::connection::Stream, ClientError> {
        let peer_public_key = parse_public_key_hex(&peer.public_key_hex)?;
        let candidates = peer.ordered_candidates();
        if candidates.is_empty() {
            return Err(ClientError::Transport(
                "peer has no endpoint candidates".to_string(),
            ));
        }

        let mut failures = Vec::new();
        for candidate in candidates {
            debug!(
                kind = ?candidate.kind,
                addr = %candidate.addr,
                priority = candidate.priority,
                "Trying peer endpoint candidate"
            );

            if let Err(err) = self
                .connection
                .transport()
                .connection()
                .add_peer(peer_public_key, Some(candidate.addr))
                .await
            {
                let message = format!("{} add_peer failed: {}", candidate.addr, err);
                warn!(%message);
                failures.push(message);
                continue;
            }

            if is_nat_candidate(&candidate) {
                self.send_nat_probes(&candidate, connection_id).await;
            }

            match tokio::time::timeout(
                Duration::from_secs(10),
                self.connection
                    .transport()
                    .connection()
                    .connect(candidate.addr, peer_public_key),
            )
            .await
            {
                Ok(Ok(stream)) => {
                    debug!(addr = %candidate.addr, "Selected peer endpoint candidate");
                    return Ok(stream);
                }
                Ok(Err(err)) => {
                    let message = format!("{} connect failed: {}", candidate.addr, err);
                    warn!(%message);
                    failures.push(message);
                }
                Err(_) => {
                    let message = format!("{} connect timed out", candidate.addr);
                    warn!(%message);
                    failures.push(message);
                }
            }
        }

        Err(ClientError::Transport(format!(
            "all endpoint candidates failed: {}",
            failures.join("; ")
        )))
    }

    pub(crate) async fn punch_candidates(&self, peer: &PeerInfo, connection_id: &str) {
        for candidate in peer
            .ordered_candidates()
            .into_iter()
            .filter(is_nat_candidate)
        {
            self.send_nat_probes(&candidate, connection_id).await;
        }
    }

    async fn send_nat_probes(&self, candidate: &EndpointCandidate, connection_id: &str) {
        let payload = format!("HTPUNCH/1 {connection_id}").into_bytes();
        for attempt in 0..NAT_PROBE_ATTEMPTS {
            match self
                .connection
                .transport()
                .connection()
                .send_probe(candidate.addr, &payload)
                .await
            {
                Ok(()) => debug!(
                    addr = %candidate.addr,
                    attempt = attempt + 1,
                    connection_id,
                    "Sent NAT punch probe"
                ),
                Err(err) => warn!(
                    addr = %candidate.addr,
                    attempt = attempt + 1,
                    error = %err,
                    "Failed to send NAT punch probe"
                ),
            }
            tokio::time::sleep(NAT_PROBE_INTERVAL).await;
        }
    }
}

fn is_nat_candidate(candidate: &EndpointCandidate) -> bool {
    matches!(
        candidate.kind,
        CandidateKind::StunPublic | CandidateKind::HolePunch
    )
}
