use crate::connection::{parse_public_key_hex, HightowerConnection};
use crate::error::ClientError;
use crate::types::{CandidateKind, PeerInfo};
use std::time::Duration;
use tracing::{debug, warn};

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

            // Public endpoints may need a hole-punch phase.  The MVP broker still
            // attempts the candidate directly; the explicit NAT probe layer is a
            // follow-up built on this candidate abstraction.
            if matches!(
                candidate.kind,
                CandidateKind::StunPublic | CandidateKind::HolePunch
            ) {
                debug!(addr = %candidate.addr, "Trying public/NAT candidate");
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
}
