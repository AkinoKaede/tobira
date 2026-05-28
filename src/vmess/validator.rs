use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{anyhow, Result};

use super::auth::AuthVerifier;

/// Upstream transport type.
#[derive(Debug, Clone)]
pub enum Transport {
    Tcp,
    Grpc {
        service_name: String,
        tls_sni: String,
    },
}

/// A single upstream target.
#[derive(Debug, Clone)]
pub struct Upstream {
    /// "host:port" (for logging and pool keying)
    pub addr: String,
    /// Pre-parsed socket address for efficient connection
    pub parsed_addr: SocketAddr,
    pub transport: Transport,
    #[allow(dead_code)]
    pub tcp_fast_open: bool,
}

/// A validated entry binding a UUID (as its AuthVerifier) to an Upstream.
struct Entry {
    #[allow(dead_code)]
    uuid: String,
    verifier: AuthVerifier,
    upstream: Arc<Upstream>,
}

/// Thread-safe routing table mapping Auth IDs to upstreams.
///
/// Shared via `Arc<tokio::sync::RwLock<Validator>>` across tasks.
pub struct Validator {
    entries: Vec<Entry>,
}

impl Validator {
    /// Build a Validator from a list of `(uuid, upstream)` pairs.
    /// Returns `Err` if any UUID is duplicated.
    pub fn new(pairs: Vec<(String, Arc<Upstream>)>) -> Result<Self> {
        let mut seen = std::collections::HashSet::new();
        let mut entries = Vec::with_capacity(pairs.len());
        for (uuid, upstream) in pairs {
            if !seen.insert(uuid.clone()) {
                return Err(anyhow!("duplicate UUID: {}", uuid));
            }
            let verifier = AuthVerifier::from_uuid(&uuid)?;
            entries.push(Entry {
                uuid,
                verifier,
                upstream,
            });
        }
        Ok(Self { entries })
    }

    /// Try every entry until one matches `auth_id`.
    /// Returns `Some(upstream)` on success, `None` on failure.
    pub fn match_auth_id(&self, auth_id: &[u8; 16]) -> Option<Arc<Upstream>> {
        for entry in &self.entries {
            if entry.verifier.verify(auth_id) {
                return Some(entry.upstream.clone());
            }
        }
        None
    }

    /// Number of configured entries.
    #[allow(dead_code)]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vmess::auth::AuthVerifier;
    use aes::cipher::{BlockEncrypt, KeyInit};
    use aes::Aes128;
    use rand::Rng;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn make_auth_id(uuid: &str) -> [u8; 16] {
        let verifier = AuthVerifier::from_uuid(uuid).unwrap();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let mut plain = [0u8; 16];
        plain[0..8].copy_from_slice(&now.to_be_bytes());
        rand::thread_rng().fill(&mut plain[8..12]);
        let checksum = crc32fast::hash(&plain[0..12]);
        plain[12..16].copy_from_slice(&checksum.to_be_bytes());
        let cipher = Aes128::new_from_slice(&verifier.ecb_key).unwrap();
        let mut block = aes::cipher::generic_array::GenericArray::clone_from_slice(&plain);
        cipher.encrypt_block(&mut block);
        block.into()
    }

    fn tcp_upstream(host: &str, port: u16) -> Arc<Upstream> {
        let addr_str = format!("{}:{}", host, port);
        let parsed_addr = addr_str.parse().unwrap();
        Arc::new(Upstream {
            addr: addr_str,
            parsed_addr,
            transport: Transport::Tcp,
            tcp_fast_open: false,
        })
    }

    #[test]
    fn test_validator_routing() {
        let uuid = "550e8400-e29b-41d4-a716-446655440000";
        let upstream = tcp_upstream("127.0.0.1", 9000);
        let validator = Validator::new(vec![(uuid.to_string(), upstream.clone())]).unwrap();

        let auth_id = make_auth_id(uuid);
        let result = validator.match_auth_id(&auth_id);
        assert!(result.is_some());
        assert_eq!(result.unwrap().addr, upstream.addr);
    }

    #[test]
    fn test_validator_no_match() {
        let uuid = "550e8400-e29b-41d4-a716-446655440000";
        let upstream = tcp_upstream("127.0.0.1", 9000);
        let validator = Validator::new(vec![(uuid.to_string(), upstream)]).unwrap();

        let bad_id = [0u8; 16];
        assert!(validator.match_auth_id(&bad_id).is_none());
    }

    #[test]
    fn test_validator_duplicate_uuid() {
        let uuid = "550e8400-e29b-41d4-a716-446655440000";
        let upstream = tcp_upstream("127.0.0.1", 9000);
        let result = Validator::new(vec![
            (uuid.to_string(), upstream.clone()),
            (uuid.to_string(), upstream.clone()),
        ]);
        assert!(result.is_err());
        assert!(result.err().unwrap().to_string().contains("duplicate UUID"));
    }

    #[test]
    fn test_validator_multiple_uuids() {
        let uuid1 = "550e8400-e29b-41d4-a716-446655440000";
        let uuid2 = "550e8400-e29b-41d4-a716-446655440001";
        let up1 = tcp_upstream("127.0.0.1", 9001);
        let up2 = tcp_upstream("127.0.0.1", 9002);

        let validator = Validator::new(vec![
            (uuid1.to_string(), up1.clone()),
            (uuid2.to_string(), up2.clone()),
        ])
        .unwrap();

        let id1 = make_auth_id(uuid1);
        let id2 = make_auth_id(uuid2);

        assert_eq!(validator.match_auth_id(&id1).unwrap().addr, up1.addr);
        assert_eq!(validator.match_auth_id(&id2).unwrap().addr, up2.addr);
    }

    #[test]
    fn test_validator_concurrent_reads() {
        use std::sync::Arc;
        use std::thread;

        let uuid = "550e8400-e29b-41d4-a716-446655440000";
        let upstream = tcp_upstream("127.0.0.1", 9000);
        let validator = Arc::new(Validator::new(vec![(uuid.to_string(), upstream)]).unwrap());

        let bad_id = [0u8; 16];
        let handles: Vec<_> = (0..8)
            .map(|_| {
                let v = validator.clone();
                thread::spawn(move || {
                    assert!(v.match_auth_id(&bad_id).is_none());
                })
            })
            .collect();
        for h in handles {
            h.join().unwrap();
        }
    }
}
