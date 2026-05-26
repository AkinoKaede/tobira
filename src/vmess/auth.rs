use aes::cipher::{generic_array::GenericArray, BlockDecrypt, KeyInit};
use aes::Aes128;
/// VMess Auth ID verification.
///
/// Algorithm (matching v2ray-core):
///   instruction_key[16] = MD5(uuid_bytes || "c48619fe-8f02-49e0-b9e9-edf763e17e21")
///   aes_ecb_key[16]     = KDF(instruction_key, ["AES Auth ID Encryption"])[0:16]
///   decrypted[16]       = AES-128-ECB-Decrypt(auth_id[16], aes_ecb_key)
///   checksum_ok         = crc32_ieee(decrypted[0:12]) == u32_be(decrypted[12:16])
///   timestamp_ok        = |unix_now - u64_be(decrypted[0:8])| ≤ 120
use anyhow::{anyhow, Result};
use md5::Md5;
use sha2::Digest as _;
use sha2::Sha256;
use std::time::{SystemTime, UNIX_EPOCH};

// ──────────────────────────────────────────────────────────────────────────────
// KDF — direct port of shoes/src/vmess/sha2.rs
// ──────────────────────────────────────────────────────────────────────────────

trait VmessHash: Send + Sync {
    fn clone_state(&self) -> Box<dyn VmessHash>;
    fn update(&mut self, data: &[u8]);
    fn finalize(&mut self) -> [u8; 32];
}

struct Sha256Hash(Sha256);

impl VmessHash for Sha256Hash {
    fn clone_state(&self) -> Box<dyn VmessHash> {
        Box::new(Sha256Hash(self.0.clone()))
    }
    fn update(&mut self, data: &[u8]) {
        sha2::Digest::update(&mut self.0, data);
    }
    fn finalize(&mut self) -> [u8; 32] {
        let result = sha2::Digest::finalize(self.0.clone());
        let mut out = [0u8; 32];
        out.copy_from_slice(&result);
        out
    }
}

struct RecursiveHash {
    inner: Box<dyn VmessHash>,
    outer: Box<dyn VmessHash>,
    default_inner: [u8; 64],
    default_outer: [u8; 64],
}

impl RecursiveHash {
    fn create(key: &[u8], hash: Box<dyn VmessHash>) -> Self {
        assert!(key.len() <= 64, "KDF key must be ≤ 64 bytes");
        let mut default_outer = [0x5cu8; 64];
        let mut default_inner = [0x36u8; 64];
        for (i, &b) in key.iter().enumerate() {
            default_outer[i] ^= b;
            default_inner[i] ^= b;
        }
        let mut inner = hash.clone_state();
        let outer = hash;
        inner.update(&default_inner);
        RecursiveHash {
            inner,
            outer,
            default_inner,
            default_outer,
        }
    }
}

impl VmessHash for RecursiveHash {
    fn clone_state(&self) -> Box<dyn VmessHash> {
        Box::new(RecursiveHash {
            inner: self.inner.clone_state(),
            outer: self.outer.clone_state(),
            default_inner: self.default_inner,
            default_outer: self.default_outer,
        })
    }
    fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }
    fn finalize(&mut self) -> [u8; 32] {
        self.outer.update(&self.default_outer);
        let inner_result = self.inner.finalize();
        self.outer.update(&inner_result);
        self.outer.finalize()
    }
}

/// VMess KDF — identical to v2ray-core's `kdf()` function.
pub fn kdf(key: &[u8], path: &[&[u8]]) -> [u8; 32] {
    let mut current: Box<dyn VmessHash> = Box::new(RecursiveHash::create(
        b"VMess AEAD KDF",
        Box::new(Sha256Hash(Sha256::new())),
    ));
    for path_item in path {
        current = Box::new(RecursiveHash::create(path_item, current));
    }
    current.update(key);
    current.finalize()
}

// ──────────────────────────────────────────────────────────────────────────────
// UUID → instruction_key
// ──────────────────────────────────────────────────────────────────────────────

/// Parse a UUID string ("xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx") to 16 raw bytes.
pub fn parse_uuid(uuid: &str) -> Result<[u8; 16]> {
    let hex: String = uuid.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    if hex.len() != 32 {
        return Err(anyhow!(
            "invalid UUID: expected 32 hex chars, got {}",
            hex.len()
        ));
    }
    let mut bytes = [0u8; 16];
    for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
        bytes[i] = u8::from_str_radix(std::str::from_utf8(chunk)?, 16)?;
    }
    Ok(bytes)
}

/// Compute instruction_key = MD5(uuid_bytes || magic_salt)
fn instruction_key(uuid_bytes: &[u8; 16]) -> [u8; 16] {
    let mut hasher = Md5::new();
    md5::Digest::update(&mut hasher, uuid_bytes);
    md5::Digest::update(&mut hasher, b"c48619fe-8f02-49e0-b9e9-edf763e17e21");
    md5::Digest::finalize(hasher).into()
}

// ──────────────────────────────────────────────────────────────────────────────
// Auth ID verifier
// ──────────────────────────────────────────────────────────────────────────────

/// Pre-computed per-UUID state for verifying VMess AEAD Auth IDs.
#[derive(Clone)]
pub struct AuthVerifier {
    #[cfg(test)]
    pub(crate) ecb_key: [u8; 16],
    cipher: Aes128,
}

impl AuthVerifier {
    /// Build a verifier from a UUID string.
    pub fn from_uuid(uuid: &str) -> Result<Self> {
        let uuid_bytes = parse_uuid(uuid)?;
        let ikey = instruction_key(&uuid_bytes);
        let derived = kdf(&ikey, &[b"AES Auth ID Encryption"]);
        let mut ecb_key = [0u8; 16];
        ecb_key.copy_from_slice(&derived[0..16]);
        let cipher = Aes128::new(GenericArray::from_slice(&ecb_key));
        Ok(Self {
            #[cfg(test)]
            ecb_key,
            cipher,
        })
    }

    /// Attempt to verify a 16-byte Auth ID.
    /// Returns `true` if the checksum and timestamp are valid.
    pub fn verify(&self, auth_id: &[u8; 16]) -> bool {
        // Decrypt with AES-128-ECB
        let mut block = GenericArray::clone_from_slice(auth_id);
        self.cipher.decrypt_block(&mut block);
        let decrypted: [u8; 16] = block.into();

        // CRC32 IEEE checksum check
        let checksum = crc32fast::hash(&decrypted[0..12]);
        let expected = u32::from_be_bytes(decrypted[12..16].try_into().unwrap());
        if checksum != expected {
            return false;
        }

        // Timestamp within ±120 seconds
        let timestamp = u64::from_be_bytes(decrypted[0..8].try_into().unwrap());
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        now.abs_diff(timestamp) <= 120
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_uuid_valid() {
        let uuid = "550e8400-e29b-41d4-a716-446655440000";
        let bytes = parse_uuid(uuid).unwrap();
        assert_eq!(bytes.len(), 16);
        assert_eq!(bytes[0], 0x55);
        assert_eq!(bytes[1], 0x0e);
    }

    #[test]
    fn test_parse_uuid_invalid() {
        assert!(parse_uuid("not-a-uuid").is_err());
        assert!(parse_uuid("").is_err());
    }

    #[test]
    fn test_kdf_deterministic() {
        let key = b"test-key";
        let r1 = kdf(key, &[b"AES Auth ID Encryption"]);
        let r2 = kdf(key, &[b"AES Auth ID Encryption"]);
        assert_eq!(r1, r2);
    }

    #[test]
    fn test_kdf_different_paths() {
        let key = b"test-key";
        let r1 = kdf(key, &[b"path1"]);
        let r2 = kdf(key, &[b"path2"]);
        assert_ne!(r1, r2);
    }

    #[test]
    fn test_kdf_empty_path() {
        let key = b"test-key";
        let result = kdf(key, &[]);
        assert_eq!(result.len(), 32);
    }

    #[test]
    fn test_auth_verifier_from_uuid() {
        let uuid = "550e8400-e29b-41d4-a716-446655440000";
        let verifier = AuthVerifier::from_uuid(uuid).unwrap();
        // The ECB key should be non-zero
        assert_ne!(verifier.ecb_key, [0u8; 16]);
    }

    #[test]
    fn test_auth_verifier_bad_data() {
        let uuid = "550e8400-e29b-41d4-a716-446655440000";
        let verifier = AuthVerifier::from_uuid(uuid).unwrap();
        // Random bytes should fail verification
        let bad_auth_id = [0u8; 16];
        assert!(!verifier.verify(&bad_auth_id));
    }

    #[test]
    fn test_auth_id_round_trip() {
        // Generate a valid auth ID for a known UUID and verify it.
        use aes::cipher::BlockEncrypt;
        use rand::Rng;

        let uuid = "550e8400-e29b-41d4-a716-446655440000";
        let verifier = AuthVerifier::from_uuid(uuid).unwrap();

        // Build a valid auth ID
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let mut plain = [0u8; 16];
        plain[0..8].copy_from_slice(&now.to_be_bytes());
        rand::thread_rng().fill(&mut plain[8..12]);
        let checksum = crc32fast::hash(&plain[0..12]);
        plain[12..16].copy_from_slice(&checksum.to_be_bytes());

        // Encrypt it
        let cipher = Aes128::new_from_slice(&verifier.ecb_key).unwrap();
        let mut block = aes::cipher::generic_array::GenericArray::clone_from_slice(&plain);
        cipher.encrypt_block(&mut block);
        let auth_id: [u8; 16] = block.into();

        assert!(verifier.verify(&auth_id));
    }

    #[test]
    fn test_auth_id_expired_timestamp() {
        use aes::cipher::BlockEncrypt;

        let uuid = "550e8400-e29b-41d4-a716-446655440000";
        let verifier = AuthVerifier::from_uuid(uuid).unwrap();

        // Use a timestamp that's 200 seconds in the past (beyond the 120s window)
        let old_time: u64 = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            .saturating_sub(200);

        let mut plain = [0u8; 16];
        plain[0..8].copy_from_slice(&old_time.to_be_bytes());
        let checksum = crc32fast::hash(&plain[0..12]);
        plain[12..16].copy_from_slice(&checksum.to_be_bytes());

        let cipher = Aes128::new_from_slice(&verifier.ecb_key).unwrap();
        let mut block = aes::cipher::generic_array::GenericArray::clone_from_slice(&plain);
        cipher.encrypt_block(&mut block);
        let auth_id: [u8; 16] = block.into();

        assert!(!verifier.verify(&auth_id));
    }
}
