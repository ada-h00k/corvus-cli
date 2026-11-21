// Safety numbers and trust, with signal-cli's default policy (trust-new-identities on-first-use):
// the first key seen for someone is TRUSTED_UNVERIFIED; a different key later is UNTRUSTED, and
// nothing is sent to it until the user verifies it (`trust`). presage itself trusts every key, so
// the decision is kept here, in <account dir>/trust.json — encrypted when a secret unlocked the
// data (see crypto.rs), like everything else in the account directory.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::bail;
use base64::prelude::*;
use presage::libsignal_service::prelude::Uuid;
use presage::libsignal_service::protocol::{Fingerprint, IdentityKey};
use serde_json::{json, Value};
use tracing::warn;

use crate::crypto::{self, Crypto};

/// Signal's safety number parameters (version 2: identified by ACI).
const FINGERPRINT_VERSION: u32 = 2;
const FINGERPRINT_ITERATIONS: u32 = 5200;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Level {
    TrustedUnverified,
    TrustedVerified,
    Untrusted,
}

impl Level {
    pub fn as_str(self) -> &'static str {
        match self {
            Level::TrustedUnverified => "TRUSTED_UNVERIFIED",
            Level::TrustedVerified => "TRUSTED_VERIFIED",
            Level::Untrusted => "UNTRUSTED",
        }
    }

    fn parse(s: &str) -> Option<Self> {
        match s {
            "TRUSTED_UNVERIFIED" => Some(Level::TrustedUnverified),
            "TRUSTED_VERIFIED" => Some(Level::TrustedVerified),
            _ => None,
        }
    }
}

/// The key the user accepted for one person, and how.
#[derive(Debug, Clone, PartialEq)]
struct Accepted {
    key: Vec<u8>,
    level: Level,
    added: u64,
}

pub struct TrustStore {
    path: PathBuf,
    /// Present when a secret unlocked the data: the store is written encrypted, and the
    /// plaintext file of an older version is still read.
    crypto: Option<Crypto>,
    accepted: BTreeMap<Uuid, Accepted>,
}

/// The encrypted form of a trust store path (trust.json -> trust.json.enc).
fn enc_path_of(path: &Path) -> PathBuf {
    let mut name = path.file_name().map(|n| n.to_os_string()).unwrap_or_default();
    name.push(".enc");
    path.with_file_name(name)
}

impl TrustStore {
    /// Loads the trust decisions. With a secret, the encrypted store is required: a plaintext
    /// file in its place means someone replaced the data (the migration seals the plaintext at
    /// startup), and accepting it would treat every key — including a changed one — as
    /// verified again (L1). Load errors are fatal: the caller refuses to run without the trust
    /// decisions instead of starting from a clean slate.
    pub fn load(account_dir: &Path, crypto: Option<Crypto>) -> anyhow::Result<Self> {
        let path = account_dir.join("trust.json");
        let enc_path = account_dir.join("trust.json.enc");
        let bytes = match &crypto {
            Some(crypto) => {
                if enc_path.exists() {
                    Some(crypto.read_encrypted(crypto::purpose::TRUST, "", &enc_path)?)
                } else if path.exists() {
                    bail!(
                        "{} is a plaintext trust store, but this data is encrypted; refusing to trust a replaced file",
                        path.display()
                    );
                } else {
                    None
                }
            }
            None => std::fs::read(&path).ok(),
        };
        let mut accepted = BTreeMap::new();
        if let Some(bytes) = bytes {
            let Some(Value::Object(map)) = serde_json::from_slice(&bytes).ok() else {
                bail!("{} cannot be parsed as a trust store", path.display());
            };
            for (uuid, entry) in map {
                let (Ok(uuid), Some(key), Some(level)) = (
                    Uuid::parse_str(&uuid),
                    entry["key"].as_str().and_then(|k| BASE64_STANDARD.decode(k).ok()),
                    entry["level"].as_str().and_then(Level::parse),
                ) else {
                    continue;
                };
                accepted.insert(uuid, Accepted { key, level, added: entry["added"].as_u64().unwrap_or(0) });
            }
        }
        Ok(Self { path, crypto, accepted })
    }

    fn save(&self) {
        let map: serde_json::Map<String, Value> = self
            .accepted
            .iter()
            .map(|(uuid, a)| {
                (uuid.to_string(), json!({"key": BASE64_STANDARD.encode(&a.key), "level": a.level.as_str(), "added": a.added}))
            })
            .collect();
        let data = Value::Object(map).to_string();
        let written = match &self.crypto {
            Some(crypto) => crypto.seal_file(crypto::purpose::TRUST, "", &enc_path_of(&self.path), data.as_bytes()),
            None => {
                let tmp = self.path.with_extension("json.tmp");
                std::fs::write(&tmp, &data)
                    .and_then(|()| std::fs::rename(&tmp, &self.path))
                    .map_err(anyhow::Error::from)
            }
        };
        if let Err(e) = written {
            warn!(%e, "cannot save trust decisions");
        }
    }

    /// The trust level of `key` for `uuid`; a first key is accepted (and remembered) as unverified.
    pub fn level(&mut self, uuid: Uuid, key: &[u8], now: u64) -> (Level, u64) {
        match self.accepted.get(&uuid) {
            Some(a) if a.key == key => (a.level, a.added),
            Some(_) => (Level::Untrusted, now),
            None => {
                self.accepted.insert(uuid, Accepted { key: key.to_vec(), level: Level::TrustedUnverified, added: now });
                self.save();
                (Level::TrustedUnverified, now)
            }
        }
    }

    pub fn accept(&mut self, uuid: Uuid, key: &[u8], level: Level, now: u64) {
        self.accepted.insert(uuid, Accepted { key: key.to_vec(), level, added: now });
        self.save();
    }
}

pub struct SafetyNumber {
    pub display: String,
    pub scannable: String,
}

pub fn safety_number(own_aci: Uuid, own_key: &IdentityKey, remote: Uuid, remote_key: &IdentityKey) -> Option<SafetyNumber> {
    let fp = Fingerprint::new(
        FINGERPRINT_VERSION,
        FINGERPRINT_ITERATIONS,
        own_aci.as_bytes(),
        own_key,
        remote.as_bytes(),
        remote_key,
    )
    .ok()?;
    Some(SafetyNumber {
        display: fp.display_string().ok()?,
        scannable: BASE64_STANDARD.encode(fp.scannable.serialize().ok()?),
    })
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn digits(text: &str) -> String {
    text.chars().filter(char::is_ascii_digit).collect()
}

/// The error signal-cli gives for a send to a key that was not accepted; corvus looks for
/// "untrusted identity" in it.
pub fn untrusted_error(who: &str) -> String {
    format!("Failed to send message: Untrusted Identity for \"{who}\"")
}

#[cfg(test)]
mod tests {
    use super::*;
    use presage::libsignal_service::protocol::IdentityKeyPair;

    fn tmp() -> PathBuf {
        let dir = std::env::temp_dir().join(format!("corvus-cli-trust-{}-{:?}", std::process::id(), std::thread::current().id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn first_use_then_change_then_verify() {
        let dir = tmp();
        let alice = Uuid::from_u128(5);
        let mut store = TrustStore::load(&dir, None).unwrap();
        assert_eq!(store.level(alice, b"k1", 10).0, Level::TrustedUnverified);
        assert_eq!(store.level(alice, b"k1", 20), (Level::TrustedUnverified, 10));
        assert_eq!(store.level(alice, b"k2", 30).0, Level::Untrusted);
        // A change is not accepted by looking at it again.
        assert_eq!(store.level(alice, b"k2", 40).0, Level::Untrusted);
        store.accept(alice, b"k2", Level::TrustedVerified, 50);
        // Kept across restarts.
        let mut again = TrustStore::load(&dir, None).unwrap();
        assert_eq!(again.level(alice, b"k2", 60), (Level::TrustedVerified, 50));
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn encrypted_store_roundtrips_and_hides_the_keys() {
        let dir = tmp();
        let crypto = crypto::unlock(&dir, "pw", None).unwrap();
        let alice = Uuid::from_u128(7);
        let mut store = TrustStore::load(&dir, Some(crypto.clone())).unwrap();
        store.accept(alice, b"key-1", Level::TrustedVerified, 10);
        assert!(dir.join("trust.json.enc").exists());
        assert!(!dir.join("trust.json").exists());
        // The accepted key is not readable on disk.
        let raw = std::fs::read(dir.join("trust.json.enc")).unwrap();
        assert!(!raw.windows(5).any(|w| w == b"key-1"));
        // The next start (with the same secret) reads the decisions back.
        let mut again = TrustStore::load(&dir, Some(crypto::unlock(&dir, "pw", None).unwrap())).unwrap();
        assert_eq!(again.level(alice, b"key-1", 20), (Level::TrustedVerified, 10));
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn a_replaced_or_broken_trust_store_is_refused() {
        let dir = tmp();
        let crypto = crypto::unlock(&dir, "pw", None).unwrap();
        // No decisions yet: an empty store is fine.
        assert!(TrustStore::load(&dir, Some(crypto.clone())).unwrap().accepted.is_empty());
        // Someone replaced the encrypted store with plaintext data (L1): refused, not
        // accepted as an empty (or attacker-chosen) trust state.
        std::fs::write(dir.join("trust.json"), br#"{"key":"a2V5","level":"TRUSTED_UNVERIFIED"}"#).unwrap();
        assert!(TrustStore::load(&dir, Some(crypto.clone())).is_err());
        std::fs::remove_file(dir.join("trust.json")).unwrap();
        // A broken encrypted file (truncated, wrong bytes) is fatal as well.
        std::fs::write(dir.join("trust.json.enc"), b"not a frame").unwrap();
        assert!(TrustStore::load(&dir, Some(crypto.clone())).is_err());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn safety_numbers_are_symmetric_60_digits() {
        let mut rng = rand::rng();
        let (a, b) = (IdentityKeyPair::generate(&mut rng), IdentityKeyPair::generate(&mut rng));
        let (ua, ub) = (Uuid::from_u128(1), Uuid::from_u128(2));
        let ours = safety_number(ua, a.identity_key(), ub, b.identity_key()).unwrap();
        let theirs = safety_number(ub, b.identity_key(), ua, a.identity_key()).unwrap();
        assert_eq!(digits(&ours.display).len(), 60);
        assert_eq!(ours.display, theirs.display);
        assert!(untrusted_error("+49").to_lowercase().contains("untrusted identity"));
    }
}
