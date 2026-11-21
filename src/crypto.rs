// Local encryption of corvus-cli's data at rest: the account index (accounts.json), the trust
// store (trust.json), the presage SQLite store (store.db3) and the downloaded attachments.
//
// Corvus unlocks its chat history with a secret (the keychain entry, or the user's passphrase)
// and passes that same secret to every corvus-cli process in the CORVUS_CLI_SECRET environment
// variable, so one unlock opens everything. Without Corvus the variable can also be set by hand.
//
// Layout (all integers little endian):
//
// * <data dir>/keyring.enc wraps the master key, exactly like the GUI's history file wraps its
//   data key:
//
//   ```text
//   header (105 bytes)
//     "CVKR" | version u8 | argon2 m_kib u32 | t u32 | p u32 | salt[16]   <- authenticated (AAD)
//     wrap_nonce[24] | wrapped_master[32 + 16 tag]
//   ```
//
//   The master key is wrapped with a key derived from the secret via Argon2id, so changing the
//   secret re-wraps the header and nothing else.
//
// * Everything else is one frame:
//
//   ```text
//   "CVFR" | version u8 | purpose u8 | nonce[24] | ciphertext + tag
//   ```
//
//   The purpose (and for attachments the file name) is authenticated with the ciphertext, so a
//   frame cannot be moved to another use. Every purpose gets its own subkey, derived from the
//   master key with XChaCha20 in stream mode over a fixed domain nonce (the subkeys are
//   unrelated to each other and to the master key).
//
// Frames are written through a temp file + rename, so a crash never leaves a half-written file
// behind. The SQLite store is the one exception: SQLite needs a real file while the process
// runs, so it is decrypted at startup and re-encrypted on clean shutdown, and a crash leaves
// its plaintext for the next start to pick up and re-encrypt (see store::prepare_db/seal_db).

use std::fmt;
use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{anyhow, bail, Context as _};
use argon2::{Algorithm, Argon2, Block, Params, Version};
use chacha20::cipher::{KeyIvInit, StreamCipher};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use rand::TryRngCore;

pub const SECRET_ENV: &str = "CORVUS_CLI_SECRET";
pub const PREVIOUS_SECRET_ENV: &str = "CORVUS_CLI_SECRET_PREVIOUS";

const FRAME_MAGIC: &[u8; 4] = b"CVFR";
const KEYRING_MAGIC: &[u8; 4] = b"CVKR";
const VERSION: u8 = 1;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 24;
const KEY_LEN: usize = 32;
const TAG_LEN: usize = 16;
const KEYRING_AAD_LEN: usize = 4 + 1 + 12 + SALT_LEN; // magic, version, kdf params, salt
const KEYRING_LEN: usize = KEYRING_AAD_LEN + NONCE_LEN + KEY_LEN + TAG_LEN;
const FRAME_HEADER_LEN: usize = 4 + 1 + 1 + NONCE_LEN;

/// What a frame is used for; authenticated with the ciphertext and the subkey's domain.
pub mod purpose {
    pub const ACCOUNTS: u8 = 1;
    pub const TRUST: u8 = 2;
    pub const DB: u8 = 3;
    pub const ATTACH: u8 = 4;
}

/// Fixed 24-byte domain nonces for the XChaCha20 subkey derivation. The lengths are checked by
/// the type; a mistake here compiles, but a wrong length cannot.
const DOMAIN_ACCOUNTS: &[u8; 24] = b"corvus-cli/accounts.json";
const DOMAIN_TRUST: &[u8; 24] = b"corvus-cli/trust.json\0\0\0";
const DOMAIN_DB: &[u8; 24] = b"corvus-cli/store.db3\0\0\0\0";
const DOMAIN_ATTACH: &[u8; 24] = b"corvus-cli/attachments\0\0";
/// The SQLCipher key of the store (see store::open_store) is its own subkey, unrelated to the
/// one that wraps a legacy frame copy of the store file.
const DOMAIN_SQLCIPHER: &[u8; 24] = b"corvus-cli/sqlcipher key";

/// Argon2id cost parameters; the same values the GUI's history file uses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KdfParams {
    pub m_kib: u32,
    pub t: u32,
    pub p: u32,
}

impl Default for KdfParams {
    fn default() -> Self {
        // 64 MiB, 3 passes, 1 lane: well above the OWASP minimum for Argon2id.
        KdfParams { m_kib: 64 * 1024, t: 3, p: 1 }
    }
}

/// Overwrites `bytes` with zeros in a way the optimizer cannot elide (volatile writes plus a
/// compiler fence, like the GUI's history-store does for its key material).
fn wipe(bytes: &mut [u8]) {
    for b in bytes.iter_mut() {
        unsafe { std::ptr::write_volatile(b, 0) };
    }
    std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
}

/// Best-effort wipe of a String's contents (its buffer stays allocated, but zeroed), the same
/// shape the `zeroize` crate uses. The invalid UTF-8 inside the buffer is never observed: the
/// length is 0 by the time anyone can look again.
pub fn wipe_str(s: &mut String) {
    wipe(unsafe { s.as_mut_vec() }.as_mut_slice());
    s.clear();
}

/// The master key, wiped when the last clone is gone.
struct MasterKey([u8; KEY_LEN]);

impl Drop for MasterKey {
    fn drop(&mut self) {
        wipe(&mut self.0);
    }
}

/// Holds the unwrapped master key of a data directory. Cheap to clone (the key lives in an Arc);
/// the secret it was unlocked with is not kept.
#[derive(Clone)]
pub struct Crypto {
    master: Arc<MasterKey>,
    keyring: PathBuf,
}

impl fmt::Debug for Crypto {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The key must not end up in logs.
        f.debug_struct("Crypto").field("keyring", &self.keyring).finish_non_exhaustive()
    }
}

/// True when the data directory has a keyring, i.e. its data is (or was) encrypted.
pub fn keyring_exists(data_dir: &Path) -> bool {
    data_dir.join("keyring.enc").is_file()
}

/// Unlocks (or creates) the keyring of `data_dir` with `secret`. A keyring that only opens with
/// `previous` (the secret that was just replaced, passed by Corvus after a passphrase change) is
/// re-wrapped with `secret`, so one run self-heals the changed secret.
pub fn unlock(data_dir: &Path, secret: &str, previous: Option<&str>) -> anyhow::Result<Crypto> {
    let keyring = data_dir.join("keyring.enc");
    if !keyring.exists() {
        let master = new_master()?;
        let header = wrap_new(secret, &master)?;
        write_atomic(&keyring, &header)?;
        return Ok(Crypto { master: Arc::new(MasterKey(master)), keyring });
    }
    match open_keyring(&keyring, secret) {
        Ok(master) => Ok(Crypto { master: Arc::new(MasterKey(master)), keyring }),
        Err(_) => {
            let Some(prev) = previous else {
                bail!("this data is encrypted and CORVUS_CLI_SECRET does not open it (wrong passphrase or keychain entry)");
            };
            let master = open_keyring(&keyring, prev).map_err(|_| {
                anyhow!("neither CORVUS_CLI_SECRET nor its previous value opens the keyring")
            })?;
            let crypto = Crypto { master: Arc::new(MasterKey(master)), keyring };
            // The data is still encrypted with the same master key, so re-wrapping it under the
            // new secret changes nothing else.
            crypto.rewrap(secret)?;
            Ok(crypto)
        }
    }
}

impl Crypto {
    /// The subkey of a purpose, derived from the master key with a fixed domain nonce.
    fn subkey(&self, domain: &[u8; 24]) -> [u8; KEY_LEN] {
        let mut key = [0u8; KEY_LEN];
        let mut cipher = chacha20::XChaCha20::new((&self.master.0).into(), domain.into());
        cipher.apply_keystream(&mut key);
        key
    }

    /// SQLCipher's raw-key string for the store: a dedicated subkey of the master key, in the
    /// `x'<64 hex>'` form that makes SQLCipher use the key as it is instead of running PBKDF2
    /// over a passphrase on every connection (see store::open_store).
    pub fn sqlcipher_key(&self) -> String {
        let mut key = self.subkey(DOMAIN_SQLCIPHER);
        let hex: String = key.iter().map(|b| format!("{b:02x}")).collect();
        wipe(&mut key);
        format!("x'{hex}'")
    }

    fn cipher(&self, domain: &[u8; 24]) -> (XChaCha20Poly1305, [u8; KEY_LEN]) {
        let key = self.subkey(domain);
        (XChaCha20Poly1305::new((&key).into()), key)
    }

    /// Encrypts `plaintext` as one frame of `purpose`. `name` (a file name, or empty) is bound
    /// into the authentication, so a frame only opens at the place it was written for.
    pub fn seal(&self, purpose: u8, name: &str, plaintext: &[u8]) -> anyhow::Result<Vec<u8>> {
        let (cipher, mut key) = self.cipher(domain_of(purpose));
        let mut nonce = [0u8; NONCE_LEN];
        rand::rngs::OsRng.try_fill_bytes(&mut nonce).expect("os randomness unavailable");
        let mut aad = Vec::with_capacity(FRAME_HEADER_LEN + name.len());
        aad.extend_from_slice(FRAME_MAGIC);
        aad.push(VERSION);
        aad.push(purpose);
        aad.extend_from_slice(name.as_bytes());
        let ct = cipher
            .encrypt(nonce_ref(&nonce)?, Payload { msg: plaintext, aad: &aad })
            .map_err(|_| anyhow!("encryption failed"))?;
        let mut out = Vec::with_capacity(FRAME_HEADER_LEN + ct.len());
        out.extend_from_slice(FRAME_MAGIC);
        out.push(VERSION);
        out.push(purpose);
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ct);
        wipe(&mut key);
        Ok(out)
    }

    /// Decrypts a frame made by `seal`.
    pub fn open(&self, purpose: u8, name: &str, frame: &[u8]) -> anyhow::Result<Vec<u8>> {
        if frame.len() < FRAME_HEADER_LEN + TAG_LEN || &frame[..4] != FRAME_MAGIC || frame[4] != VERSION {
            bail!("not an encrypted corvus-cli file");
        }
        if frame[5] != purpose {
            bail!("this encrypted file belongs to another use");
        }
        let (cipher, mut key) = self.cipher(domain_of(purpose));
        let nonce: [u8; NONCE_LEN] = frame[6..6 + NONCE_LEN].try_into().expect("length checked above");
        let mut aad = Vec::with_capacity(FRAME_HEADER_LEN + name.len());
        aad.extend_from_slice(&frame[..6]);
        aad.extend_from_slice(name.as_bytes());
        let pt = cipher
            .decrypt(nonce_ref(&nonce)?, Payload { msg: &frame[FRAME_HEADER_LEN..], aad: &aad })
            .map_err(|_| anyhow!("this file does not open with the given secret (or was modified)"))?;
        wipe(&mut key);
        Ok(pt)
    }

    /// True when `data` starts like a frame; used to skip already-encrypted files during
    /// migration and to read files that may still be from an older, plaintext version.
    pub fn is_frame(data: &[u8]) -> bool {
        data.len() >= FRAME_HEADER_LEN + TAG_LEN && &data[..4] == FRAME_MAGIC && data[4] == VERSION
    }

    /// Reads `path` and decrypts it when it is a frame of `purpose`; plain files (from an older
    /// version) are returned as they are.
    pub fn read_file(&self, purpose: u8, name: &str, path: &Path) -> anyhow::Result<Vec<u8>> {
        let data = fs::read(path).with_context(|| format!("cannot read {}", path.display()))?;
        if Crypto::is_frame(&data) {
            self.open(purpose, name, &data)
        } else {
            Ok(data)
        }
    }

    /// Encrypts `plaintext` and writes it to `path` atomically, readable only by the user.
    pub fn seal_file(&self, purpose: u8, name: &str, path: &Path, plaintext: &[u8]) -> anyhow::Result<()> {
        let frame = self.seal(purpose, name, plaintext)?;
        write_atomic(path, &frame)
    }

    /// Re-wraps the master key under a new secret; all data stays encrypted as it is.
    pub fn rewrap(&self, secret: &str) -> anyhow::Result<()> {
        let header = wrap_new(secret, &self.master.0)?;
        write_atomic(&self.keyring, &header)
    }
}

fn domain_of(purpose: u8) -> &'static [u8; 24] {
    match purpose {
        purpose::ACCOUNTS => DOMAIN_ACCOUNTS,
        purpose::TRUST => DOMAIN_TRUST,
        purpose::DB => DOMAIN_DB,
        _ => DOMAIN_ATTACH,
    }
}

fn new_master() -> anyhow::Result<[u8; KEY_LEN]> {
    let mut key = [0u8; KEY_LEN];
    rand::rngs::OsRng.try_fill_bytes(&mut key).expect("os randomness unavailable");
    Ok(key)
}

// ---- keyring wrapping (the same layout the GUI's history file uses) -------------------------

#[derive(Clone, Copy)]
struct KeyringHeader {
    params: KdfParams,
    salt: [u8; SALT_LEN],
    nonce: [u8; NONCE_LEN],
    wrapped: [u8; KEY_LEN + TAG_LEN],
}

impl KeyringHeader {
    fn aad(&self) -> [u8; KEYRING_AAD_LEN] {
        let mut a = [0u8; KEYRING_AAD_LEN];
        a[..4].copy_from_slice(KEYRING_MAGIC);
        a[4] = VERSION;
        a[5..9].copy_from_slice(&self.params.m_kib.to_le_bytes());
        a[9..13].copy_from_slice(&self.params.t.to_le_bytes());
        a[13..17].copy_from_slice(&self.params.p.to_le_bytes());
        a[17..].copy_from_slice(&self.salt);
        a
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(KEYRING_LEN);
        v.extend_from_slice(&self.aad());
        v.extend_from_slice(&self.nonce);
        v.extend_from_slice(&self.wrapped);
        v
    }

    fn parse(buf: &[u8]) -> anyhow::Result<KeyringHeader> {
        if buf.len() < KEYRING_LEN || &buf[..4] != KEYRING_MAGIC {
            bail!("not a corvus-cli keyring");
        }
        if buf[4] != VERSION {
            bail!("unsupported keyring version {}", buf[4]);
        }
        let rd = |o: usize| u32::from_le_bytes(buf[o..o + 4].try_into().unwrap());
        let params = KdfParams { m_kib: rd(5), t: rd(9), p: rd(13) };
        // Guard against absurd values in a crafted file.
        if params.m_kib > 1 << 20 || params.t == 0 || params.t > 64 || params.p == 0 || params.p > 16 {
            bail!("implausible KDF parameters in the keyring");
        }
        // The KEYRING_LEN check above guarantees every slice has exactly the right length.
        let salt: [u8; SALT_LEN] = buf[17..17 + SALT_LEN].try_into().expect("length checked above");
        let nonce: [u8; NONCE_LEN] = buf[KEYRING_AAD_LEN..KEYRING_AAD_LEN + NONCE_LEN]
            .try_into()
            .expect("length checked above");
        let wrapped: [u8; KEY_LEN + TAG_LEN] = buf[KEYRING_AAD_LEN + NONCE_LEN..KEYRING_LEN]
            .try_into()
            .expect("length checked above");
        Ok(KeyringHeader { params, salt, nonce, wrapped })
    }

    /// A fresh header that wraps `master` under a key derived from `secret`.
    fn wrap_new(secret: &str, master: &[u8; KEY_LEN], params: KdfParams) -> anyhow::Result<KeyringHeader> {
        let mut salt = [0u8; SALT_LEN];
        let mut nonce = [0u8; NONCE_LEN];
        rand::rngs::OsRng.try_fill_bytes(&mut salt).expect("os randomness unavailable");
        rand::rngs::OsRng.try_fill_bytes(&mut nonce).expect("os randomness unavailable");
        let header = KeyringHeader { params, salt, nonce, wrapped: [0; KEY_LEN + TAG_LEN] };
        let kek = derive_kek(secret, &header.salt, params)?;
        let cipher = XChaCha20Poly1305::new((&kek).into());
        let aad = header.aad();
        let ct = cipher
            .encrypt((&header.nonce).into(), Payload { msg: master, aad: &aad })
            .map_err(|_| anyhow!("key wrapping failed"))?;
        let mut wrapped = [0u8; KEY_LEN + TAG_LEN];
        wrapped.copy_from_slice(&ct);
        let mut kek = kek;
        wipe(&mut kek);
        Ok(KeyringHeader { params, salt, nonce, wrapped })
    }

    fn unwrap_master(&self, secret: &str) -> anyhow::Result<[u8; KEY_LEN]> {
        let kek = derive_kek(secret, &self.salt, self.params)?;
        let cipher = XChaCha20Poly1305::new((&kek).into());
        let aad = self.aad();
        let pt = cipher
            .decrypt((&self.nonce).into(), Payload { msg: &self.wrapped, aad: &aad })
            .map_err(|_| anyhow!("wrong secret"))?;
        let mut pt = pt;
        if pt.len() != KEY_LEN {
            bail!("bad key length in the keyring");
        }
        let mut out = [0u8; KEY_LEN];
        out.copy_from_slice(&pt);
        wipe(&mut pt);
        let mut kek = kek;
        wipe(&mut kek);
        Ok(out)
    }
}

fn wrap_new(secret: &str, master: &[u8; KEY_LEN]) -> anyhow::Result<Vec<u8>> {
    Ok(KeyringHeader::wrap_new(secret, master, KdfParams::default())?.to_bytes())
}

fn open_keyring(keyring: &Path, secret: &str) -> anyhow::Result<[u8; KEY_LEN]> {
    let buf = fs::read(keyring).with_context(|| format!("cannot read {}", keyring.display()))?;
    KeyringHeader::parse(&buf)?.unwrap_master(secret)
}

/// Argon2id with the passphrase into a 32-byte key. The working memory is provided here instead
/// of by argon2's `alloc` feature (the same way the GUI's history-store does it) and wiped
/// afterwards.
fn derive_kek(secret: &str, salt: &[u8], p: KdfParams) -> anyhow::Result<[u8; KEY_LEN]> {
    let params = Params::new(p.m_kib, p.t, p.p, Some(KEY_LEN)).map_err(|e| anyhow!("kdf parameters: {e}"))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params.clone());
    let n = params.block_count();
    let mut mem = vec![Block::default(); n];
    let mut out = [0u8; KEY_LEN];
    let result = argon.hash_password_into_with_memory(secret.as_bytes(), salt, &mut out, &mut mem);
    wipe(unsafe {
        // SAFETY: `Block` is a plain array of u64 words (all-zero is valid) and `mem` owns
        // exactly `mem.len()` blocks of allocated memory.
        std::slice::from_raw_parts_mut(mem.as_mut_ptr().cast(), mem.capacity() * std::mem::size_of::<Block>())
    });
    result.map_err(|e| anyhow!("key derivation failed: {e}"))?;
    Ok(out)
}

// ---- files ----------------------------------------------------------------------------------

fn nonce_ref(b: &[u8]) -> anyhow::Result<&XNonce> {
    <&XNonce>::try_from(b).map_err(|_| anyhow!("bad nonce length"))
}

/// Writes via a temp file + rename so a crash never leaves a half-written file, with
/// user-only permissions (key material and ciphertext live below these paths).
fn write_atomic(path: &Path, data: &[u8]) -> anyhow::Result<()> {
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir).with_context(|| format!("cannot create {}", dir.display()))?;
    }
    let tmp = path.with_extension("enc.tmp");
    {
        let mut o = fs::OpenOptions::new();
        o.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            o.mode(0o600);
        }
        let mut f = o.open(&tmp).with_context(|| format!("cannot write {}", tmp.display()))?;
        f.write_all(data).with_context(|| format!("cannot write {}", tmp.display()))?;
        f.sync_all().ok();
    }
    fs::rename(&tmp, path).with_context(|| format!("cannot replace {}", path.display()))?;
    Ok(())
}


#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("corvus-cli-crypto-{}-{name}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn keyring_roundtrip_and_wrong_secret() {
        let dir = tmp("keyring");
        let crypto = unlock(&dir, "right", None).unwrap();
        assert!(keyring_exists(&dir));
        // A wrong secret with no previous one must fail clearly.
        assert!(unlock(&dir, "wrong", None).is_err());
        // The unlocked keyring still seals and opens with the same master key.
        let frame = crypto.seal(purpose::ACCOUNTS, "", b"hello").unwrap();
        let again = unlock(&dir, "right", None).unwrap();
        assert_eq!(again.open(purpose::ACCOUNTS, "", &frame).unwrap(), b"hello");
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn previous_secret_rewraps() {
        let dir = tmp("rewrap");
        unlock(&dir, "old", None).unwrap();
        // First start after the change: the new secret fails, the previous one opens and the
        // keyring is re-wrapped under the new secret.
        let crypto = unlock(&dir, "new", Some("old")).unwrap();
        let frame = crypto.seal(purpose::DB, "", b"data").unwrap();
        // From now on only the new secret works.
        assert!(unlock(&dir, "old", None).is_err());
        let again = unlock(&dir, "new", None).unwrap();
        assert_eq!(again.open(purpose::DB, "", &frame).unwrap(), b"data");
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn frames_do_not_open_elsewhere() {
        let dir = tmp("frames");
        let crypto = unlock(&dir, "pw", None).unwrap();
        let data = b"attachment bytes";
        let frame = crypto.seal(purpose::ATTACH, "abc123", data).unwrap();
        // The right place opens it.
        assert_eq!(crypto.open(purpose::ATTACH, "abc123", &frame).unwrap(), data);
        // Another file name, another purpose, another secret: none of them open it.
        assert!(crypto.open(purpose::ATTACH, "other", &frame).is_err());
        assert!(crypto.open(purpose::DB, "abc123", &frame).is_err());
        let other = unlock(&tmp("frames2"), "pw", None).unwrap();
        assert!(other.open(purpose::ATTACH, "abc123", &frame).is_err());
        // A flipped byte is rejected (authentication), as is a moved purpose byte.
        let mut tampered = frame.clone();
        tampered[5] = purpose::DB;
        assert!(crypto.open(purpose::DB, "abc123", &tampered).is_err());
        let mut flipped = frame.clone();
        let last = flipped.len() - 1;
        flipped[last] ^= 1;
        assert!(crypto.open(purpose::ATTACH, "abc123", &flipped).is_err());
        fs::remove_dir_all(dir).unwrap();
        fs::remove_dir_all(tmp("frames2")).unwrap();
    }

    #[test]
    fn files_roundtrip_atomically_and_stay_on_disk() {
        let dir = tmp("files");
        let crypto = unlock(&dir, "pw", None).unwrap();
        let path = dir.join("accounts.json.enc");
        crypto.seal_file(purpose::ACCOUNTS, "", &path, br#"{"+49172":"uuid"}"#).unwrap();
        // No plaintext copy is left behind (the temp file is renamed away).
        assert!(!dir.join("accounts.json.enc.tmp").exists());
        let raw = fs::read(&path).unwrap();
        assert!(!raw.windows(6).any(|w| w == b"+49172"));
        let back = crypto.read_file(purpose::ACCOUNTS, "", &path).unwrap();
        assert_eq!(back, br#"{"+49172":"uuid"}"#);
        // Old plaintext files still read.
        let legacy = dir.join("legacy.bin");
        fs::write(&legacy, b"old bytes").unwrap();
        assert_eq!(crypto.read_file(purpose::ATTACH, "legacy.bin", &legacy).unwrap(), b"old bytes");
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn plaintext_is_wiped_when_keys_are_dropped() {
        // MasterKey wipes on drop; check through a raw copy of the mechanism.
        let mut key = MasterKey([0x55u8; KEY_LEN]);
        let ptr = key.0.as_mut_ptr();
        // SAFETY: `key` is not used as a MasterKey again after drop_in_place.
        unsafe { std::ptr::drop_in_place(&mut key) };
        let bytes = unsafe { std::slice::from_raw_parts(ptr, KEY_LEN) };
        assert!(bytes.iter().all(|&b| b == 0));
        std::mem::forget(key);
    }
}
