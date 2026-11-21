// On-disk layout: <data dir>/accounts/<aci>/{store.db3,attachments/} plus accounts.json
// (number -> aci). When a secret is available (see crypto.rs), the index is accounts.json.enc,
// the store is store.db3.enc and trust decisions live in trust.json.enc; the SQLite store is
// decrypted to its plaintext path for the run and re-encrypted on shutdown. The data dir is
// $CORVUS_CLI_DIR, else $XDG_DATA_HOME/corvus-cli, else ~/.local/share/corvus-cli.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context as _};
use presage::libsignal_service::prelude::phonenumber::{self, PhoneNumber};
use presage::model::identity::OnNewIdentity;
use presage_store_sqlite::SqliteStore;
use tracing::warn;

use crate::crypto::{self, Crypto};

pub fn data_dir(config: Option<&Path>) -> PathBuf {
    if let Some(dir) = config {
        return dir.to_path_buf();
    }
    if let Some(dir) = std::env::var_os("CORVUS_CLI_DIR") {
        return dir.into();
    }
    let base = std::env::var_os("XDG_DATA_HOME")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .unwrap_or_else(|| home().join(".local/share"));
    base.join("corvus-cli")
}

fn home() -> PathBuf {
    std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
}

/// Creates a directory readable only by the user (key material lives below it).
pub fn private_dir(path: &Path) -> anyhow::Result<()> {
    fs::create_dir_all(path).with_context(|| format!("cannot create {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

pub fn e164(number: &PhoneNumber) -> String {
    number.format().mode(phonenumber::Mode::E164).to_string()
}

pub struct Accounts {
    dir: PathBuf,
    /// Present when a secret unlocked the data; then every write goes out encrypted.
    crypto: Option<Crypto>,
}

impl Accounts {
    pub fn new(dir: PathBuf, crypto: Option<Crypto>) -> Self {
        Self { dir, crypto }
    }

    fn index_path(&self) -> PathBuf {
        self.dir.join("accounts.json")
    }

    fn index_enc_path(&self) -> PathBuf {
        self.dir.join("accounts.json.enc")
    }

    /// number -> account directory name
    pub fn list(&self) -> BTreeMap<String, String> {
        // The encrypted index wins; the plaintext one is only read before the migration ran
        // (it is sealed at startup and never written again) and when no secret is available.
        if let Some(crypto) = &self.crypto {
            if self.index_enc_path().exists() {
                return crypto
                    .read_file(crypto::purpose::ACCOUNTS, "", &self.index_enc_path())
                    .ok()
                    .and_then(|data| serde_json::from_slice(&data).ok())
                    .unwrap_or_default();
            }
        }
        fs::read(self.index_path())
            .ok()
            .and_then(|data| serde_json::from_slice(&data).ok())
            .unwrap_or_default()
    }

    fn save(&self, index: &BTreeMap<String, String>) -> anyhow::Result<()> {
        private_dir(&self.dir)?;
        let data = serde_json::to_vec_pretty(index)?;
        if let Some(crypto) = &self.crypto {
            crypto.seal_file(crypto::purpose::ACCOUNTS, "", &self.index_enc_path(), &data)?;
            // A plaintext index from an older version must not survive next to the encrypted one.
            wipe_and_remove(&self.index_path());
            return Ok(());
        }
        let tmp = self.dir.join("accounts.json.tmp");
        fs::write(&tmp, data).with_context(|| format!("cannot write account index {}", tmp.display()))?;
        let index_path = self.index_path();
        fs::rename(&tmp, &index_path)
            .with_context(|| format!("cannot replace account index {}", index_path.display()))?;
        Ok(())
    }

    pub fn account_dir(&self, name: &str) -> PathBuf {
        self.dir.join("accounts").join(name)
    }

    /// The directory of a linked account, by phone number or ACI.
    pub fn find(&self, account: &str) -> anyhow::Result<PathBuf> {
        let index = self.list();
        let name = index
            .get(account)
            .cloned()
            .or_else(|| index.values().find(|v| v.as_str() == account).cloned());
        match name {
            Some(name) => Ok(self.account_dir(&name)),
            None => bail!("User {account} is not registered."),
        }
    }

    /// A fresh directory for linking; it is renamed by `register` once linking succeeded.
    pub fn staging_dir(&self) -> anyhow::Result<PathBuf> {
        private_dir(&self.dir)?;
        let accounts = self.dir.join("accounts");
        private_dir(&accounts)?;
        // Leftovers of interrupted links hold keys of devices that were never linked.
        for entry in fs::read_dir(&accounts)?.flatten() {
            if entry.file_name().to_string_lossy().starts_with(".link-") {
                let _ = fs::remove_dir_all(entry.path());
            }
        }
        let dir = accounts.join(format!(".link-{}", std::process::id()));
        private_dir(&dir)?;
        Ok(dir)
    }

    /// Moves a linked staging directory into place and records the account.
    /// Linking the same number again replaces the old (now unusable) device data.
    pub fn register(&self, staging: &Path, number: &str, aci: &str) -> anyhow::Result<()> {
        let target = self.account_dir(aci);
        if target.exists() {
            fs::remove_dir_all(&target)
                .with_context(|| format!("cannot remove previous account directory {}", target.display()))?;
        }
        fs::rename(staging, &target).with_context(|| {
            format!(
                "cannot move linked account data from {} to {}",
                staging.display(),
                target.display()
            )
        })?;
        let mut index = self.list();
        index.retain(|_, v| v != aci);
        index.insert(number.to_string(), aci.to_string());
        self.save(&index)
    }
}

pub async fn open_store(account_dir: &Path) -> anyhow::Result<SqliteStore> {
    private_dir(account_dir)?;
    let url = format!("sqlite://{}", account_dir.join("store.db3").display());
    // Like signal-cli's default (trust on first use): new identities are accepted and marked unverified.
    SqliteStore::open(&url, OnNewIdentity::Trust)
        .await
        .with_context(|| format!("cannot open store in {}", account_dir.display()))
}

pub fn attachments_dir(account_dir: &Path) -> PathBuf {
    account_dir.join("attachments")
}

// ---- encrypted data at rest -----------------------------------------------------------------

/// Decrypts the SQLite store of `account_dir` so presage can open it at its usual path. A
/// plaintext store.db3 (left behind by a crashed run, or written by an older version) wins: it
/// holds the newest state, and seal_db re-encrypts it on the next clean shutdown.
pub fn prepare_db(account_dir: &Path, crypto: &Crypto) -> anyhow::Result<()> {
    let db = account_dir.join("store.db3");
    if db.exists() {
        return Ok(());
    }
    let enc = account_dir.join("store.db3.enc");
    if !enc.exists() {
        return Ok(());
    }
    let data = crypto.read_file(crypto::purpose::DB, "", &enc)?;
    private_dir(account_dir)?;
    write_private_file(&db, &data)?;
    Ok(())
}

/// Re-encrypts the SQLite store after the process closed it and removes the plaintext, so the
/// account directory holds no readable session keys while corvus-cli is not running. Callers
/// only seal after the store was closed successfully; a leftover write-ahead log means the
/// newest state is not in the main file yet, and then nothing is sealed (the next start picks
/// the plaintext up instead of losing it).
pub fn seal_db(account_dir: &Path, crypto: &Crypto) -> anyhow::Result<()> {
    let db = account_dir.join("store.db3");
    if !db.exists() {
        return Ok(());
    }
    let wal = account_dir.join("store.db3-wal");
    if wal.is_file() && fs::metadata(&wal)?.len() > 0 {
        bail!("the store still has an uncheckpointed write-ahead log; leaving it for the next start");
    }
    let data = fs::read(&db).with_context(|| format!("cannot read {}", db.display()))?;
    crypto.seal_file(crypto::purpose::DB, "", &account_dir.join("store.db3.enc"), &data)?;
    // The encrypted copy exists now; the plaintext (and any journal leftovers) can go.
    wipe_and_remove(&db);
    for leftover in ["store.db3-wal", "store.db3-shm", "store.db3-journal"] {
        wipe_and_remove(&account_dir.join(leftover));
    }
    Ok(())
}

/// One-time encryption of the files an older, plaintext version left behind. Runs after the
/// keyring is unlocked, before any command. Cheap when there is nothing to do.
pub fn migrate_legacy(data_dir: &Path, crypto: &Crypto) -> anyhow::Result<()> {
    let index = data_dir.join("accounts.json");
    if index.exists() {
        let data = fs::read(&index).with_context(|| format!("cannot read {}", index.display()))?;
        crypto.seal_file(crypto::purpose::ACCOUNTS, "", &data_dir.join("accounts.json.enc"), &data)?;
        wipe_and_remove(&index);
    }
    // The account directory names come from the index, which is encrypted by now.
    let index_enc = data_dir.join("accounts.json.enc");
    let Ok(data) = crypto.read_file(crypto::purpose::ACCOUNTS, "", &index_enc) else {
        return Ok(());
    };
    let Ok(index) = serde_json::from_slice::<BTreeMap<String, String>>(&data) else {
        return Ok(());
    };
    for name in index.into_values() {
        let dir = data_dir.join("accounts").join(name);
        let trust = dir.join("trust.json");
        if trust.exists() {
            match fs::read(&trust) {
                Ok(data) => {
                    if let Err(e) = crypto.seal_file(crypto::purpose::TRUST, "", &dir.join("trust.json.enc"), &data) {
                        warn!(%e, "cannot encrypt the trust store");
                    } else {
                        wipe_and_remove(&trust);
                    }
                }
                Err(e) => warn!(%e, "cannot read the plaintext trust store"),
            }
        }
        let attachments = attachments_dir(&dir);
        let Ok(entries) = fs::read_dir(&attachments) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            let Ok(data) = fs::read(&path) else {
                continue;
            };
            if Crypto::is_frame(&data) {
                continue;
            }
            let name = entry.file_name().to_string_lossy().into_owned();
            // The frame replaces the file in place (temp file + rename); an interrupted write
            // leaves the old plaintext for the next start.
            if let Err(e) = crypto.seal_file(crypto::purpose::ATTACH, &name, &path, &data) {
                warn!(%e, name, "cannot encrypt an attachment");
            }
        }
    }
    Ok(())
}

/// Overwrites a file with zeros before unlinking it. Best effort: some filesystems keep the old
/// blocks anyway, but this beats a plain unlink for the plaintext that must not be recovered.
fn wipe_and_remove(path: &Path) {
    let wipe = |path: &Path| -> std::io::Result<()> {
        let len = fs::metadata(path)?.len();
        let mut f = fs::OpenOptions::new().write(true).open(path)?;
        std::io::Write::write_all(&mut f, &vec![0u8; len as usize])?;
        f.sync_all()?;
        Ok(())
    };
    if let Err(e) = wipe(path) {
        warn!(%e, path = %path.display(), "cannot overwrite a plaintext file before removing it");
    }
    if let Err(e) = fs::remove_file(path) {
        warn!(%e, path = %path.display(), "cannot remove a plaintext file");
    }
}

/// Writes a file readable only by the user, through a temp file + rename.
pub(crate) fn write_private_file(path: &Path, data: &[u8]) -> anyhow::Result<()> {
    let tmp = path.with_extension("part");
    {
        let mut o = fs::OpenOptions::new();
        o.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            o.mode(0o600);
        }
        let mut f = o.open(&tmp).with_context(|| format!("cannot write {}", tmp.display()))?;
        std::io::Write::write_all(&mut f, data).with_context(|| format!("cannot write {}", tmp.display()))?;
        f.sync_all().ok();
    }
    fs::rename(&tmp, path).with_context(|| format!("cannot replace {}", path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("corvus-cli-store-{}-{name}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn index_is_encrypted_and_migrated() {
        let dir = tmp("index");
        let crypto = crypto::unlock(&dir, "pw", None).unwrap();
        // Legacy plaintext index: migrate seals and removes it.
        fs::write(dir.join("accounts.json"), br#"{"+49172":"acc1"}"#).unwrap();
        migrate_legacy(&dir, &crypto).unwrap();
        assert!(!dir.join("accounts.json").exists());
        let raw = fs::read(dir.join("accounts.json.enc")).unwrap();
        assert!(!raw.windows(6).any(|w| w == b"+49172"));
        let accounts = Accounts::new(dir.clone(), Some(crypto));
        assert_eq!(accounts.list().get("+49172").map(String::as_str), Some("acc1"));
        // A new account is saved encrypted only; its staging directory moves into place.
        let staging = dir.join("accounts").join(".link-1");
        fs::create_dir_all(&staging).unwrap();
        accounts.register(&staging, "+49170", "acc2").unwrap();
        assert!(!dir.join("accounts.json").exists());
        let again = Accounts::new(dir.clone(), None);
        assert!(again.list().is_empty()); // without the secret the encrypted index stays unreadable
        let unlocker = Accounts::new(dir.clone(), Some(crypto::unlock(&dir, "pw", None).unwrap()));
        assert_eq!(unlocker.list().get("+49170").map(String::as_str), Some("acc2"));
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn db_roundtrip_and_plaintext_wins() {
        let dir = tmp("db");
        let account = dir.join("accounts").join("acc1");
        fs::create_dir_all(&account).unwrap();
        let crypto = crypto::unlock(&dir, "pw", None).unwrap();
        // Legacy plaintext database: prepare keeps it, seal encrypts and removes it.
        fs::write(account.join("store.db3"), b"sqlite bytes").unwrap();
        prepare_db(&account, &crypto).unwrap();
        assert_eq!(fs::read(account.join("store.db3")).unwrap(), b"sqlite bytes");
        seal_db(&account, &crypto).unwrap();
        assert!(!account.join("store.db3").exists());
        let raw = fs::read(account.join("store.db3.enc")).unwrap();
        assert!(!raw.windows(6).any(|w| w == b"sqlite"));
        // Encrypted database: prepare restores it, with user-only permissions.
        prepare_db(&account, &crypto).unwrap();
        assert_eq!(fs::read(account.join("store.db3")).unwrap(), b"sqlite bytes");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(fs::metadata(account.join("store.db3")).unwrap().permissions().mode() & 0o777, 0o600);
        }
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn dirty_wal_blocks_sealing() {
        let dir = tmp("wal");
        let account = dir.join("accounts").join("acc1");
        fs::create_dir_all(&account).unwrap();
        let crypto = crypto::unlock(&dir, "pw", None).unwrap();
        fs::write(account.join("store.db3"), b"sqlite bytes").unwrap();
        fs::write(account.join("store.db3-wal"), b"uncheckpointed frames").unwrap();
        assert!(seal_db(&account, &crypto).is_err());
        assert_eq!(fs::read(account.join("store.db3")).unwrap(), b"sqlite bytes");
        fs::remove_dir_all(dir).unwrap();
    }
}
