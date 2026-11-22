// On-disk layout: <data dir>/accounts/<aci>/{store.db3,attachments/} plus accounts.json
// (number -> aci). When a secret is available (see crypto.rs), the index is accounts.json.enc,
// trust decisions live in trust.json.enc, and the SQLite store IS an SQLCipher database keyed
// with a subkey of the master key — encrypted at rest from the first byte on, with no
// plaintext copy at any time (see open_store). Without a secret nothing is encrypted yet: the
// files are plaintext and stay that way. The data dir is $CORVUS_CLI_DIR, else
// $XDG_DATA_HOME/corvus-cli, else ~/.local/share/corvus-cli.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context as _};
use presage::libsignal_service::prelude::phonenumber::{self, PhoneNumber};
use presage::model::identity::OnNewIdentity;
use presage_store_sqlite::{SqliteConnectOptions, SqliteStore};
use sqlx::{query, sqlite::SqlitePoolOptions};
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

/// Creates a directory readable only by the user (key material lives below it). Missing
/// components on the way are created 0700 as well (they would otherwise carry the umask's
/// group/other bits). A directory that already exists is tightened to 0700 only when it is
/// the data directory itself (leaf `corvus-cli`) — its name is ours, so chmod-ing it cannot
/// hurt a directory the user merely pointed `-c` at (L7: `-c ~` must never change the home
/// directory, whose leaf is not named corvus-cli). Every other existing directory with
/// looser permissions is refused with the exact fix, and left as it was.
pub fn private_dir(path: &Path) -> anyhow::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut walked = PathBuf::new();
        for component in path.components() {
            walked.push(component);
            if !walked.is_dir() {
                fs::create_dir(&walked).with_context(|| format!("cannot create {}", walked.display()))?;
                fs::set_permissions(&walked, fs::Permissions::from_mode(0o700))?;
            }
        }
        let meta = fs::metadata(path)?;
        if !meta.is_dir() {
            bail!("{} is not a directory", path.display());
        }
        let mode = meta.permissions().mode() & 0o777;
        if mode != 0o700 {
            if path.file_name() == Some(std::ffi::OsStr::new("corvus-cli")) {
                fs::set_permissions(path, fs::Permissions::from_mode(0o700))
                    .with_context(|| format!("cannot tighten permissions on {}", path.display()))?;
                eprintln!("note: tightened permissions on {} from {:o} to 0700", path.display(), mode);
            } else {
                bail!(
                    "{} exists with permissions {:o}; corvus-cli needs 0700 there (key material lives below; fix it yourself with: chmod 700 '{}')",
                    path.display(),
                    mode,
                    path.display()
                );
            }
        }
        return Ok(());
    }
    #[cfg(not(unix))]
    {
        fs::create_dir_all(path).with_context(|| format!("cannot create {}", path.display()))?;
        Ok(())
    }
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
        // While a secret unlocks the data, the encrypted index is the only one trusted (L1):
        // a plaintext index next to it is either a plant (the startup migration refuses to
        // seal it) or a downgrade leftover — either way it is not read here. A broken
        // encrypted index is not silently replaced by an empty one from a plaintext file:
        // the error is reported and no account is found.
        if let Some(crypto) = &self.crypto {
            if self.index_enc_path().exists() {
                return match crypto.read_encrypted(crypto::purpose::ACCOUNTS, "", &self.index_enc_path()) {
                    Ok(data) => serde_json::from_slice(&data).unwrap_or_default(),
                    Err(e) => {
                        warn!(%e, "cannot open the account index; no account can be found");
                        Default::default()
                    }
                };
            }
            // No encrypted index: there was nothing to migrate, a plaintext file here is not
            // data this version wrote.
            return Default::default();
        }
        // Without a secret nothing is encrypted yet; the plaintext index is the real one.
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
        // 0600 from the moment of creation (L7), like crypto::write_atomic's files.
        let mut options = fs::OpenOptions::new();
        options.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        options
            .open(&tmp)
            .and_then(|mut file| std::io::Write::write_all(&mut file, &data))
            .with_context(|| format!("cannot write account index {}", tmp.display()))?;
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

    /// Removes everything an earlier link left behind: the account directories (store,
    /// imported history, attachments), the account index, the identity trust decisions and
    /// the keyring. `link` runs this first, so a re-link starts fresh like re-registering in
    /// the official Signal Desktop client. Nothing here is read, only removed: this also
    /// works without the secret when the old data is encrypted, which makes a fresh link the
    /// way out of a key the user no longer has. The data directory itself stays (0700).
    pub fn wipe_previous_accounts(dir: &Path) -> anyhow::Result<()> {
        let targets = [
            dir.join("accounts"),
            dir.join("accounts.json"),
            dir.join("accounts.json.enc"),
            dir.join("trust.json"),
            dir.join("trust.json.enc"),
            dir.join("keyring.enc"),
        ];
        for target in &targets {
            let meta = match fs::symlink_metadata(target) {
                Ok(meta) => meta,
                Err(_) => continue, // nothing of that kind was ever written
            };
            if meta.is_dir() {
                fs::remove_dir_all(target)
                    .with_context(|| format!("cannot remove previous account data {}", target.display()))?;
            } else {
                fs::remove_file(target)
                    .with_context(|| format!("cannot remove previous account data {}", target.display()))?;
            }
        }
        Ok(())
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

pub async fn open_store(account_dir: &Path, crypto: Option<&Crypto>) -> anyhow::Result<SqliteStore> {
    private_dir(account_dir)?;
    let url = format!("sqlite://{}", account_dir.join("store.db3").display());
    match crypto {
        None => {
            // No secret unlocked the data: nothing is encrypted yet, the store is plaintext.
            // An encrypted store cannot be opened here (see the SQLCipher error below).
            SqliteStore::open(&url, OnNewIdentity::Trust)
                .await
                .with_context(|| format!("cannot open store in {}", account_dir.display()))
        }
        Some(crypto) => {
            migrate_store(account_dir, crypto).await?;
            // SQLCipher with a raw key: no second key derivation runs on any connection.
            let mut key = cipher_key(crypto);
            let options = cipher_options(&url, &key)?;
            let store = SqliteStore::open_with_options(options, OnNewIdentity::Trust)
                .await
                .with_context(|| format!("cannot open store in {}", account_dir.display()));
            crypto::wipe_str(&mut key);
            store
        }
    }
}

/// SQLite's magic header: a plaintext database starts with it, an SQLCipher database does not.
const SQLITE_HEADER: &[u8; 16] = b"SQLite format 3\0";

/// True when `path` holds a plaintext SQLite database.
fn is_plaintext_db(path: &Path) -> bool {
    use std::io::Read as _;
    let mut header = [0u8; SQLITE_HEADER.len()];
    let Ok(mut file) = fs::File::open(path) else { return false };
    file.read_exact(&mut header).is_ok() && header == *SQLITE_HEADER
}

/// SQLCipher's raw-key string of the store key, quoted for direct use in `PRAGMA key` and the
/// ATTACH KEY clause: `'x''<64 hex>'''` makes SQLite hand SQLCipher the string `x'<64 hex>'`,
/// which it recognises as a raw key and uses without a key derivation.
fn cipher_key(crypto: &Crypto) -> String {
    format!("'{}'", crypto.sqlcipher_key().replace('\'', "''"))
}

/// SQLCipher connect options of the store: the raw key (see cipher_key) and `secure_delete`,
/// which zeroes freed pages so a deleted message does not linger inside the file (F1 clears
/// and deletes).
fn cipher_options(url: &str, key: &str) -> anyhow::Result<SqliteConnectOptions> {
    let options: SqliteConnectOptions = url
        .parse()
        .with_context(|| format!("cannot use the store url {url}"))?;
    Ok(options.create_if_missing(true).foreign_keys(true).pragma("key", key.to_string()).pragma("secure_delete", "ON"))
}

/// One-time move from the old at-rest formats into the SQLCipher store (F2). Two legacy states
/// existed: a plaintext store.db3 (written by an older version, or left by a crashed run that
/// never re-encrypted) and its frame-encrypted copy store.db3.enc (see the old prepare_db and
/// seal_db). The plaintext always held the newest state; it is exported into an encrypted
/// database with sqlcipher_export and wiped afterwards. From then on store.db3 IS the
/// encrypted database: no plaintext copy ever exists on disk, not even while running.
async fn migrate_store(account_dir: &Path, crypto: &Crypto) -> anyhow::Result<()> {
    let db = account_dir.join("store.db3");
    let enc = account_dir.join("store.db3.enc");
    if !db.exists() && !enc.exists() {
        return Ok(()); // a fresh account
    }
    if db.exists() && !is_plaintext_db(&db) {
        // Already migrated. A stale .enc (the old code re-encrypted on every clean shutdown)
        // is redundant now.
        if enc.exists() {
            warn!("the store is already an SQLCipher database; removing the redundant store.db3.enc");
            wipe_and_remove(&enc);
        }
        return Ok(());
    }
    // Bring the newest state into the plaintext file: decrypt the frame copy when the
    // plaintext is gone.
    if !db.exists() {
        let data = crypto
            .read_file(crypto::purpose::DB, "", &enc)
            .with_context(|| format!("cannot decrypt {}", enc.display()))?;
        if !data.starts_with(SQLITE_HEADER) {
            anyhow::bail!("{} does not hold a SQLite database", enc.display());
        }
        write_private_file(&db, &data)?;
        wipe_and_remove(&enc);
    }
    encrypt_store(account_dir, crypto).await
}

/// Exports the plaintext store at store.db3 into an SQLCipher database and replaces the
/// plaintext with it. The plaintext is only wiped after the export succeeded and its file was
/// closed, so an interrupted migration leaves the old state untouched for the next start to
/// retry. An uncheckpointed write-ahead log is fine: SQLite replays it when the source opens.
async fn encrypt_store(account_dir: &Path, crypto: &Crypto) -> anyhow::Result<()> {
    let db = account_dir.join("store.db3");
    let target = account_dir.join("store.db3.sqlcipher");
    let _ = fs::remove_file(&target);

    // The migration runs on its own pool, before presage opens the store; foreign keys are
    // off while the export copies the tables. Two forms of the same key: SQLCipher's raw-key
    // string for the bound KEY parameter, and the SQL-quoted form for the PRAGMA key of the
    // connections presage opens later — they must agree, or the store could not be opened again.
    let mut key = crypto.sqlcipher_key();
    let mut pragma_key = cipher_key(crypto);
    let source_url = format!("sqlite://{}", db.display());
    let source: SqliteConnectOptions = source_url
        .parse()
        .with_context(|| format!("cannot read {}", db.display()))?;
    // create_if_missing: the attached TARGET is created by the ATTACH (which opens with the
    // connection's flags); the source is verified to exist by migrate_store.
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(source.create_if_missing(true).foreign_keys(false))
        .await
        .with_context(|| format!("cannot read {}", db.display()))?;
    let attach_path = target.display().to_string();
    let exported: anyhow::Result<()> = async {
        query("ATTACH DATABASE ? AS migrate KEY ?")
            .bind(attach_path)
            .bind(key.clone())
            .execute(&pool)
            .await?;
        query("SELECT sqlcipher_export('migrate')").execute(&pool).await?;
        query("DETACH DATABASE migrate").execute(&pool).await?;
        Ok(())
    }
    .await;
    pool.close().await;
    crypto::wipe_str(&mut key);
    crypto::wipe_str(&mut pragma_key);
    exported?;
    // The encrypted copy exists and is closed; the plaintext (and any journal leftovers) can go.
    wipe_and_remove(&db);
    for leftover in ["store.db3-wal", "store.db3-shm", "store.db3-journal"] {
        wipe_and_remove(&account_dir.join(leftover));
    }
    fs::rename(&target, &db)
        .with_context(|| format!("cannot put the encrypted store in place at {}", db.display()))?;
    Ok(())
}

pub fn attachments_dir(account_dir: &Path) -> PathBuf {
    account_dir.join("attachments")
}

// ---- encrypted data at rest -----------------------------------------------------------------

/// One-time encryption of the files an older, plaintext version left behind. Runs after the
/// keyring is unlocked, before any command. Cheap when there is nothing to do.
pub fn migrate_legacy(data_dir: &Path, crypto: &Crypto) -> anyhow::Result<()> {
    let index = data_dir.join("accounts.json");
    let index_enc = data_dir.join("accounts.json.enc");
    if index.exists() {
        if index_enc.exists() {
            // The migration already ran: an encrypted index exists. A plaintext index next to
            // it was not written by this program (it seals and removes what it migrates) —
            // sealing it would overwrite the encrypted store with whatever a process running
            // as this user planted there (L1). It is reported and left alone; the encrypted
            // index stays the only one Accounts::list reads.
            warn!("a plaintext accounts.json exists next to accounts.json.enc; not migrating it");
        } else {
            let data = fs::read(&index).with_context(|| format!("cannot read {}", index.display()))?;
            crypto.seal_file(crypto::purpose::ACCOUNTS, "", &index_enc, &data)?;
            wipe_and_remove(&index);
        }
    }
    // The account directory names come from the index, which is encrypted by now. A broken
    // index is not fatal here (migrate_legacy only encrypts leftover files), but the run
    // afterwards cannot find accounts (see Accounts::list).
    let Ok(data) = crypto.read_encrypted(crypto::purpose::ACCOUNTS, "", &index_enc) else {
        return Ok(());
    };
    let Ok(index) = serde_json::from_slice::<BTreeMap<String, String>>(&data) else {
        return Ok(());
    };
    for name in index.into_values() {
        let dir = data_dir.join("accounts").join(name);
        let trust = dir.join("trust.json");
        let trust_enc = dir.join("trust.json.enc");
        if trust.exists() {
            if trust_enc.exists() {
                // Same as the index above: the encrypted trust store is the one that counts;
                // a plaintext file next to it is a plant or a downgrade leftover (L1).
                warn!("a plaintext trust.json exists next to its encrypted store; not migrating it");
            } else {
                match fs::read(&trust) {
                    Ok(data) => {
                        if let Err(e) = crypto.seal_file(crypto::purpose::TRUST, "", &trust_enc, &data) {
                            warn!(%e, "cannot encrypt the trust store");
                        } else {
                            wipe_and_remove(&trust);
                        }
                    }
                    Err(e) => warn!(%e, "cannot read the plaintext trust store"),
                }
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
        let _ = fs::remove_dir_all(&dir);
        // 0700, like the dirs private_dir creates: the tests simulate real usage.
        fs::create_dir_all(&dir).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        }
        dir
    }

    #[test]
    fn private_dir_creates_tightens_or_refuses() {
        let dir = tmp("private");
        // Created on demand, readable only by the user — every level of the way.
        let nested = dir.join("accounts").join("acc1");
        private_dir(&nested).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(fs::metadata(&nested).unwrap().permissions().mode() & 0o777, 0o700);
            assert_eq!(fs::metadata(dir.join("accounts")).unwrap().permissions().mode() & 0o777, 0o700);
        }
        // An existing directory is tightened only when it is the data directory itself
        // (leaf `corvus-cli`): its name is ours, so 0755 cannot be intentional.
        let ours = dir.join("corvus-cli");
        fs::create_dir_all(&ours).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&ours, fs::Permissions::from_mode(0o755)).unwrap();
            private_dir(&ours).unwrap();
            assert_eq!(fs::metadata(&ours).unwrap().permissions().mode() & 0o777, 0o700);
        }
        // Anything else is refused and left as it was (`-c ~` must not change the home
        // directory, L7), with the exact fix in the message.
        let existing = dir.join("loose");
        fs::create_dir_all(&existing).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&existing, fs::Permissions::from_mode(0o755)).unwrap();
            let err = format!("{}", private_dir(&existing).unwrap_err());
            assert!(err.contains("chmod 700"), "error lacks the fix: {err}");
            assert_eq!(fs::metadata(&existing).unwrap().permissions().mode() & 0o777, 0o755);
        }
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn wipe_previous_accounts_removes_everything_from_an_earlier_link() {
        let dir = tmp("wipe");
        // What a previous link leaves behind: account directory with store, imported history
        // and attachments, the index (plaintext and encrypted variants), trust decisions and
        // the keyring.
        let accounts = dir.join("accounts");
        fs::create_dir_all(accounts.join("acc1").join("attachments")).unwrap();
        fs::write(accounts.join("acc1").join("store.db3"), b"store").unwrap();
        fs::write(accounts.join("acc1").join("history-import.jsonl"), b"{}\n").unwrap();
        fs::write(accounts.join("acc1").join("attachments").join("a.bin"), b"att").unwrap();
        fs::write(dir.join("accounts.json"), b"{}").unwrap();
        fs::write(dir.join("accounts.json.enc"), b"enc").unwrap();
        fs::write(dir.join("trust.json"), b"{}").unwrap();
        fs::write(dir.join("trust.json.enc"), b"enc").unwrap();
        fs::write(dir.join("keyring.enc"), b"keyring").unwrap();

        Accounts::wipe_previous_accounts(&dir).unwrap();
        // The data directory itself stays (linking continues there), but it is empty now.
        assert!(dir.is_dir());
        assert_eq!(fs::read_dir(&dir).unwrap().count(), 0);

        // Wiping a directory that has nothing to remove (fresh install) is fine, and so is
        // calling it again on the now-empty directory.
        let empty = tmp("wipe-empty");
        Accounts::wipe_previous_accounts(&empty).unwrap();
        Accounts::wipe_previous_accounts(&dir).unwrap();
        assert!(empty.is_dir());
        fs::remove_dir_all(dir).unwrap();
        fs::remove_dir_all(empty).unwrap();
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
    fn a_plaintext_file_next_to_an_encrypted_one_is_not_laundered() {
        let dir = tmp("launder");
        let crypto = crypto::unlock(&dir, "pw", None).unwrap();
        // A real encrypted index is created by the first, legitimate migration.
        fs::write(dir.join("accounts.json"), br#"{"+49172":"acc1"}"#).unwrap();
        migrate_legacy(&dir, &crypto).unwrap();

        // Afterwards, a process running as the user plants a plaintext index and trust store:
        // sealing them would overwrite the encrypted stores with attacker data (L1).
        fs::write(dir.join("accounts.json"), br#"{"+49999":"evil"}"#).unwrap();
        let account = dir.join("accounts").join("acc1");
        fs::create_dir_all(&account).unwrap();
        crypto.seal_file(crypto::purpose::TRUST, "", &account.join("trust.json.enc"), b"{}").unwrap();
        fs::write(account.join("trust.json"), br#"{"key":"cGxhbnRlZA==","level":"TRUSTED_UNVERIFIED"}"#).unwrap();
        migrate_legacy(&dir, &crypto).unwrap();

        // The encrypted stores are unchanged; the plants are neither sealed nor read.
        let accounts = Accounts::new(dir.clone(), Some(crypto.clone()));
        assert_eq!(accounts.list().get("+49172").map(String::as_str), Some("acc1"));
        assert!(accounts.list().get("+49999").is_none());
        let enc = fs::read(dir.join("accounts.json.enc")).unwrap();
        assert!(!enc.windows(4).any(|w| w == b"evil"));
        assert_eq!(
            crypto.read_encrypted(crypto::purpose::TRUST, "", &account.join("trust.json.enc")).unwrap(),
            b"{}"
        );
        // Reported and left alone, not destroyed and not migrated.
        assert!(dir.join("accounts.json").exists());
        assert!(account.join("trust.json").exists());
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn with_a_secret_a_plaintext_index_without_an_encrypted_one_is_not_read() {
        let dir = tmp("no-enc");
        let crypto = crypto::unlock(&dir, "pw", None).unwrap();
        fs::write(dir.join("accounts.json"), br#"{"+49172":"acc1"}"#).unwrap();
        // At startup the migration seals this state; until then the plaintext file is not
        // trusted either (L1).
        assert!(Accounts::new(dir.clone(), Some(crypto)).list().is_empty());
        fs::remove_dir_all(dir).unwrap();
    }

    /// The tests run on their own current-thread runtime (tokio's test macros are not enabled).
    fn block_on<F: std::future::Future>(future: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(future)
    }

    #[test]
    fn the_store_is_an_sqlcipher_database_with_a_secret() {
        let dir = tmp("sqlcipher");
        let account = dir.join("accounts").join("acc1");
        let crypto = crypto::unlock(&dir, "pw", None).unwrap();
        block_on(async {
            let store = open_store(&account, Some(&crypto)).await.unwrap();
            store.close().await;
        });
        // The store file is not a plaintext SQLite database (F2).
        let raw = fs::read(account.join("store.db3")).unwrap();
        assert!(&raw[..16] != SQLITE_HEADER);
        // Opening it again with the key works; without one it must not open.
        block_on(async {
            open_store(&account, Some(&crypto)).await.unwrap().close().await;
            assert!(open_store(&account, None).await.is_err());
        });
        // And the index keeps working next to it (plaintext mode stays for unencrypted data).
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn a_frame_encrypted_legacy_store_is_migrated_to_sqlcipher() {
        let dir = tmp("migrate-frame");
        let account = dir.join("accounts").join("acc1");
        let crypto = crypto::unlock(&dir, "pw", None).unwrap();
        // The old at-rest format: a plaintext store, sealed as a frame (old seal_db).
        block_on(async {
            open_store(&account, None).await.unwrap().close().await;
        });
        let data = fs::read(account.join("store.db3")).unwrap();
        assert!(data.starts_with(SQLITE_HEADER));
        crypto.seal_file(crypto::purpose::DB, "", &account.join("store.db3.enc"), &data).unwrap();
        fs::remove_file(account.join("store.db3")).unwrap();

        block_on(async {
            open_store(&account, Some(&crypto)).await.unwrap().close().await;
        });
        // The frame copy is gone, the store file is SQLCipher, no plaintext or export
        // leftovers remain.
        assert!(!account.join("store.db3.enc").exists());
        assert!(!account.join("store.db3.sqlcipher").exists());
        let raw = fs::read(account.join("store.db3")).unwrap();
        assert!(&raw[..16] != SQLITE_HEADER);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn a_leftover_plaintext_store_is_migrated_to_sqlcipher() {
        let dir = tmp("migrate-plain");
        let account = dir.join("accounts").join("acc1");
        let crypto = crypto::unlock(&dir, "pw", None).unwrap();
        // A crashed run left the plaintext store.db3 without a frame copy: it holds the
        // newest state and becomes the encrypted store.
        block_on(async {
            open_store(&account, None).await.unwrap().close().await;
        });
        assert!(fs::read(account.join("store.db3")).unwrap().starts_with(SQLITE_HEADER));
        block_on(async {
            open_store(&account, Some(&crypto)).await.unwrap().close().await;
        });
        assert!(!account.join("store.db3.enc").exists());
        let raw = fs::read(account.join("store.db3")).unwrap();
        assert!(&raw[..16] != SQLITE_HEADER);
        fs::remove_dir_all(dir).unwrap();
    }
}
