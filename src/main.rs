// corvus-signal: a signal-cli compatible backend built on presage.
// Implements the command lines corvus runs: --version, listAccounts, link and jsonRpc.

mod account;
mod contract;
mod daemon;
mod envelope;
mod groupops;
mod groups;
mod identities;
mod rpc;
mod stickers;
mod storage;
mod store;
mod textstyle;

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write as _};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::{Arc, Mutex};

use anyhow::{bail, Context as _};
use futures::{channel::oneshot, future};
use presage::libsignal_service::configuration::SignalServers;
use presage::libsignal_service::prelude::Uuid;
use presage::manager::Registered;
use presage::Manager;
use presage_store_sqlite::SqliteStore;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::sync::mpsc;
use tracing::{error, warn};

use crate::store::{e164, open_store, private_dir, Accounts};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
/// The signal-cli version whose interface is implemented. Corvus gates features on the last word of
/// `--version`, so this is printed last.
const COMPAT_VERSION: &str = "0.14.9";

#[derive(Debug, Default)]
struct Args {
    account: Option<String>,
    config: Option<PathBuf>,
    json_output: bool,
    verbosity: u8,
    version: bool,
    command: Option<String>,
    rest: Vec<String>,
}

fn parse_args(argv: impl IntoIterator<Item = String>) -> anyhow::Result<Args> {
    let mut args = Args::default();
    let mut it = argv.into_iter();
    while let Some(arg) = it.next() {
        if args.command.is_some() {
            args.rest.push(arg);
            continue;
        }
        let (flag, inline) = match arg.split_once('=') {
            Some((f, v)) if f.starts_with("--") => (f.to_string(), Some(v.to_string())),
            _ => (arg.clone(), None),
        };
        let mut value = |name: &str| -> anyhow::Result<String> {
            inline.clone().or_else(|| it.next()).with_context(|| format!("{name} needs a value"))
        };
        match flag.as_str() {
            "-a" | "--account" | "-u" | "--username" => args.account = Some(value(&flag)?),
            "-c" | "--config" => args.config = Some(value(&flag)?.into()),
            "-o" | "--output" => args.json_output = value(&flag)? == "json",
            "-v" | "--verbose" => args.verbosity += 1,
            "-vv" => args.verbosity += 2,
            "--version" | "-V" => args.version = true,
            f if f.starts_with('-') => warn!(flag = f, "ignoring unknown option"),
            _ => args.command = Some(arg),
        }
    }
    Ok(args)
}

/// signal-cli style options of a subcommand: "-n NAME", "--name=NAME", "--name NAME".
fn option(rest: &[String], short: &str, long: &str) -> Option<String> {
    let mut it = rest.iter();
    while let Some(arg) = it.next() {
        if arg == short || arg == long {
            return it.next().cloned();
        }
        if let Some(v) = arg.strip_prefix(long).and_then(|r| r.strip_prefix('=')) {
            return Some(v.to_string());
        }
    }
    None
}

/// Writes diagnostics to stderr (shown briefly by Corvus) and to a private, persistent log file.
#[derive(Clone)]
struct LogWriter {
    file: Option<Arc<Mutex<File>>>,
}

struct LogWriterGuard {
    file: Option<Arc<Mutex<File>>>,
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for LogWriter {
    type Writer = LogWriterGuard;

    fn make_writer(&'a self) -> Self::Writer {
        LogWriterGuard { file: self.file.clone() }
    }
}

impl io::Write for LogWriterGuard {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if let Some(file) = &self.file {
            if let Ok(mut file) = file.lock() {
                let _ = file.write_all(buf);
            }
        }
        // stderr is consumed by the desktop UI; keep it working even if the log file is unavailable.
        let _ = io::stderr().lock().write_all(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        if let Some(file) = &self.file {
            if let Ok(mut file) = file.lock() {
                let _ = file.flush();
            }
        }
        let _ = io::stderr().lock().flush();
        Ok(())
    }
}

fn open_diagnostic_log(config: Option<&Path>) -> Option<File> {
    let dir = store::data_dir(config);
    private_dir(&dir).ok()?;
    let path = dir.join("corvus-signal.log");

    // Keep one bounded backup so a long-running daemon cannot grow the log indefinitely.
    const MAX_LOG_BYTES: u64 = 5 * 1024 * 1024;
    if fs::metadata(&path).is_ok_and(|meta| meta.len() >= MAX_LOG_BYTES) {
        let backup = dir.join("corvus-signal.log.1");
        let _ = fs::remove_file(&backup);
        let _ = fs::rename(&path, &backup);
    }

    let mut options = OpenOptions::new();
    options.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = options.open(&path).ok()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&path, fs::Permissions::from_mode(0o600));
    }
    Some(file)
}

fn init_logging(verbosity: u8, config: Option<&Path>) {
    // stderr is shown to the user by corvus, so only problems are logged by default.
    let default = match verbosity {
        0 => "corvus_signal=warn,presage=error,libsignal_service=error",
        1 => "corvus_signal=info,presage=info,libsignal_service=warn",
        _ => "debug",
    };
    let filter = tracing_subscriber::EnvFilter::try_from_env("CORVUS_SIGNAL_LOG")
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(default));
    let writer = LogWriter { file: open_diagnostic_log(config).map(|file| Arc::new(Mutex::new(file))) };
    tracing_subscriber::fmt().with_writer(writer).with_env_filter(filter).with_target(false).init();
}

fn main() -> ExitCode {
    let args = match parse_args(std::env::args().skip(1)) {
        Ok(args) => args,
        Err(e) => {
            eprintln!("{e:#}");
            return ExitCode::from(1);
        }
    };
    init_logging(args.verbosity, args.config.as_deref());
    if args.version {
        println!("corvus-signal {VERSION} compatible with signal-cli {COMPAT_VERSION}");
        return ExitCode::SUCCESS;
    }
    let runtime = match tokio::runtime::Builder::new_current_thread().enable_all().build() {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("cannot start runtime: {e}");
            return ExitCode::from(1);
        }
    };
    let local = tokio::task::LocalSet::new();
    match local.block_on(&runtime, run(args)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("{e:#}");
            ExitCode::from(1)
        }
    }
}

async fn run(args: Args) -> anyhow::Result<()> {
    let accounts = Accounts::new(store::data_dir(args.config.as_deref()));
    match args.command.as_deref() {
        Some("listAccounts") => list_accounts(&accounts, args.json_output),
        Some("link") => {
            let name = option(&args.rest, "-n", "--name").unwrap_or_else(|| "corvus-signal".into());
            link(&accounts, name).await
        }
        Some("jsonRpc") => {
            let account = match args.account {
                Some(account) => account,
                None => single_account(&accounts).context("No account given: use -a <number>")?,
            };
            json_rpc(&accounts, &account).await
        }
        Some(other) => bail!("Command {other} is not supported by corvus-signal"),
        None => bail!("No command given (supported: link, listAccounts, jsonRpc)"),
    }
}

fn single_account(accounts: &Accounts) -> Option<String> {
    let list = accounts.list();
    if list.len() == 1 { list.into_keys().next() } else { None }
}

fn list_accounts(accounts: &Accounts, json: bool) -> anyhow::Result<()> {
    let list = accounts.list();
    if json {
        let entries: Vec<_> = list.keys().map(|n| serde_json::json!({"number": n})).collect();
        println!("{}", serde_json::Value::Array(entries));
    } else {
        for number in list.keys() {
            println!("Number: {number}");
        }
    }
    Ok(())
}

async fn link(accounts: &Accounts, device_name: String) -> anyhow::Result<()> {
    let staging = accounts.staging_dir()?;
    let store = open_store(&staging).await?;
    let (url_tx, url_rx) = oneshot::channel();
    let (linked, ()) = future::join(
        Manager::link_secondary_device(store, SignalServers::Production, device_name, url_tx),
        async move {
            if let Ok(url) = url_rx.await {
                // corvus reads the first stdout line starting with sgnl:// and shows it as a QR code.
                println!("{url}");
                let _ = std::io::stdout().flush();
            }
        },
    )
    .await;
    let manager = match linked {
        Ok(manager) => manager,
        Err(e) => {
            let _ = std::fs::remove_dir_all(&staging);
            bail!("Linking failed: {e}");
        }
    };
    let data = manager.registration_data();
    let number = e164(&data.phone_number);
    let aci = Uuid::from(data.service_ids.aci()).to_string();
    drop(manager);
    accounts.register(&staging, &number, &aci)?;
    println!("Associated with: {number}");
    Ok(())
}

async fn json_rpc(accounts: &Accounts, account: &str) -> anyhow::Result<()> {
    let dir = accounts.find(account)?;
    let store: SqliteStore = open_store(&dir).await?;
    let manager: Manager<SqliteStore, Registered> = Manager::load_registered(store)
        .await
        .context("account is not linked (link it again)")?;

    let (out_tx, mut out_rx) = mpsc::unbounded_channel::<serde_json::Value>();
    let writer = tokio::task::spawn_local(async move {
        let mut stdout = tokio::io::stdout();
        while let Some(value) = out_rx.recv().await {
            let mut line = value.to_string();
            line.push('\n');
            if stdout.write_all(line.as_bytes()).await.is_err() || stdout.flush().await.is_err() {
                break;
            }
        }
    });

    let daemon = daemon::Daemon::new(manager, &dir, out_tx.clone()).await?;
    // Contacts' numbers and names come from the storage service: read it before the first
    // listContacts is answered (requests wait in stdin meanwhile), but not for ever.
    if tokio::time::timeout(std::time::Duration::from_secs(10), daemon.refresh_storage()).await.is_err() {
        warn!("the storage service did not answer in time");
    }
    tokio::task::spawn_local(daemon.clone().receive_loop());
    let profiles = daemon.clone();
    tokio::task::spawn_local(async move { profiles.prefetch_profiles().await });

    let mut lines = BufReader::new(tokio::io::stdin()).lines();
    while let Some(line) = lines.next_line().await? {
        if line.trim().is_empty() {
            continue;
        }
        let request = match rpc::parse_request(&line) {
            Ok(request) => request,
            Err(response) => {
                let _ = out_tx.send(response);
                continue;
            }
        };
        let daemon = daemon.clone();
        let out = out_tx.clone();
        tokio::task::spawn_local(async move {
            let result = daemon.call(&request.method, &request.params).await;
            if let Err(e) = &result {
                // Missing avatars are normal: Corvus tries the contact avatar first, then
                // the profile avatar, and finally falls back to its generated placeholder.
                let expected_avatar_miss = request.method == "getAvatar" && e.message == "No avatar found";
                if !expected_avatar_miss {
                    error!(method = request.method, error = e.message, "call failed");
                }
            }
            if let Some(id) = request.id {
                let _ = out.send(rpc::response(id, result));
            }
        });
    }
    // stdin closed: corvus stopped us. Let queued responses go out first.
    drop(out_tx);
    drop(daemon);
    let _ = tokio::time::timeout(std::time::Duration::from_secs(2), writer).await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(list: &[&str]) -> Args {
        parse_args(list.iter().map(|s| s.to_string())).unwrap()
    }

    #[test]
    fn corvus_command_lines() {
        let a = args(&["-a", "+491234", "jsonRpc", "--receive-mode=on-start"]);
        assert_eq!(a.account.as_deref(), Some("+491234"));
        assert_eq!(a.command.as_deref(), Some("jsonRpc"));
        assert_eq!(a.rest, ["--receive-mode=on-start"]);

        let a = args(&["-vv", "-a", "+49", "jsonRpc"]);
        assert_eq!(a.verbosity, 2);

        let a = args(&["-o", "json", "listAccounts"]);
        assert!(a.json_output);
        assert_eq!(a.command.as_deref(), Some("listAccounts"));

        let a = args(&["link", "-n", "corvus (host)"]);
        assert_eq!(option(&a.rest, "-n", "--name").as_deref(), Some("corvus (host)"));
        assert_eq!(option(&["--name=x".into()], "-n", "--name").as_deref(), Some("x"));

        assert!(args(&["--version"]).version);
    }
}
