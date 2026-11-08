// corvus-cli: a signal-cli compatible backend built on presage.
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

use std::io::Write as _;
use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::{bail, Context as _};
use futures::{channel::oneshot, future};
use presage::libsignal_service::configuration::SignalServers;
use presage::libsignal_service::prelude::Uuid;
use presage::manager::Registered;
use presage::Manager;
use presage_store_sqlite::SqliteStore;
use tokio::io::{AsyncBufReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::sync::mpsc;
use tracing::{debug, error, warn};

use crate::store::{e164, open_store, Accounts};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
/// Commit of the build, for Corvus' update check (releases are tagged "commit-<sha>"). Set by CI
/// (GITHUB_SHA) or by hand (CORVUS_CLI_COMMIT) when building; absent in local builds.
const BUILD_COMMIT: Option<&str> = match option_env!("CORVUS_CLI_COMMIT") {
    Some(c) => Some(c),
    None => option_env!("GITHUB_SHA"),
};

/// "0.1.0" or "0.1.0 (4d76022)".
fn version_text() -> String {
    match BUILD_COMMIT {
        Some(c) if c.len() >= 7 && c.chars().all(|ch| ch.is_ascii_hexdigit()) => {
            format!("{VERSION} ({})", &c[..7].to_ascii_lowercase())
        }
        _ => VERSION.to_string(),
    }
}
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

/// Expected server throttling for read/delivery receipts is not an application failure.
fn should_log_rpc_error(method: &str, message: &str) -> bool {
    let expected_avatar_miss = method == "getAvatar" && message == "No avatar found";
    let expected_receipt_rate_limit =
        method == "sendReceipt" && message.contains("Rate limit exceeded");
    !expected_avatar_miss && !expected_receipt_rate_limit
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

fn init_logging(verbosity: u8) {
    // stderr is shown to the user by corvus, so only problems are logged by default.
    let default = match verbosity {
        0 => "corvus_cli=warn,presage=error,libsignal_service=error",
        1 => "corvus_cli=info,presage=info,libsignal_service=warn",
        _ => "debug",
    };
    let filter = tracing_subscriber::EnvFilter::try_from_env("CORVUS_CLI_LOG")
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(default));
    tracing_subscriber::fmt().with_writer(std::io::stderr).with_env_filter(filter).with_target(false).init();
}

fn main() -> ExitCode {
    let args = match parse_args(std::env::args().skip(1)) {
        Ok(args) => args,
        Err(e) => {
            eprintln!("{e:#}");
            return ExitCode::from(1);
        }
    };
    init_logging(args.verbosity);
    if args.version {
        println!("corvus-cli {} compatible with signal-cli {COMPAT_VERSION}", version_text());
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
            let name = option(&args.rest, "-n", "--name").unwrap_or_else(|| "corvus-cli".into());
            link(&accounts, name).await
        }
        Some("jsonRpc") => {
            let account = match args.account {
                Some(account) => account,
                None => single_account(&accounts).context("No account given: use -a <number>")?,
            };
            json_rpc(&accounts, &account).await
        }
        Some(other) => bail!("Command {other} is not supported by corvus-cli"),
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

    let (out_tx, out_rx) = mpsc::unbounded_channel::<daemon::Output>();
    let writer = tokio::task::spawn_local(async move {
        if let Err(e) = write_output(out_rx, tokio::io::stdout()).await {
            error!(%e, "stdout write failed; exiting to avoid silently dropping incoming Signal messages");
            std::process::exit(1);
        }
    });

    let daemon = daemon::Daemon::new(manager, &dir, out_tx.clone()).await?;
    daemon.start_receipt_worker();
    // Contacts' numbers and names come from the storage service: read it before the first
    // listContacts is answered (requests wait in stdin meanwhile), but not for ever.
    if tokio::time::timeout(std::time::Duration::from_secs(10), daemon.clone().refresh_storage()).await.is_err() {
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
                let _ = out_tx.send(daemon::Output::queued(response));
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
                if should_log_rpc_error(&request.method, &e.message) {
                    error!(method = request.method, error = e.message, "call failed");
                } else if request.method == "sendReceipt" {
                    debug!(method = request.method, error = e.message, "Signal temporarily rate-limited a receipt; the receipt was not sent");
                }
            }
            if let Some(id) = request.id {
                let _ = out.send(daemon::Output::queued(rpc::response(id, result)));
            }
        });
    }
    // stdin closed: corvus stopped us. Let queued responses go out first.
    drop(out_tx);
    drop(daemon);
    let _ = tokio::time::timeout(std::time::Duration::from_secs(2), writer).await;
    Ok(())
}

/// Writes one JSON-RPC line at a time and confirms tracked notifications only after flush.
async fn write_output<W>(
    mut out_rx: mpsc::UnboundedReceiver<daemon::Output>,
    mut stdout: W,
) -> std::io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    while let Some(output) = out_rx.recv().await {
        let mut line = output.value.to_string();
        line.push('\n');
        let result = async {
            stdout.write_all(line.as_bytes()).await?;
            stdout.flush().await
        }
        .await;

        if let Some(written) = output.written {
            let confirmation = result.as_ref().map(|_| ()).map_err(ToString::to_string);
            let _ = written.send(confirmation);
        }
        result?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;

    fn args(list: &[&str]) -> Args {
        parse_args(list.iter().map(|s| s.to_string())).unwrap()
    }

    #[test]
    fn output_writer_confirms_a_notification_after_writing_it() {
        let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        runtime.block_on(async {
            let (tx, rx) = mpsc::unbounded_channel();
            let (confirmed_tx, confirmed_rx) = tokio::sync::oneshot::channel();
            let (mut reader, writer) = tokio::io::duplex(128);
            tx.send(daemon::Output {
                value: serde_json::json!({"method": "receive"}),
                written: Some(confirmed_tx),
            }).unwrap();
            drop(tx);

            let mut bytes = Vec::new();
            let (write_result, read_result) = futures::future::join(write_output(rx, writer), reader.read_to_end(&mut bytes)).await;
            write_result.unwrap();
            read_result.unwrap();
            assert_eq!(bytes, [br#"{"method":"receive"}"#.as_slice(), b"\n"].concat());
            assert!(matches!(confirmed_rx.await, Ok(Ok(()))));
        });
    }

    #[test]
    fn output_writer_reports_a_broken_pipe_to_the_receiver() {
        let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        runtime.block_on(async {
            let (tx, rx) = mpsc::unbounded_channel();
            let (confirmed_tx, confirmed_rx) = tokio::sync::oneshot::channel();
            let (reader, writer) = tokio::io::duplex(64);
            drop(reader);
            tx.send(daemon::Output {
                value: serde_json::json!({"method": "receive"}),
                written: Some(confirmed_tx),
            }).unwrap();
            drop(tx);

            assert!(write_output(rx, writer).await.is_err());
            assert!(matches!(confirmed_rx.await, Ok(Err(_))));
        });
    }

    #[test]
    fn expected_receipt_rate_limits_are_not_logged_as_application_errors() {
        assert!(!should_log_rpc_error(
            "sendReceipt",
            "libsignal-service sending error: service error: Rate limit exceeded: retry after PT600S",
        ));
        assert!(should_log_rpc_error("send", "Rate limit exceeded"));
        assert!(!should_log_rpc_error("getAvatar", "No avatar found"));
        assert!(should_log_rpc_error("getAvatar", "network unavailable"));
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
