// Transfer of recent chat history from the phone while linking (Signal's "synchronized start
// for linked devices", https://signal.org/blog/a-synchronized-start-for-linked-devices/).
//
// The phone (primary device) decides at scan time whether a transfer happens; when it does, the
// provisioning message carries a one-time 32-byte ephemeral backup key (presage exposes it as
// RegistrationData::ephemeral_backup_key). After this device is registered, the phone packs the
// recent message history into one archive, encrypts it with a key derived from that ephemeral
// key and our ACI, uploads it to the attachment CDN and tells the server where it landed.
//
// This module asks the server for the archive location (GET /v1/devices/transfer_archive),
// downloads it and parses it: the same encrypted message-backup format the official clients use
// (AES-256-CBC + HMAC-SHA256 over a gzip stream of varint-delimited protobuf frames, purpose
// DeviceTransfer, keys derived by libsignal's message-backup crate). Every frame that maps to
// something Corvus shows is converted into the same envelope JSON a live message produces
// (crate::envelope) and written to the account directory as one JSON object per line
// (history-import.jsonl). The jsonRpc methods listHistoryImport, fetchHistoryImport and
// clearHistoryImport serve those lines to Corvus, which replays them into its own encrypted
// history store. Attachments that still sit on the transit CDN are recorded in
// history-attachments.json so downloadAttachment can fetch them like live ones; media that only
// exists in the media tier (or files the phone downloaded and no longer has a transit pointer
// for) has no id and shows a placeholder in Corvus.
//
// The generated protobuf types (libsignal_message_backup::proto, behind the test-util feature)
// keep the field names of the .proto source (recipientId, dateSent, …).

use std::collections::HashMap;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{bail, Context as _};
use base64::prelude::*;
use libsignal_account_keys::BackupKey;
use libsignal_core::Aci as BackupAci;
use libsignal_message_backup::frame::{FileReaderFactory, FramesReader};
use libsignal_message_backup::key::MessageBackupKey;
use libsignal_message_backup::parse::VarintDelimitedReader;
use libsignal_message_backup::proto::backup::{
    body_range, chat_item, chat_update_message, file_pointer, frame, message_attachment,
    recipient, BackupInfo, ChatItem, Contact, Frame, Reaction, Recipient, StandardMessage,
};
use presage::libsignal_service::configuration::Endpoint;
use presage::libsignal_service::prelude::{PushService, Uuid};
use presage::libsignal_service::protocol::Aci;
use presage::libsignal_service::push_service::HttpAuthOverride;
use presage::proto::attachment_pointer::AttachmentIdentifier;
use presage::proto::{body_range as presage_body_range, AttachmentPointer, BodyRange as PresageBodyRange};
use protobuf::Message as _;
use reqwest::Method;
use serde_json::{json, Map, Value};
use url::Url;
use tokio::io::{AsyncBufReadExt as _, AsyncWriteExt as _};
use tracing::{info, warn};

use crate::textstyle;

/// How long the answer for the transfer offer may take to arrive on stdin (Corvus shows the
/// choice while the linking dialog is up), and how long we wait for the phone to finish
/// uploading the archive once the transfer was accepted.
const ANSWER_TIMEOUT: Duration = Duration::from_secs(5 * 60);
const TRANSFER_TIMEOUT: Duration = Duration::from_secs(15 * 60);
/// The server holds each long-poll for this long before answering 204 (no archive yet).
const LONG_POLL_SECONDS: u32 = 60;
/// Progress notifications to Corvus are throttled to one per this many imported messages.
const PROGRESS_STEP: usize = 200;

/// Files written into the account directory (or the staging directory while linking).
pub const HISTORY_FILE: &str = "history-import.jsonl";
pub const META_FILE: &str = "history-import.meta.json";
pub const ATTACHMENTS_FILE: &str = "history-attachments.json";
const ARCHIVE_TMP: &str = "transfer-archive.tmp";

pub fn history_file(dir: &Path) -> PathBuf {
    dir.join(HISTORY_FILE)
}
pub fn meta_file(dir: &Path) -> PathBuf {
    dir.join(META_FILE)
}
pub fn attachments_file(dir: &Path) -> PathBuf {
    dir.join(ATTACHMENTS_FILE)
}

/// The capabilities the phone reads from the QR code's URL (comma-separated `capabilities`
/// query parameter): `backup5` (LinkAndSync) is what turns a plain link into "link + history
/// transfer" — Signal-Android's LinkDeviceViewModel parses the QR URL and only starts the
/// archive upload when backup5 is present, otherwise it links silently without any offer.
/// presage builds the URL without a capabilities parameter, so mirror Signal Desktop's
/// exact list before the URL is rendered as a QR code. A URL that already carries a
/// capabilities parameter is left alone.
pub fn with_link_capabilities(mut url: Url) -> Url {
    if !url.query_pairs().any(|(k, _)| k == "capabilities") {
        url.query_pairs_mut()
            .append_pair("capabilities", "nopni,nopni2,backup5");
    }
    url
}

/// True when a finished import can be served (meta says done; the JSONL has the messages).
pub fn import_available(dir: &Path) -> Option<usize> {
    let meta = std::fs::read_to_string(meta_file(dir)).ok()?;
    let meta: Value = serde_json::from_str(&meta).ok()?;
    if meta.get("done")?.as_bool()? {
        Some(meta.get("count").and_then(|c| c.as_u64()).unwrap_or(0) as usize)
    } else {
        None
    }
}

/// Reads the user's answer to the transfer offer from stdin: "transfer" (or "y") to accept,
/// "skip" (or "n", or EOF, or nothing in time) to continue without the history.
pub async fn read_answer() -> bool {
    let deadline = Instant::now() + ANSWER_TIMEOUT;
    let mut reader = tokio::io::BufReader::new(tokio::io::stdin());
    let mut line = String::new();
    loop {
        if Instant::now() >= deadline {
            return false; // no answer in time: continue without the history
        }
        let remaining = deadline - Instant::now();
        let read = tokio::time::timeout(remaining, reader.read_line(&mut line)).await;
        match read {
            // EOF or timeout: no answer, continue without the history.
            Ok(Ok(0)) | Err(_) => return false,
            Ok(Ok(_)) => {}
            Ok(Err(e)) => {
                warn!(%e, "cannot read the transfer answer from stdin");
                return false;
            }
        }
        match line.trim().to_ascii_lowercase().as_str() {
            "transfer" | "y" | "yes" => return true,
            "skip" | "n" | "no" => return false,
            _ => line.clear(), // keep waiting for a usable answer until the timeout
        }
    }
}

/// Tells the phone (primary) to stop uploading the history archive: the user declined the
/// transfer here, which the official desktop client reports as CONTINUE_WITHOUT_UPLOAD on
/// the same endpoint the archive is announced on. The phone had already started building
/// the archive when it scanned the QR, so without this it would upload in vain. Best
/// effort — a failure only costs the phone one upload; the link itself is done either way.
pub async fn notify_no_upload(
    push: &PushService,
    destination_device_id: u32,
    destination_device_registration_id: u32,
) -> anyhow::Result<()> {
    let response = push
        .request(
            Method::PUT,
            Endpoint::Service {
                path: std::borrow::Cow::Borrowed("/v1/devices/transfer_archive"),
            },
            HttpAuthOverride::NoOverride,
        )?
        .json(&json!({
            "destinationDeviceId": destination_device_id,
            "destinationDeviceRegistrationId": destination_device_registration_id,
            "transferArchive": { "error": "CONTINUE_WITHOUT_UPLOAD" },
        }))
        .send()
        .await?;
    let status = response.status();
    if !status.is_success() {
        bail!("transfer_archive error report answered HTTP {status}");
    }
    Ok(())
}

/// Fetches the archive pointer from the server. None means the phone decided to continue
/// without a transfer (CONTINUE_WITHOUT_UPLOAD). The server answers only after the phone
/// uploaded the archive, so this long-polls until it does or the deadline passes.
async fn fetch_pointer(push: &PushService, deadline: Instant) -> anyhow::Result<Option<(u32, String)>> {
    loop {
        if Instant::now() >= deadline {
            bail!("the phone did not upload the history archive in time");
        }
        let response = push
            .request(
                Method::GET,
                Endpoint::Service {
                    path: std::borrow::Cow::Owned(format!(
                        "/v1/devices/transfer_archive?timeout={LONG_POLL_SECONDS}"
                    )),
                },
                HttpAuthOverride::NoOverride,
            )?
            .send()
            .await?;
        let status = response.status();
        if status == reqwest::StatusCode::NO_CONTENT {
            continue; // long poll expired without an archive; ask again
        }
        if !status.is_success() {
            bail!("transfer_archive answered HTTP {status}");
        }
        let value: Value = response.json().await?;
        if let Some(error) = value.get("error").and_then(|e| e.as_str()) {
            match error {
                // The primary gave up on the transfer; link without the history.
                "CONTINUE_WITHOUT_UPLOAD" => return Ok(None),
                "RELINK_REQUESTED" => bail!("the phone asks to link again (RELINK_REQUESTED)"),
                other => bail!("transfer_archive error: {other}"),
            }
        }
        let cdn = value
            .get("cdn")
            .and_then(|v| v.as_u64())
            .context("transfer_archive: missing cdn")? as u32;
        let key = value
            .get("key")
            .and_then(|v| v.as_str())
            .context("transfer_archive: missing key")?
            .to_owned();
        return Ok(Some((cdn, key)));
    }
}

/// Streams the archive from the attachment CDN to `path`.
async fn download_archive(push: &PushService, cdn: u32, key: &str, path: &Path) -> anyhow::Result<()> {
    let mut response = push
        .request(
            Method::GET,
            Endpoint::Cdn {
                cdn_id: cdn,
                path: std::borrow::Cow::Owned(format!("/attachments/{key}")),
                query: None,
            },
            HttpAuthOverride::Unidentified,
        )?
        .send()
        .await?;
    let status = response.status();
    if !status.is_success() {
        bail!("archive download answered HTTP {status}");
    }
    let mut file = tokio::fs::File::create(path).await?;
    while let Some(chunk) = response.chunk().await? {
        file.write_all(&chunk).await?;
    }
    file.flush().await?;
    Ok(())
}

/// The AES/HMAC keys of the archive: derived from the ephemeral backup key and our ACI exactly
/// like the official clients do for a link-and-sync transfer (libsignal's MessageBackupKey,
/// backup id version 1, no forward-secrecy token for this purpose).
fn message_backup_key(ephemeral_key: [u8; 32], aci: &Aci) -> MessageBackupKey {
    // Presage still supplies the v0.99.0 Aci type, while BackupKey v0.108.3 expects
    // libsignal-core's v0.108.3 Aci. The service ID binary representation is the same
    // protocol-level 16-byte UUID, so bridge the Rust type boundary explicitly.
    let backup_aci_bytes: [u8; 16] = aci
        .service_id_binary()
        .try_into()
        .expect("an ACI service ID must be 16 bytes");
    let backup_aci = BackupAci::from_uuid_bytes(backup_aci_bytes);

    // The ephemeral key is used as a BackupKey directly; the version is pinned by the protocol.
    let backup_key = BackupKey::<1>(ephemeral_key);
    let backup_id = backup_key.derive_backup_id(&backup_aci);
    MessageBackupKey::derive::<1>(&backup_key, &backup_id, None)
}

/// Our own address, used for outgoing messages and as the "source" of sent syncs.
#[derive(Clone, Debug)]
pub struct SelfInfo {
    pub aci: String,
    pub number: String,
}

/// Runs the whole transfer for a freshly linked account and writes the results into `dir`.
/// Returns the number of imported messages, or None when the phone decided against the
/// transfer. `progress` is called with the running count while frames are converted.
pub async fn run(
    push: &PushService,
    dir: &Path,
    ephemeral_key: [u8; 32],
    self_info: SelfInfo,
    mut progress: impl FnMut(usize),
) -> anyhow::Result<Option<usize>> {
    info!("waiting for the phone to upload the history archive");
    let deadline = Instant::now() + TRANSFER_TIMEOUT;
    let Some((cdn, key)) = fetch_pointer(push, deadline).await? else {
        info!("the phone continued without a history transfer");
        return Ok(None);
    };
    let archive = dir.join(ARCHIVE_TMP);
    download_archive(push, cdn, &key, &archive).await?;
    let aci = Aci::from_uuid_bytes(Uuid::parse_str(&self_info.aci)?.into_bytes());
    let imported = import_frames(&archive, ephemeral_key, &aci, &self_info, dir, &mut progress).await;
    let _ = std::fs::remove_file(&archive);
    imported
}

/// Reads, decrypts and converts the archive frames, writing the JSONL/meta/attachments files.
async fn import_frames(
    archive: &Path,
    ephemeral_key: [u8; 32],
    aci: &Aci,
    self_info: &SelfInfo,
    dir: &Path,
    progress: &mut impl FnMut(usize),
) -> anyhow::Result<Option<usize>> {
    let key = message_backup_key(ephemeral_key, aci);
    let factory = FileReaderFactory { path: archive };
    // Verifies the HMAC, decrypts and decompresses; the frames are the plaintext stream.
    let frames = FramesReader::new(&key, factory)
        .await
        .map_err(|e| anyhow::anyhow!("the history archive is invalid: {e}"))?;
    let mut reader = VarintDelimitedReader::new(frames);

    let mut state = Converter::new(self_info.clone());
    let mut saw_info = false;
    let mut count = 0usize;
    let mut report = 0usize;

    let mut out = std::io::BufWriter::new(std::fs::File::create(history_file(dir))?);
    while let Some(raw) = reader.read_next().await? {
        if !saw_info {
            // The first item is the BackupInfo header, not a frame.
            let info = BackupInfo::parse_from_bytes(&raw)?;
            info!(version = info.version, "history archive version");
            saw_info = true;
            continue;
        }
        let frame = Frame::parse_from_bytes(&raw)?;
        for envelope in state.convert(frame)? {
            serde_json::to_writer(&mut out, &envelope)?;
            out.write_all(b"\n")?;
            count += 1;
            if count - report >= PROGRESS_STEP {
                report = count;
                progress(count);
            }
        }
    }
    out.flush()?;

    std::fs::write(attachments_file(dir), serde_json::to_vec(&Value::Object(state.attachments.clone()))?)?;
    let meta = json!({"done": true, "count": count, "finishedAt": crate::daemon::now_ms()});
    std::fs::write(meta_file(dir), serde_json::to_vec(&meta)?)?;
    progress(count);
    Ok(Some(count))
}

/// What one recipient of the archive is: a contact (by number and/or ACI), a group (by master
/// key) or ourselves. Anything else (call links, stories) cannot appear in Corvus chats.
#[derive(Clone, Debug)]
enum Destination {
    Contact { uuid: Option<String>, e164: Option<String>, name: Option<String> },
    Group([u8; 32]),
    Self_,
    Other,
}

#[derive(Clone, Debug)]
struct ChatEntry {
    recipient: u64,
    /// Chat-wide expiration timer in seconds (items may carry their own).
    expiration_seconds: u32,
}

struct Person {
    uuid: Option<String>,
    e164: Option<String>,
    name: Option<String>,
}

/// Turns archive frames into envelope JSONs in the exact shape crate::envelope emits.
struct Converter {
    self_info: SelfInfo,
    recipients: HashMap<u64, Destination>,
    chats: HashMap<u64, ChatEntry>,
    /// Attachment id -> CDN pointer info, for downloadAttachment.
    attachments: Map<String, Value>,
}

impl Converter {
    fn new(self_info: SelfInfo) -> Self {
        Self {
            self_info,
            recipients: HashMap::new(),
            chats: HashMap::new(),
            attachments: Map::new(),
        }
    }

    /// Converts one frame into zero or more envelopes, in file order.
    fn convert(&mut self, frame: Frame) -> anyhow::Result<Vec<Value>> {
        match frame.item {
            Some(frame::Item::Recipient(r)) => self.convert_recipient(r),
            Some(frame::Item::Chat(c)) => {
                self.chats.insert(
                    c.id,
                    ChatEntry {
                        recipient: c.recipientId,
                        expiration_seconds: c
                            .expirationTimerMs
                            .map(|ms| (ms / 1000).min(u32::MAX as u64) as u32)
                            .unwrap_or(0),
                    },
                );
                Ok(Vec::new())
            }
            Some(frame::Item::ChatItem(item)) => self.convert_item(item),
            // Accounts, sticker packs, call logs, chat folders and notification profiles are
            // either synced live by presage or not shown by Corvus.
            _ => Ok(Vec::new()),
        }
    }

    fn convert_recipient(&mut self, r: Recipient) -> anyhow::Result<Vec<Value>> {
        let Some(id) = (r.id != 0).then_some(r.id) else { return Ok(Vec::new()) };
        let destination = match r.destination {
            Some(recipient::Destination::Contact(contact)) => {
                let uuid = contact.aci.as_deref().and_then(|b| Uuid::from_slice(b).ok());
                Destination::Contact {
                    uuid: uuid.map(|u| u.to_string()),
                    e164: contact.e164.map(|n| format!("+{n}")),
                    name: contact_name(&contact),
                }
            }
            Some(recipient::Destination::Group(group)) => match group.masterKey.try_into() {
                Ok(key) => Destination::Group(key),
                Err(_) => Destination::Other,
            },
            Some(recipient::Destination::Self_(_)) => Destination::Self_,
            _ => Destination::Other,
        };
        self.recipients.insert(id, destination);
        Ok(Vec::new())
    }

    fn convert_item(&mut self, item: ChatItem) -> anyhow::Result<Vec<Value>> {
        let Some(chat) = self.chats.get(&item.chatId) else { return Ok(Vec::new()) };
        let recipient_id = chat.recipient;
        let expiration = match item.expiresInMs {
            Some(ms) => (ms / 1000).min(u32::MAX as u64) as u32,
            None => chat.expiration_seconds,
        };
        let group = self.group_json(recipient_id);
        let destination = self.recipient_person(recipient_id);
        let date_sent = item.dateSent;
        let date_received = match item.directionalDetails.as_ref() {
            Some(chat_item::DirectionalDetails::Incoming(i)) => i.dateReceived,
            Some(chat_item::DirectionalDetails::Outgoing(o)) => o.dateReceived,
            _ => date_sent,
        };
        let outgoing = matches!(
            item.directionalDetails,
            Some(chat_item::DirectionalDetails::Outgoing(_))
        );
        let author = self.recipient_person(item.authorId).unwrap_or_else(|| self.self_person());
        let self_recipient_id = self.self_recipient();

        // The content this item shows now; revisions are older versions of the same message.
        let mut envelopes = Vec::new();
        match item.item {
            Some(chat_item::Item::StandardMessage(m)) => {
                let dm = self.standard_message_json(&m, group.clone(), expiration, date_sent);
                if outgoing {
                    envelopes.push(self.outgoing_envelope(destination.as_ref(), dm, date_sent, date_received));
                } else {
                    envelopes.push(self.incoming_envelope(&author, dm, date_sent, date_received));
                }
                // Reactions hang off the message they refer to; each becomes its own envelope
                // like a live reaction does.
                for reaction in &m.reactions {
                    let reactor = self
                        .recipient_person(reaction.authorId)
                        .unwrap_or_else(|| self.self_person());
                    let dm = self.reaction_data(reaction, item.authorId, group.clone(), date_sent);
                    if reaction.authorId == self_recipient_id {
                        envelopes.push(self.outgoing_envelope(destination.as_ref(), dm, reaction.sentTimestamp, reaction.sentTimestamp));
                    } else {
                        envelopes.push(self.incoming_envelope(&reactor, dm, reaction.sentTimestamp, reaction.sentTimestamp));
                    }
                }
                // Edits: the newest revision is the current content of the item, so an edit
                // envelope marks the imported message as edited. Older revisions are not
                // reproducible as individual edit events (they carry no distinct timestamps).
                if let Some(revision) = item.revisions.last() {
                    if let Some(text) = revision_text(revision).filter(|t| !t.is_empty()) {
                        let edit_data = self.edit_json(&group, expiration, date_sent, text);
                        let envelope = if outgoing {
                            self.outgoing_edit_envelope(destination.as_ref(), edit_data, date_sent, date_received)
                        } else {
                            self.incoming_edit_envelope(&author, edit_data, date_sent, date_received)
                        };
                        envelopes.push(envelope);
                    }
                }
            }
            Some(chat_item::Item::RemoteDeletedMessage(_)) => {
                let mut dm = Map::new();
                dm.insert("timestamp".into(), json!(date_sent));
                dm.insert("remoteDelete".into(), json!({"timestamp": date_sent}));
                let dm = self.with_group(dm, group.clone());
                let envelope = if outgoing {
                    self.outgoing_envelope(destination.as_ref(), dm, date_sent, date_received)
                } else {
                    self.incoming_envelope(&author, dm, date_sent, date_received)
                };
                envelopes.push(envelope);
            }
            Some(chat_item::Item::UpdateMessage(update)) => {
                if let Some(chat_update_message::Update::ExpirationTimerChange(timer)) = update.update {
                    let mut dm = Map::new();
                    dm.insert("timestamp".into(), json!(date_sent));
                    dm.insert(
                        "expiresInSeconds".into(),
                        json!((timer.expiresInMs / 1000).min(u32::MAX as u64)),
                    );
                    dm.insert("isExpirationUpdate".into(), json!(true));
                    let dm = self.with_group(dm, group.clone());
                    let envelope = if outgoing {
                        self.outgoing_envelope(destination.as_ref(), dm, date_sent, date_received)
                    } else {
                        self.incoming_envelope(&author, dm, date_sent, date_received)
                    };
                    envelopes.push(envelope);
                }
                // Other chat updates (group changes, calls, profile changes, pins) are not
                // shown by Corvus as chat messages; group metadata arrives live from the
                // storage service instead.
            }
            Some(chat_item::Item::ViewOnceMessage(view)) => {
                let mut dm = Map::new();
                dm.insert("timestamp".into(), json!(date_sent));
                dm.insert("expiresInSeconds".into(), json!(expiration));
                dm.insert("viewOnce".into(), json!(true));
                if let Some(attachment) = view.attachment.as_ref() {
                    dm.insert("attachments".into(), json!([self.attachment_json(attachment)]));
                }
                let dm = self.with_group(dm, group.clone());
                let envelope = if outgoing {
                    self.outgoing_envelope(destination.as_ref(), dm, date_sent, date_received)
                } else {
                    self.incoming_envelope(&author, dm, date_sent, date_received)
                };
                envelopes.push(envelope);
            }
            Some(chat_item::Item::ContactMessage(m)) => {
                let mut dm = Map::new();
                dm.insert("timestamp".into(), json!(date_sent));
                dm.insert("expiresInSeconds".into(), json!(expiration));
                dm.insert("contacts".into(), json!([self.contact_attachment_json(m.contact.as_ref())]));
                let dm = self.with_group(dm, group.clone());
                let envelope = if outgoing {
                    self.outgoing_envelope(destination.as_ref(), dm, date_sent, date_received)
                } else {
                    self.incoming_envelope(&author, dm, date_sent, date_received)
                };
                envelopes.push(envelope);
            }
            Some(chat_item::Item::StickerMessage(m)) => {
                let Some(sticker) = m.sticker.as_ref() else { return Ok(Vec::new()) };
                let mut dm = Map::new();
                dm.insert("timestamp".into(), json!(date_sent));
                dm.insert("expiresInSeconds".into(), json!(expiration));
                dm.insert(
                    "sticker".into(),
                    json!({
                        "packId": hex(&sticker.packId),
                        "stickerId": sticker.stickerId,
                        "emoji": sticker.emoji,
                        "attachmentId": sticker.data.as_ref().and_then(|d| d.locatorInfo.as_ref())
                            .and_then(|l| l.transitCdnKey.clone())
                            .filter(|k| !k.is_empty()),
                    }),
                );
                let dm = self.with_group(dm, group.clone());
                let envelope = if outgoing {
                    self.outgoing_envelope(destination.as_ref(), dm, date_sent, date_received)
                } else {
                    self.incoming_envelope(&author, dm, date_sent, date_received)
                };
                envelopes.push(envelope);
            }
            Some(chat_item::Item::Poll(poll)) => {
                let mut dm = Map::new();
                dm.insert("timestamp".into(), json!(date_sent));
                dm.insert("expiresInSeconds".into(), json!(expiration));
                dm.insert(
                    "pollCreate".into(),
                    json!({
                        "question": poll.question,
                        "allowMultiple": poll.allowMultiple,
                        // Individual votes have no timestamps in the archive, so the live vote
                        // events are not reproducible; the options are imported as-is.
                        "options": poll.options.iter().map(|o| o.option.clone()).collect::<Vec<_>>(),
                    }),
                );
                let dm = self.with_group(dm, group.clone());
                let envelope = if outgoing {
                    self.outgoing_envelope(destination.as_ref(), dm, date_sent, date_received)
                } else {
                    self.incoming_envelope(&author, dm, date_sent, date_received)
                };
                envelopes.push(envelope);
            }
            // Story replies, payments, gift badges, calls and admin deletions are not shown by
            // Corvus as chat messages.
            _ => {}
        }
        // Corvus drops message envelopes without a usable timestamp; keep the rest.
        envelopes.retain(|env| env.get("timestamp").and_then(|t| t.as_u64()).unwrap_or(0) > 0);
        Ok(envelopes)
    }

    fn self_recipient(&self) -> u64 {
        self.recipients
            .iter()
            .find(|(_, d)| matches!(d, Destination::Self_))
            .map(|(id, _)| *id)
            .unwrap_or(u64::MAX)
    }

    fn self_person(&self) -> Person {
        Person {
            uuid: Some(self.self_info.aci.clone()),
            e164: Some(self.self_info.number.clone()),
            name: None,
        }
    }

    fn recipient_person(&self, id: u64) -> Option<Person> {
        match self.recipients.get(&id)? {
            Destination::Contact { uuid, e164, name } => Some(Person {
                uuid: uuid.clone(),
                e164: e164.clone(),
                name: name.clone(),
            }),
            Destination::Self_ => Some(self.self_person()),
            _ => None,
        }
    }

    /// signal-cli's group id for a chat: base64 of the group identifier derived from the
    /// master key (crate::envelope::group_id). None for 1:1 chats.
    fn group_json(&self, recipient_id: u64) -> Option<Value> {
        let Destination::Group(master_key) = self.recipients.get(&recipient_id)? else {
            return None;
        };
        let params = presage::libsignal_service::prelude::GroupSecretParams::derive_from_master_key(
            presage::libsignal_service::prelude::GroupMasterKey::new(*master_key),
        );
        Some(json!({
            "groupId": BASE64_STANDARD.encode(params.get_group_identifier()),
            "type": "DELIVER",
        }))
    }

    fn with_group(&self, mut dm: Map<String, Value>, group: Option<Value>) -> Map<String, Value> {
        if let Some(group) = group {
            dm.insert("groupInfo".into(), group);
        }
        dm
    }

    /// The header of an incoming envelope (crate::envelope::header with an archive person).
    fn incoming_envelope(
        &self,
        person: &Person,
        data_message: Map<String, Value>,
        date_sent: u64,
        date_received: u64,
    ) -> Value {
        let mut env = Map::new();
        insert_address(&mut env, "source", person);
        env.insert("sourceName".into(), json!(person.name));
        env.insert("sourceDevice".into(), json!(1));
        env.insert("timestamp".into(), json!(date_sent));
        env.insert("serverReceivedTimestamp".into(), json!(date_received));
        env.insert("dataMessage".into(), Value::Object(data_message));
        Value::Object(env)
    }

    /// An incoming edit: {"editMessage": {"targetSentTimestamp", "dataMessage"}} at the top.
    fn incoming_edit_envelope(
        &self,
        person: &Person,
        edit_data: Value,
        date_sent: u64,
        date_received: u64,
    ) -> Value {
        let mut env = self.incoming_envelope(person, Map::new(), date_sent, date_received);
        if let Some(env) = env.as_object_mut() {
            env.insert("editMessage".into(), edit_data);
        }
        env
    }

    /// The envelope of a message sent by us on the phone: a sent sync like live ones.
    fn outgoing_envelope(
        &self,
        destination: Option<&Person>,
        data_message: Map<String, Value>,
        date_sent: u64,
        date_received: u64,
    ) -> Value {
        let mut sent = Map::new();
        if let Some(dest) = destination {
            insert_address(&mut sent, "destination", dest);
        }
        for (key, value) in data_message {
            sent.insert(key, value);
        }
        let self_person = self.self_person();
        let mut env = Map::new();
        insert_address(&mut env, "source", &self_person);
        env.insert("sourceName".into(), Value::Null);
        env.insert("sourceDevice".into(), json!(1));
        env.insert("timestamp".into(), json!(date_sent));
        env.insert("serverReceivedTimestamp".into(), json!(date_received));
        env.insert("syncMessage".into(), json!({"sentMessage": Value::Object(sent)}));
        Value::Object(env)
    }

    /// An outgoing edit: like a live sent sync with editMessage inside sentMessage
    /// (crate::envelope::sent_json).
    fn outgoing_edit_envelope(
        &self,
        destination: Option<&Person>,
        edit_data: Value,
        date_sent: u64,
        date_received: u64,
    ) -> Value {
        let mut sent = Map::new();
        if let Some(dest) = destination {
            insert_address(&mut sent, "destination", dest);
        }
        sent.insert("editMessage".into(), edit_data);
        sent.insert("timestamp".into(), json!(date_sent));
        let self_person = self.self_person();
        let mut env = Map::new();
        insert_address(&mut env, "source", &self_person);
        env.insert("sourceName".into(), Value::Null);
        env.insert("sourceDevice".into(), json!(1));
        env.insert("timestamp".into(), json!(date_sent));
        env.insert("serverReceivedTimestamp".into(), json!(date_received));
        env.insert("syncMessage".into(), json!({"sentMessage": Value::Object(sent)}));
        Value::Object(env)
    }

    /// The editMessage JSON shared by incoming and outgoing edits.
    fn edit_json(&self, group: &Option<Value>, expiration: u32, date_sent: u64, text: String) -> Value {
        let mut dm = Map::new();
        dm.insert("timestamp".into(), json!(date_sent));
        dm.insert("message".into(), json!(text));
        dm.insert("expiresInSeconds".into(), json!(expiration));
        let dm = self.with_group(dm, group.clone());
        json!({
            "targetSentTimestamp": date_sent,
            "dataMessage": Value::Object(dm),
        })
    }

    /// The dataMessage members of a text (or attachment) message, matching
    /// crate::envelope::data_message_fields.
    fn standard_message_json(
        &mut self,
        message: &StandardMessage,
        group: Option<Value>,
        expiration: u32,
        date_sent: u64,
    ) -> Map<String, Value> {
        let mut dm = Map::new();
        dm.insert("timestamp".into(), json!(date_sent));
        dm.insert("expiresInSeconds".into(), json!(expiration));
        if let Some(group) = group {
            dm.insert("groupInfo".into(), group);
        }
        if let Some(text) = message.text.as_ref() {
            dm.insert("message".into(), json!(text.body));
            // Style ranges become signal-cli's "start:length:STYLE" strings; mentions are
            // skipped, like the live envelope path does.
            let ranges: Vec<PresageBodyRange> = text
                .bodyRanges
                .iter()
                .filter_map(|r| {
                    let style = match r.associatedValue.as_ref()? {
                        body_range::AssociatedValue::Style(style) => style.value(),
                        body_range::AssociatedValue::MentionAci(_) => return None,
                        _ => return None,
                    };
                    Some(PresageBodyRange {
                        start: Some(r.start),
                        length: Some(r.length),
                        associated_value: Some(presage_body_range::AssociatedValue::Style(style)),
                    })
                })
                .collect();
            let styles = textstyle::to_strings(&ranges);
            if !styles.is_empty() {
                dm.insert("textStyle".into(), json!(styles));
            }
        }
        if !message.attachments.is_empty() {
            dm.insert(
                "attachments".into(),
                json!(message.attachments.iter().map(|a| self.attachment_json(a)).collect::<Vec<_>>()),
            );
        }
        if let Some(quote) = message.quote.as_ref() {
            let mut q = Map::new();
            q.insert("id".into(), json!(quote.targetSentTimestamp));
            if let Some(author) = self.recipient_person(quote.authorId) {
                insert_address(&mut q, "author", &author);
            }
            q.insert("text".into(), json!(quote.text.as_ref().map(|t| t.body.clone())));
            q.insert(
                "attachments".into(),
                json!(quote
                    .attachments
                    .iter()
                    .map(|a| json!({"contentType": a.contentType, "filename": a.fileName}))
                    .collect::<Vec<_>>()),
            );
            dm.insert("quote".into(), Value::Object(q));
        }
        if let Some(preview) = message.linkPreview.first() {
            let mut p = Map::new();
            p.insert("url".into(), json!(preview.url));
            p.insert("title".into(), json!(preview.title));
            p.insert("description".into(), json!(preview.description));
            if let Some(image) = preview.image.as_ref() {
                p.insert("image".into(), self.file_pointer_json(image));
            }
            dm.insert("previews".into(), json!([Value::Object(p)]));
        }
        dm
    }

    /// The dataMessage of a live reaction envelope: the reaction rides on the message it
    /// refers to, so the target is that message (its author and its sent timestamp).
    fn reaction_data(
        &mut self,
        reaction: &Reaction,
        target_author: u64,
        group: Option<Value>,
        target_ts: u64,
    ) -> Map<String, Value> {
        let mut dm = Map::new();
        dm.insert("timestamp".into(), json!(reaction.sentTimestamp));
        if let Some(group) = group {
            dm.insert("groupInfo".into(), group);
        }
        let mut r = Map::new();
        r.insert("emoji".into(), json!(reaction.emoji));
        if let Some(author) = self.recipient_person(target_author) {
            insert_address(&mut r, "targetAuthor", &author);
        }
        r.insert("targetSentTimestamp".into(), json!(target_ts));
        r.insert("isRemove".into(), json!(false));
        dm.insert("reaction".into(), Value::Object(r));
        dm
    }

    /// Corvus' attachment JSON plus (for transit-tier files) the CDN pointer used by
    /// downloadAttachment. Without transit info the attachment has no id and Corvus shows
    /// a placeholder instead of a thumbnail, like for a failed live download.
    fn attachment_json(&mut self, attachment: &MessageAttachment) -> Value {
        self.file_pointer_json_ext(
            attachment.pointer.as_ref(),
            attachment.flag.value() == message_attachment::Flag::VOICE_MESSAGE as i32,
        )
    }

    fn file_pointer_json(&mut self, pointer: &FilePointer) -> Value {
        self.file_pointer_json_ext(Some(pointer), false)
    }

    fn file_pointer_json_ext(&mut self, pointer: Option<&FilePointer>, voice_note: bool) -> Value {
        let Some(pointer) = pointer else { return json!({}) };
        let locator = pointer.locatorInfo.as_ref();
        let transit_key = locator
            .and_then(|l| l.transitCdnKey.clone())
            .filter(|k| !k.is_empty());
        let mut out = Map::new();
        out.insert("contentType".into(), json!(pointer.contentType));
        out.insert("filename".into(), json!(pointer.fileName));
        out.insert("size".into(), json!(locator.map(|l| l.size)));
        out.insert("width".into(), json!(pointer.width));
        out.insert("height".into(), json!(pointer.height));
        out.insert("caption".into(), json!(pointer.caption));
        out.insert("voiceNote".into(), json!(voice_note));
        let Some(transit_key) = transit_key else {
            return Value::Object(out);
        };
        let id: String = transit_key
            .chars()
            .map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c } else { '_' })
            .collect();
        if id.is_empty() {
            return Value::Object(out);
        }
        out.insert("id".into(), json!(id));
        // Record how to download this file later (downloadAttachment). Only plain transit CDN
        // entries work, and the decryption key must be present; the digest may be.
        if let Some(locator) = locator {
            if !locator.key.is_empty() {
                let key = &locator.key;
                let digest = match locator.integrityCheck.as_ref() {
                    Some(file_pointer::locator_info::IntegrityCheck::EncryptedDigest(d)) => {
                        Some(BASE64_STANDARD.encode(d))
                    }
                    _ => None,
                };
                self.attachments.insert(
                    id.clone(),
                    json!({
                        "cdn": locator.transitCdnNumber.unwrap_or(3),
                        "cdnKey": transit_key,
                        "key": BASE64_STANDARD.encode(key),
                        "digest": digest,
                        "size": locator.size,
                        "contentType": pointer.contentType,
                        "filename": pointer.fileName,
                        "caption": pointer.caption,
                        "width": pointer.width,
                        "height": pointer.height,
                        "voiceNote": voice_note,
                    }),
                );
            }
        }
        Value::Object(out)
    }

    /// A contact card like crate::envelope::contact_json.
    fn contact_attachment_json(&mut self, contact: Option<&ContactAttachment>) -> Value {
        let mut out = Map::new();
        let Some(contact) = contact else { return Value::Object(out) };
        if let Some(name) = contact.name.as_ref() {
            let mut full = name.givenName.clone();
            if !name.familyName.is_empty() {
                if !full.is_empty() {
                    full.push(' ');
                }
                full.push_str(&name.familyName);
            }
            out.insert("name".into(), json!(full));
        }
        if let Some(phone) = contact.number.first() {
            out.insert("number".into(), json!(phone.value));
        }
        if let Some(avatar) = contact.avatar.as_ref() {
            out.insert("avatar".into(), self.file_pointer_json(avatar));
        }
        Value::Object(out)
    }
}

use libsignal_message_backup::proto::backup::{ContactAttachment, FilePointer, MessageAttachment};

/// The three address fields signal-cli emits for a person ("<prefix>", "<prefix>Number",
/// "<prefix>Uuid"), like crate::envelope::Directory::address.
fn insert_address(out: &mut Map<String, Value>, prefix: &str, person: &Person) {
    if let Some(number) = &person.e164 {
        out.insert(prefix.to_owned(), json!(number));
        out.insert(format!("{prefix}Number"), json!(number));
    } else if let Some(uuid) = &person.uuid {
        out.insert(prefix.to_owned(), json!(uuid));
    }
    if let Some(uuid) = &person.uuid {
        out.insert(format!("{prefix}Uuid"), json!(uuid));
    }
}

fn contact_name(contact: &Contact) -> Option<String> {
    let profile = contact
        .profileGivenName
        .clone()
        .filter(|s| !s.is_empty())
        .map(|given| match contact.profileFamilyName.as_deref().filter(|f| !f.is_empty()) {
            Some(family) => format!("{given} {family}"),
            None => given,
        });
    profile.or_else(|| {
        if contact.systemGivenName.is_empty() {
            None
        } else if contact.systemFamilyName.is_empty() {
            Some(contact.systemGivenName.clone())
        } else {
            Some(format!("{} {}", contact.systemGivenName, contact.systemFamilyName))
        }
    })
}

/// The body of a revision ChatItem (an edit): the text, or None when the revision carries
/// no text.
fn revision_text(revision: &ChatItem) -> Option<String> {
    match revision.item.as_ref() {
        Some(chat_item::Item::StandardMessage(m)) => Some(m.text.as_ref().map(|t| t.body.clone()).unwrap_or_default()),
        _ => None,
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The attachment pointer corvus-cli builds from the archive for downloadAttachment.
pub fn pointer_from_index(entry: &Value) -> Option<AttachmentPointer> {
    let cdn_key = entry.get("cdnKey")?.as_str()?.to_owned();
    if cdn_key.is_empty() {
        return None;
    }
    let decode = |field: &str| -> Option<Vec<u8>> {
        entry
            .get(field)
            .and_then(|v| v.as_str())
            .and_then(|s| BASE64_STANDARD.decode(s).ok())
    };
    Some(AttachmentPointer {
        attachment_identifier: Some(AttachmentIdentifier::CdnKey(cdn_key)),
        content_type: entry.get("contentType").and_then(|v| v.as_str()).map(str::to_owned),
        key: decode("key"),
        size: entry.get("size").and_then(|v| v.as_u64()).map(|s| s.min(u32::MAX as u64) as u32),
        digest: decode("digest"),
        flags: entry.get("voiceNote").and_then(|v| v.as_bool()).filter(|b| *b).map(|_| 1),
        width: entry.get("width").and_then(|v| v.as_u64()).map(|s| s.min(u32::MAX as u64) as u32),
        height: entry.get("height").and_then(|v| v.as_u64()).map(|s| s.min(u32::MAX as u64) as u32),
        file_name: entry.get("filename").and_then(|v| v.as_str()).map(str::to_owned),
        caption: entry.get("caption").and_then(|v| v.as_str()).map(str::to_owned),
        ..Default::default()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use protobuf::MessageField;
    use libsignal_message_backup::proto::backup::{Chat, Text};
    use libsignal_message_backup::proto::backup::chat_item::IncomingMessageDetails;

    #[test]
    fn qr_url_gets_the_link_and_sync_capability() {
        // What presage produces for the QR code (uuid + pub_key, no capabilities).
        let url: Url = "sgnl://linkdevice?uuid=d382d457-45e2-4d17-a1e9-5f76cf2d0b39&pub_key=YWJj"
            .parse()
            .unwrap();
        let url = with_link_capabilities(url);
        // Same query order as Signal Desktop: uuid, pub_key, capabilities — the comma list
        // is form-urlencoded (%2C), which Android's Uri.getQueryParameter decodes back.
        assert_eq!(url.as_str(),
            "sgnl://linkdevice?uuid=d382d457-45e2-4d17-a1e9-5f76cf2d0b39&pub_key=YWJj&capabilities=nopni%2Cnopni2%2Cbackup5");
        // A URL that already carries capabilities stays untouched.
        let pre: Url = "sgnl://linkdevice?uuid=d382d457-45e2-4d17-a1e9-5f76cf2d0b39&pub_key=YWJj&capabilities=backup5"
            .parse()
            .unwrap();
        assert_eq!(with_link_capabilities(pre.clone()).as_str(), pre.as_str());
    }

    fn self_info() -> SelfInfo {
        SelfInfo {
            aci: "33333333-3333-4333-8333-333333333333".into(),
            number: "+49333".into(),
        }
    }

    fn contact_recipient() -> Destination {
        Destination::Contact {
            uuid: Some("11111111-1111-4111-8111-111111111111".into()),
            e164: Some("+49111".into()),
            name: Some("Alice".into()),
        }
    }

    #[test]
    fn address_fields_like_signal_cli() {
        let mut out = Map::new();
        insert_address(
            &mut out,
            "source",
            &Person { uuid: Some("11111111-1111-4111-8111-111111111111".into()), e164: Some("+49111".into()), name: None },
        );
        assert_eq!(out["source"], json!("+49111"));
        assert_eq!(out["sourceNumber"], json!("+49111"));
        assert_eq!(out["sourceUuid"], json!("11111111-1111-4111-8111-111111111111"));

        // A contact without a number (username-only) falls back to the UUID as the address.
        let mut out = Map::new();
        insert_address(
            &mut out,
            "source",
            &Person { uuid: Some("22222222-2222-4222-8222-222222222222".into()), e164: None, name: None },
        );
        assert_eq!(out["source"], json!("22222222-2222-4222-8222-222222222222"));
        assert!(out.get("sourceNumber").is_none());
    }

    #[test]
    fn incoming_text_message_becomes_a_live_envelope() {
        let mut state = Converter::new(self_info());
        state.recipients.insert(1, contact_recipient());
        state.recipients.insert(2, Destination::Self_);
        state.chats.insert(10, ChatEntry { recipient: 1, expiration_seconds: 0 });
        state.chats.insert(11, ChatEntry { recipient: 2, expiration_seconds: 60 });

        let item = ChatItem {
            chatId: 10,
            authorId: 1,
            dateSent: 1_700_000_000_000,
            directionalDetails: Some(chat_item::DirectionalDetails::Incoming(IncomingMessageDetails {
                dateReceived: 1_700_000_000_123,
                dateServerSent: None,
                read: false,
                sealedSender: false,
                ..Default::default()
            })),
            item: Some(chat_item::Item::StandardMessage(StandardMessage {
                text: MessageField::some(Text { body: "hello".into(), bodyRanges: Vec::new(), ..Default::default() }),
                ..Default::default()
            })),
            ..Default::default()
        };
        let envelopes = state.convert_item(item).unwrap();
        assert_eq!(envelopes.len(), 1);
        let env = &envelopes[0];
        assert_eq!(env["source"], json!("+49111"));
        assert_eq!(env["sourceName"], json!("Alice"));
        assert_eq!(env["timestamp"], json!(1_700_000_000_000i64));
        assert_eq!(env["serverReceivedTimestamp"], json!(1_700_000_000_123i64));
        assert_eq!(env["dataMessage"]["message"], json!("hello"));
        assert_eq!(env["dataMessage"]["expiresInSeconds"], json!(0));

        // An outgoing message becomes a sent sync with a destination.
        let item = ChatItem {
            chatId: 11,
            authorId: 2,
            dateSent: 1_700_000_005_000,
            directionalDetails: Some(chat_item::DirectionalDetails::Outgoing(chat_item::OutgoingMessageDetails {
                sendStatus: Vec::new(),
                dateReceived: 1_700_000_005_000,
                ..Default::default()
            })),
            item: Some(chat_item::Item::StandardMessage(StandardMessage {
                text: MessageField::some(Text { body: "hi me".into(), bodyRanges: Vec::new(), ..Default::default() }),
                ..Default::default()
            })),
            ..Default::default()
        };
        let envelopes = state.convert_item(item).unwrap();
        assert_eq!(envelopes.len(), 1);
        let sent = &envelopes[0]["syncMessage"]["sentMessage"];
        assert_eq!(sent["destination"], json!("+49333"));
        assert_eq!(sent["message"], json!("hi me"));
        assert_eq!(sent["expiresInSeconds"], json!(60));
    }

    #[test]
    fn group_chat_items_carry_the_signal_cli_group_id() {
        let mut state = Converter::new(self_info());
        state.recipients.insert(3, Destination::Group([7u8; 32]));
        state.chats.insert(20, ChatEntry { recipient: 3, expiration_seconds: 0 });
        let group = state.group_json(3).unwrap();
        assert_eq!(group["type"], json!("DELIVER"));
        // Same derivation as crate::envelope::group_id for the same master key.
        let expected = crate::envelope::group_id(&[7u8; 32]).unwrap();
        assert_eq!(group["groupId"], json!(expected));
    }

    #[test]
    fn reactions_become_their_own_envelopes() {
        let mut state = Converter::new(self_info());
        state.recipients.insert(1, contact_recipient());
        state.recipients.insert(2, Destination::Self_);
        state.chats.insert(10, ChatEntry { recipient: 1, expiration_seconds: 0 });

        let item = ChatItem {
            chatId: 10,
            authorId: 1,
            dateSent: 1_700_000_000_000,
            directionalDetails: Some(chat_item::DirectionalDetails::Incoming(IncomingMessageDetails {
                dateReceived: 1_700_000_000_000,
                dateServerSent: None,
                read: false,
                sealedSender: false,
                ..Default::default()
            })),
            item: Some(chat_item::Item::StandardMessage(StandardMessage {
                reactions: vec![Reaction {
                    emoji: "👍".into(),
                    authorId: 2,
                    sentTimestamp: 1_700_000_100_000,
                    sortOrder: 1,
                    ..Default::default()
                }],
                ..Default::default()
            })),
            ..Default::default()
        };
        let envelopes = state.convert_item(item).unwrap();
        assert_eq!(envelopes.len(), 2); // the message, then the reaction
        let reaction = &envelopes[1];
        // A reaction by ourselves arrives like a live sent sync.
        assert!(reaction.get("syncMessage").is_some());
        let r = &reaction["syncMessage"]["sentMessage"]["reaction"];
        assert_eq!(r["emoji"], json!("👍"));
        assert_eq!(r["targetSentTimestamp"], json!(1_700_000_000_000i64));
        assert_eq!(r["targetAuthor"], json!("+49111"));
    }
}

#[cfg(test)]
mod archive_tests {
    use super::*;
    use libsignal_message_backup::proto::backup::{Chat, Text};
    use libsignal_message_backup::proto::backup::chat_item::IncomingMessageDetails;
    use protobuf::MessageField;

    /// One encrypted history archive exactly the way the phone builds it: varint-delimited
    /// protobuf frames, gzip-compressed, AES-256-CBC with a random IV prepended and an
    /// HMAC-SHA256 of IV || ciphertext appended.
    fn build_archive(ephemeral_key: [u8; 32], aci: &Aci) -> Vec<u8> {
        use aes::Aes256;
        use cbc::cipher::{BlockModeEncrypt as _, KeyIvInit as _, block_padding::Pkcs7};
        use flate2::write::GzEncoder;
        use flate2::Compression;
        use hmac::{KeyInit as _, Mac as _};
        use std::io::Write as _;

        let mut varint = |mut n: usize, out: &mut Vec<u8>| loop {
            let mut byte = (n & 0x7f) as u8;
            n >>= 7;
            if n != 0 {
                byte |= 0x80;
            }
            out.push(byte);
            if n == 0 {
                break;
            }
        };
        let info: Vec<u8> = BackupInfo { version: 1, ..Default::default() }.write_to_bytes().unwrap();
        let contact_frame: Vec<u8> = Frame {
            item: Some(frame::Item::Recipient(Recipient {
                id: 1,
                destination: Some(recipient::Destination::Contact(Contact {
                    aci: Some([0x11u8; 16].to_vec()),
                    e164: Some(49111),
                    profileGivenName: Some("Alice".into()),
                    ..Default::default()
                })),
                ..Default::default()
            })),
            ..Default::default()
        }
        .write_to_bytes()
        .unwrap();
        let chat_frame: Vec<u8> = Frame {
            item: Some(frame::Item::Chat(Chat { id: 10, recipientId: 1, ..Default::default() })),
            ..Default::default()
        }
        .write_to_bytes()
        .unwrap();
        let item_frame: Vec<u8> = Frame {
            item: Some(frame::Item::ChatItem(ChatItem {
                chatId: 10,
                authorId: 1,
                dateSent: 1_700_000_000_000,
                directionalDetails: Some(chat_item::DirectionalDetails::Incoming(
                    IncomingMessageDetails { dateReceived: 1_700_000_000_123, ..Default::default() },
                )),
                item: Some(chat_item::Item::StandardMessage(StandardMessage {
                    text: MessageField::some(Text { body: "hello from the archive".into(), ..Default::default() }),
                    ..Default::default()
                })),
                ..Default::default()
            })),
            ..Default::default()
        }
        .write_to_bytes()
        .unwrap();

        let mut frames = Vec::new();
        for item in [info, contact_frame, chat_frame, item_frame] {
            varint(item.len(), &mut frames);
            frames.extend_from_slice(&item);
        }

        let mut gz = GzEncoder::new(Vec::new(), Compression::default());
        gz.write_all(&frames).unwrap();
        let gz = gz.finish().unwrap();

        let key = message_backup_key(ephemeral_key, aci);
        let mut iv = [0u8; 16];
        rand::RngCore::fill_bytes(&mut rand::rng(), &mut iv);
        let mut enc = cbc::Encryptor::<Aes256>::new((&key.aes_key).into(), (&iv).into());
        let ciphertext = enc.encrypt_padded_vec::<Pkcs7>(&gz);

        let mut mac = hmac::Hmac::<sha2::Sha256>::new_from_slice(&key.hmac_key).unwrap();
        mac.update(&iv);
        mac.update(&ciphertext);
        let tag = mac.finalize().into_bytes().to_vec();

        let mut file = iv.to_vec();
        file.extend_from_slice(&ciphertext);
        file.extend_from_slice(&tag);
        file
    }

    #[tokio::test]
    async fn imports_a_real_encrypted_archive() {
        let ephemeral = [42u8; 32];
        let aci_uuid = Uuid::parse_str("33333333-3333-4333-8333-333333333333").unwrap();
        let aci = Aci::from_uuid_bytes(aci_uuid.into_bytes());
        let dir = std::env::temp_dir().join(format!("corvus-transfer-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();

        let archive = dir.join("archive.bin");
        std::fs::write(&archive, build_archive(ephemeral, &aci)).unwrap();

        let self_info = SelfInfo { aci: aci_uuid.to_string(), number: "+49333".into() };
        let mut progress_calls = Vec::new();
        let imported = import_frames(&archive, ephemeral, &aci, &self_info, &dir, &mut |n| progress_calls.push(n))
            .await
            .unwrap();
        assert_eq!(imported, Some(1));
        assert_eq!(progress_calls.last(), Some(&1));

        let history = std::fs::read_to_string(history_file(&dir)).unwrap();
        let envelope: Value = serde_json::from_str(history.trim()).unwrap();
        assert_eq!(envelope["source"], json!("+49111"));
        assert_eq!(envelope["sourceName"], json!("Alice"));
        assert_eq!(envelope["timestamp"], json!(1_700_000_000_000i64));
        assert_eq!(envelope["dataMessage"]["message"], json!("hello from the archive"));

        let meta: Value = serde_json::from_slice(&std::fs::read(meta_file(&dir)).unwrap()).unwrap();
        assert_eq!(meta["done"], json!(true));
        assert_eq!(meta["count"], json!(1));

        // A wrong key must fail the HMAC check, never yield plaintext.
        let bad = dir.join("bad.bin");
        std::fs::write(&bad, build_archive([7u8; 32], &aci)).unwrap();
        let result = import_frames(&bad, [99u8; 32], &aci, &self_info, &dir, &mut |_| {}).await;
        assert!(result.is_err());
        // The failed run must not have written importable state: remove the good run's files
        // and the failed run has nothing left to serve.
        std::fs::remove_file(history_file(&dir)).unwrap();
        std::fs::remove_file(meta_file(&dir)).unwrap();
        assert_eq!(import_available(&dir), None);

        std::fs::remove_dir_all(&dir).ok();
    }
}
