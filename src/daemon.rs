// The jsonRpc daemon: a receive loop that emits signal-cli "receive" notifications, and the
// methods corvus calls. Everything runs on one thread (presage's store futures are !Send).

use std::cell::RefCell;
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::prelude::*;
use futures::{pin_mut, StreamExt};
use presage::libsignal_service::content::{Content, ContentBody};
use presage::libsignal_service::prelude::{ProfileKey, Uuid};
use presage::libsignal_service::protocol::{
    Aci, DeviceId, IdentityKey, IdentityKeyStore, Pni, ProtocolAddress, ServiceId,
};
use presage::libsignal_service::sender::AttachmentSpec;
use presage::manager::Registered;
use presage::model::groups::Group;
use presage::model::messages::Received;
use presage::proto::data_message::{quote, Delete, Flags, Quote, Reaction, UnpinMessage, pin_message::PinDuration, PinMessage};
use presage::proto::data_message::{contact::{Avatar as ContactAvatar, Name as ContactName, Phone as ContactPhone}, Contact, PollCreate, PollTerminate, PollVote};
use presage::proto::receipt_message::Type as ReceiptType;
use presage::proto::sync_message::{Content as SyncContent, Read as SyncRead};
use presage::proto::typing_message::Action;
use presage::proto::{
    AttachmentPointer, DataMessage, EditMessage, GroupContextV2, Preview, ReceiptMessage, SyncMessage, TypingMessage,
};
use presage::store::{ContentsStore, Store};
use presage::Manager;
use presage_store_sqlite::SqliteStore;
use serde_json::{json, Value};
use tokio::sync::{mpsc, oneshot, Mutex};
use tracing::{debug, info, warn};

use crate::crypto::{self, Crypto};
use crate::envelope::{self, Directory, Person};
use crate::groupops::ExtrasCache;
use crate::groups;
use crate::identities::{self, Level, TrustStore};
use crate::rpc::{self, Params, RpcError, RpcResult};
use crate::store::{attachments_dir, e164, private_dir};
use crate::textstyle;

type Mgr = Manager<SqliteStore, Registered>;

/// A download the background worker should do (F4): the pointer and, for stickers, the file
/// name it is stored under.
type DownloadJob = (AttachmentPointer, Option<String>);

/// The bounds of automatic attachment downloading (F4), like the official clients: at most 32
/// attachments per message, at most 100 MiB each (larger declared sizes are skipped), and at
/// most 256 MiB per message. Every download has a timeout and the queue is bounded, so one
/// stranger cannot stall the receive loop or fill the disk.
const MAX_ATTACHMENTS_PER_MESSAGE: usize = 32;
const MAX_ATTACHMENT_BYTES: u64 = 100 * 1024 * 1024;
const MAX_ATTACHMENT_BYTES_PER_MESSAGE: u64 = 256 * 1024 * 1024;
const DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(60);
const DOWNLOAD_QUEUE_CAPACITY: usize = 128;
/// Pointers of messages from hidden (unaccepted) senders, kept for downloadAttachment. Corvus
/// accepts or dismisses the request; a dismissed one is superseded by newer messages.
const PENDING_POINTER_CACHE: usize = 200;

/// One stdout item. Incoming notifications carry a completion sender so the receive loop
/// waits until Corvus has actually received the complete JSON line before sending a receipt.
pub(crate) struct Output {
    pub(crate) value: Value,
    pub(crate) written: Option<oneshot::Sender<Result<(), String>>>,
}

impl Output {
    pub(crate) fn queued(value: Value) -> Self {
        Self { value, written: None }
    }
}

/// A receipt waiting to be coalesced and sent. RPC callers wait for the actual send result;
/// automatic delivery receipts have no caller.
struct ReceiptRequest {
    recipient: ServiceId,
    kind: i32,
    timestamps: Vec<u64>,
    response: Option<oneshot::Sender<RpcResult>>,
}

#[derive(Default)]
struct TypingState {
    active: bool,
    last_sent: Option<tokio::time::Instant>,
}

pub struct Daemon {
    pub(crate) manager: Mgr,
    out: mpsc::UnboundedSender<Output>,
    pub(crate) attachments: PathBuf,
    /// The account directory: history transferred from the phone while linking is served from
    /// here (listHistoryImport / fetchHistoryImport / clearHistoryImport).
    account_dir: PathBuf,
    /// Present when a secret unlocked the data: attachments are written encrypted (and read
    /// encrypted, plain files of an older version still read).
    pub(crate) crypto: Option<Crypto>,
    pub(crate) account: String,
    pub(crate) self_aci: Uuid,
    pub(crate) dir: RefCell<Directory>,
    /// group id (signal-cli base64) -> master key
    group_keys: RefCell<HashMap<String, [u8; 32]>>,
    trust: RefCell<TrustStore>,
    pub(crate) group_extras: RefCell<ExtrasCache>,
    pub(crate) storage_state: RefCell<crate::storage::State>,
    /// Sends are serialised: concurrent sends to one recipient would race on its session state.
    pub(crate) send_lock: Mutex<()>,
    /// All outgoing receipts share one queue so read, viewed and delivery receipts can be batched.
    receipt_tx: mpsc::UnboundedSender<ReceiptRequest>,
    receipt_rx: RefCell<Option<mpsc::UnboundedReceiver<ReceiptRequest>>>,
    /// Recent successful receipts, keyed by recipient and type, to avoid resending timestamps.
    receipt_history: RefCell<HashMap<(String, i32), VecDeque<u64>>>,
    /// Enforce a minimum gap and a global server-imposed cooldown for every outbound request.
    outbound_last_send: RefCell<Option<tokio::time::Instant>>,
    outbound_blocked_until: RefCell<Option<tokio::time::Instant>>,
    /// Coalesce repeated typing notifications by conversation.
    typing_state: RefCell<HashMap<String, TypingState>>,
    /// Next allowed session-reset attempt per sender (Unix milliseconds).
    decryption_reset_retry_at: RefCell<HashMap<Uuid, u64>>,
    /// Sticker pack downloads are serialised: every storage change triggers a sync, and two of
    /// them would download the same packs twice.
    pub(crate) pack_sync: Mutex<()>,
    /// Which stored attachment files belong to which message, so remote deletes can remove
    /// them (security review F1).
    attachment_index: RefCell<AttachmentIndex>,
    /// Attachment downloads deferred out of the receive loop (F4): bounded queue, one download
    /// at a time, a timeout each, and Corvus is notified when a file is ready.
    download_tx: mpsc::Sender<DownloadJob>,
    download_rx: RefCell<Option<mpsc::Receiver<DownloadJob>>>,
    /// Pointers of messages from hidden (unaccepted) senders (F4): nothing is downloaded for
    /// them automatically; Corvus calls downloadAttachment once the request is accepted.
    pending_pointers: RefCell<VecDeque<(String, AttachmentPointer, Option<String>)>>,
    /// The transferred history's JSONL lines, read once and cached for pagination: a replay
    /// fetches the file page by page, and re-reading (and re-scanning) the whole file per
    /// page made large imports noticeably slower than the official client.
    history_lines: RefCell<Option<Vec<String>>>,
}

pub(crate) enum Target {
    Contact(ServiceId),
    Group([u8; 32]),
}

pub(crate) fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

impl Daemon {
    pub async fn new(
        manager: Mgr,
        account_dir: &Path,
        out: mpsc::UnboundedSender<Output>,
        crypto: Option<Crypto>,
    ) -> anyhow::Result<Rc<Self>> {
        // corvus decides about link previews itself and passes them with `send` (previewUrl …);
        // presage would otherwise fetch every linked page, revealing the user's IP address to it.
        manager.set_automatic_link_previews(false);
        let data = manager.registration_data();
        let account = e164(&data.phone_number);
        let self_aci = Uuid::from(data.service_ids.aci());
        let attachments = attachments_dir(account_dir);
        private_dir(&attachments)?;
        let attachment_index = AttachmentIndex::load(account_dir, crypto.as_ref());
        // Fail closed (L1): a trust store that cannot be opened (replaced, corrupt, wrong
        // secret) stops the run instead of accepting every key again as unverified.
        let trust = TrustStore::load(account_dir, crypto.clone())?;
        let (receipt_tx, receipt_rx) = mpsc::unbounded_channel();
        let (download_tx, download_rx) = mpsc::channel(DOWNLOAD_QUEUE_CAPACITY);
        let daemon = Rc::new(Self {
            manager,
            out,
            trust: RefCell::new(trust),
            group_extras: Default::default(),
            storage_state: Default::default(),
            attachments,
            account_dir: account_dir.to_path_buf(),
            crypto,
            account,
            self_aci,
            dir: Default::default(),
            group_keys: Default::default(),
            send_lock: Mutex::new(()),
            receipt_tx,
            receipt_rx: RefCell::new(Some(receipt_rx)),
            receipt_history: Default::default(),
            outbound_last_send: Default::default(),
            outbound_blocked_until: Default::default(),
            typing_state: Default::default(),
            decryption_reset_retry_at: Default::default(),
            pack_sync: Mutex::new(()),
            attachment_index: RefCell::new(attachment_index),
            download_tx,
            download_rx: RefCell::new(Some(download_rx)),
            pending_pointers: Default::default(),
            history_lines: Default::default(),
        });
        daemon.reload_directory().await;
        daemon.reload_groups().await;
        // presage stored every message it ever handled; Corvus keeps the history, so the
        // store's copy goes now (F1), and with it the attachments no one cleaned up.
        daemon.purge_messages().await;
        daemon.sweep_old_attachments().await;
        rename_legacy_sticker_files(&daemon.attachments, daemon.crypto.as_ref()).await;
        Ok(daemon)
    }

    /// Starts the single receipt sender on the local task set.
    pub(crate) fn start_receipt_worker(self: &Rc<Self>) {
        let Some(receiver) = self.receipt_rx.borrow_mut().take() else { return };
        let daemon = Rc::clone(self);
        tokio::task::spawn_local(async move {
            daemon.receipt_worker(receiver).await;
        });
    }

    /// Starts the single attachment download worker on the local task set (F4).
    pub(crate) fn start_download_worker(self: &Rc<Self>) {
        let Some(receiver) = self.download_rx.borrow_mut().take() else { return };
        let daemon = Rc::clone(self);
        tokio::task::spawn_local(async move {
            daemon.download_worker(receiver).await;
        });
    }

    /// Downloads what the queue holds, one at a time, each with a timeout (F4). A file that is
    /// ready is reported to Corvus, which may have shown the message before it existed; older
    /// Corvus versions ignore the notification method and fetch lazily as before.
    async fn download_worker(self: Rc<Self>, mut receiver: mpsc::Receiver<DownloadJob>) {
        while let Some((pointer, name)) = receiver.recv().await {
            let _ = tokio::time::timeout(DOWNLOAD_TIMEOUT, self.download(&pointer, name.clone())).await;
            let id = name.or_else(|| envelope::attachment_id(&pointer));
            if let Some(id) = id.filter(|id| self.attachments.join(id).exists()) {
                let _ = self
                    .emit(rpc::notification("attachmentDownloaded", json!({"id": id, "account": self.account})))
                    .await;
            }
        }
    }

    /// Hands a download to the background worker. A full queue means a flood: the file is
    /// skipped instead of piling up unbounded work (F4).
    fn queue_download(&self, pointer: &AttachmentPointer, name: Option<String>) {
        if self.download_tx.try_send((pointer.clone(), name)).is_err() {
            debug!("attachment download queue is full; not downloading");
        }
    }

    /// Collects nearby receipts, combines timestamps per recipient/type, and sends them serially.
    async fn receipt_worker(self: Rc<Self>, mut receiver: mpsc::UnboundedReceiver<ReceiptRequest>) {
        let mut last_send: Option<tokio::time::Instant> = None;
        let mut pending = Vec::new();

        loop {
            if pending.is_empty() {
                match receiver.recv().await {
                    Some(request) => pending.push(request),
                    None => break,
                }
            }

            // Corvus often submits one read receipt per message. A short collection window turns
            // those calls into one Signal receipt with multiple timestamps.
            let collect = tokio::time::sleep(Duration::from_millis(250));
            pin_mut!(collect);
            loop {
                tokio::select! {
                    _ = &mut collect => break,
                    request = receiver.recv() => match request {
                        Some(request) => pending.push(request),
                        None => break,
                    }
                }
            }

            let mut groups: Vec<Vec<ReceiptRequest>> = Vec::new();
            for request in pending.drain(..) {
                let recipient = request.recipient.service_id_string();
                if let Some(group) = groups.iter_mut().find(|group| {
                    group[0].kind == request.kind
                        && group[0].recipient.service_id_string() == recipient
                }) {
                    group.push(request);
                } else {
                    groups.push(vec![request]);
                }
            }

            for mut group in groups {
                let recipient = group[0].recipient.clone();
                let kind = group[0].kind;
                let key = (recipient.service_id_string(), kind);
                let mut timestamps: Vec<u64> = group.iter().flat_map(|r| r.timestamps.iter().copied()).collect();
                timestamps.sort_unstable();
                timestamps.dedup();

                // A timestamp already accepted by Signal does not need another receipt.
                if let Some(sent) = self.receipt_history.borrow().get(&key) {
                    timestamps.retain(|timestamp| !sent.contains(timestamp));
                }

                if timestamps.is_empty() {
                    let result = self.receipt_success_result(&recipient);
                    for request in group {
                        if let Some(response) = request.response {
                            let _ = response.send(Ok(result.clone()));
                        }
                    }
                    continue;
                }

                loop {
                    // Smooth bursts across recipients as well as coalescing same-recipient calls.
                    if let Some(last) = last_send {
                        let next = last + Duration::from_millis(500);
                        tokio::time::sleep_until(next).await;
                    }

                    let receipt = ReceiptMessage { r#type: Some(kind), timestamp: timestamps.clone() };
                    let result = self
                        .send_to(&[Target::Contact(recipient.clone())], ContentBody::ReceiptMessage(receipt), now_ms())
                        .await;
                    last_send = Some(tokio::time::Instant::now());

                    match result {
                        Ok(result) => {
                            let mut history = self.receipt_history.borrow_mut();
                            let sent = history.entry(key.clone()).or_default();
                            for timestamp in &timestamps {
                                if !sent.contains(timestamp) {
                                    sent.push_back(*timestamp);
                                }
                            }
                            while sent.len() > 2048 {
                                sent.pop_front();
                            }
                            drop(history);

                            for request in group {
                                if let Some(response) = request.response {
                                    let _ = response.send(Ok(result.clone()));
                                }
                            }
                            break;
                        }
                        Err(error) if is_signal_rate_limit(&error.message) => {
                            let delay = signal_retry_after(&error.message)
                                .unwrap_or(Duration::from_secs(600))
                                .saturating_add(Duration::from_secs(1));
                            debug!(
                                recipient = %recipient.service_id_string(),
                                retry_after_seconds = delay.as_secs(),
                                "Signal rate-limited receipts; keeping them queued"
                            );
                            tokio::time::sleep(delay).await;
                            // Keep the timestamps and retry after Signal's stated cooldown.
                        }
                        Err(error) => {
                            warn!(
                                recipient = %recipient.service_id_string(),
                                error = %error.message,
                                "cannot send queued Signal receipts"
                            );
                            for request in group {
                                if let Some(response) = request.response {
                                    let _ = response.send(Err(RpcError::failed(error.message.clone())));
                                }
                            }
                            break;
                        }
                    }
                }
            }
        }
    }

    fn receipt_success_result(&self, recipient: &ServiceId) -> Value {
        json!({
            "timestamp": now_ms(),
            "results": [{"recipientAddress": self.address_json(recipient), "type": "SUCCESS"}]
        })
    }

    async fn queue_receipt(&self, recipient: ServiceId, kind: i32, timestamps: Vec<u64>) -> RpcResult {
        let (response, result) = oneshot::channel();
        self.receipt_tx
            .send(ReceiptRequest { recipient, kind, timestamps, response: Some(response) })
            .map_err(|_| RpcError::failed("receipt queue is unavailable"))?;
        result.await.map_err(|_| RpcError::failed("receipt worker stopped"))?
    }

    pub(crate) fn queue_delivery_receipt(&self, recipient: ServiceId, timestamp: u64) {
        if self
            .receipt_tx
            .send(ReceiptRequest {
                recipient,
                kind: ReceiptType::Delivery as i32,
                timestamps: vec![timestamp],
                response: None,
            })
            .is_err()
        {
            debug!("receipt queue is unavailable; cannot queue delivery receipt");
        }
    }

    /// How long Signal's global outbound cooldown still has to run, if any.
    fn outbound_cooldown_remaining(&self) -> Option<Duration> {
        let now = tokio::time::Instant::now();
        let until = *self.outbound_blocked_until.borrow();
        until.and_then(|until| (until > now).then_some(until - now))
    }

    /// Fail locally while Signal has an active cooldown; otherwise space outbound requests.
    async fn wait_for_outbound_slot(&self) -> Result<(), RpcError> {
        if let Some(remaining) = self.outbound_cooldown_remaining() {
            let seconds = remaining.as_secs().saturating_add(if remaining.subsec_nanos() > 0 { 1 } else { 0 });
            return Err(RpcError::failed(format!(
                "Rate limit exceeded: retry after PT{seconds}S (locally paused; no request sent)"
            )));
        }

        let last_send = *self.outbound_last_send.borrow();
        if let Some(last) = last_send {
            let next = last + Duration::from_secs(1);
            if next > tokio::time::Instant::now() {
                tokio::time::sleep_until(next).await;
            }
        }
        Ok(())
    }

    /// Remember that a request went out and install a process-wide cooldown on a server limit.
    fn record_outbound_result(&self, error: Option<&str>) {
        let now = tokio::time::Instant::now();
        *self.outbound_last_send.borrow_mut() = Some(now);
        let Some(message) = error.filter(|message| is_signal_rate_limit(message)) else { return };

        let delay = signal_retry_after(message)
            .unwrap_or(Duration::from_secs(600))
            .saturating_add(Duration::from_secs(1));
        let until = now + delay;
        let mut blocked_until = self.outbound_blocked_until.borrow_mut();
        if blocked_until.is_none_or(|current| current < until) {
            *blocked_until = Some(until);
        }
        warn!(
            retry_after_seconds = delay.as_secs(),
            "Signal rate-limited an outbound request; pausing all outbound sends"
        );
    }

    /// Return true only for a useful typing state transition or a periodic refresh.
    fn should_send_typing(&self, key: String, started: bool) -> bool {
        const REFRESH_INTERVAL: Duration = Duration::from_secs(8);
        let now = tokio::time::Instant::now();
        let mut states = self.typing_state.borrow_mut();
        let state = states.entry(key).or_default();
        if started {
            if state.active
                && state.last_sent.is_some_and(|last| now.duration_since(last) < REFRESH_INTERVAL)
            {
                return false;
            }
            state.active = true;
            state.last_sent = Some(now);
            true
        } else if state.active {
            state.active = false;
            state.last_sent = Some(now);
            true
        } else {
            false
        }
    }

    pub(crate) fn store(&self) -> &SqliteStore {
        self.manager.store()
    }

    // ---- people and groups ----------------------------------------------------------------

    pub(crate) async fn profile_name(&self, uuid: Uuid) -> Option<String> {
        let key = self.store().profile_key(&ServiceId::Aci(uuid.into())).await.ok()??;
        let profile = self.store().profile(uuid, key).await.ok()??;
        let name = profile.name?;
        let full = match name.family_name {
            Some(family) if !family.is_empty() => format!("{} {}", name.given_name, family),
            _ => name.given_name,
        };
        (!full.trim().is_empty()).then_some(full)
    }

    /// Refreshes the people from the contacts; people known otherwise (who wrote, group members)
    /// are kept.
    pub(crate) async fn reload_directory(&self) {
        let mut people = self.dir.borrow().people.clone();
        match self.store().contacts().await {
            Ok(contacts) => {
                for contact in contacts.flatten() {
                    people.insert(
                        contact.uuid,
                        Person {
                            number: contact.phone_number.as_ref().map(e164),
                            name: (!contact.name.is_empty()).then(|| contact.name.clone()),
                        },
                    );
                }
            }
            Err(e) => warn!(%e, "cannot read contacts"),
        }
        for (uuid, person) in people.iter_mut() {
            if person.name.is_none() {
                person.name = self.profile_name(*uuid).await;
            }
        }
        // Group members (and others with a fetched profile) get their profile names too.
        if let Ok(groups) = self.groups().await {
            for (_, group) in groups {
                for member in group.members {
                    let uuid = Uuid::from(member.aci);
                    if !people.contains_key(&uuid) {
                        let name = self.profile_name(uuid).await;
                        people.insert(uuid, Person { number: None, name });
                    }
                }
            }
        }
        people.insert(self.self_aci, Person { number: Some(self.account.clone()), name: None });
        self.dir.borrow_mut().people = people;
    }

    /// Makes sure a sender we have not seen before gets a name (profile fetched over the network once).
    async fn ensure_person(&self, uuid: Uuid) {
        if self.dir.borrow().people.contains_key(&uuid) {
            return;
        }
        let mut name = self.profile_name(uuid).await;
        if name.is_none() {
            if let Ok(Some(key)) = self.store().profile_key(&ServiceId::Aci(uuid.into())).await {
                let mut m = self.manager.clone();
                if let Ok(profile) = m.retrieve_profile_by_uuid(uuid, key).await {
                    name = profile.name.map(|n| n.given_name);
                }
            }
        }
        self.dir.borrow_mut().people.insert(uuid, Person { number: None, name });
    }

    pub(crate) async fn groups(&self) -> Result<Vec<([u8; 32], Group)>, RpcError> {
        Ok(self.store().groups().await?.flatten().collect())
    }

    /// Known from the contacts or from the storage service (F4). Hidden requests are handled
    /// by the caller; group members by the group check.
    async fn known_sender(&self, sender: Uuid) -> bool {
        if self.storage_state.borrow().people.contains_key(&sender) {
            return true;
        }
        let Ok(contacts) = self.store().contacts().await else { return false };
        contacts.flatten().any(|c| c.uuid == sender)
    }

    pub(crate) async fn reload_groups(&self) {
        let Ok(groups) = self.groups().await else { return };
        let mut keys = self.group_keys.borrow_mut();
        keys.clear();
        for (key, _) in groups {
            if let Some(id) = envelope::group_id(&key) {
                keys.insert(id, key);
            }
        }
    }

    pub(crate) async fn group_key(&self, id: &str) -> Result<[u8; 32], RpcError> {
        if let Some(key) = self.group_keys.borrow().get(id) {
            return Ok(*key);
        }
        self.reload_groups().await;
        self.group_keys.borrow().get(id).copied().ok_or_else(|| RpcError::failed(format!("Unknown group {id}")))
    }

    pub(crate) async fn group_context(&self, key: [u8; 32]) -> GroupContextV2 {
        let revision = self.store().group(key).await.ok().flatten().map(|g| g.revision);
        GroupContextV2 { master_key: Some(key.to_vec()), revision: Some(revision.unwrap_or(0)), group_change: None }
    }

    /// A known phone number, an ACI uuid, or "PNI:<uuid>"; nothing is looked up.
    pub(crate) fn resolve_local(&self, who: &str) -> Result<ServiceId, RpcError> {
        if who.starts_with('+') {
            let dir = self.dir.borrow();
            return dir
                .people
                .iter()
                .find(|(_, p)| p.number.as_deref() == Some(who))
                .map(|(uuid, _)| ServiceId::Aci(Aci::from(*uuid)))
                .ok_or_else(|| RpcError::failed(format!("Unknown recipient {who}")));
        }
        if let Some(pni) = who.strip_prefix("PNI:") {
            let uuid = Uuid::parse_str(pni).map_err(|_| RpcError::invalid(format!("invalid recipient '{who}'")))?;
            return Ok(ServiceId::Pni(Pni::from(uuid)));
        }
        let uuid = Uuid::parse_str(who).map_err(|_| RpcError::invalid(format!("invalid recipient '{who}'")))?;
        Ok(ServiceId::Aci(Aci::from(uuid)))
    }

    /// Like signal-cli: also a phone number nobody synced (contact discovery) or a username
    /// ("name.42"). What is found is remembered.
    pub(crate) async fn resolve(&self, who: &str) -> Result<ServiceId, RpcError> {
        if let Ok(sid) = self.resolve_local(who) {
            return Ok(sid);
        }
        let mut m = self.manager.clone();
        if who.starts_with('+') {
            let found = m.discover_contacts_by_phone_number([who]).await?;
            let Some(sid) = found.into_iter().find_map(|(_, sid)| sid) else {
                return Err(RpcError::failed(format!("Unregistered user \"{who}\"")));
            };
            self.dir.borrow_mut().people.entry(sid.raw_uuid()).or_default().number = Some(who.to_owned());
            return Ok(sid);
        }
        if who.contains('.') {
            let Some(aci) = m.lookup_username(who).await? else {
                return Err(RpcError::failed(format!("Username {who} not found")));
            };
            self.dir.borrow_mut().people.entry(Uuid::from(aci)).or_default();
            return Ok(ServiceId::Aci(aci));
        }
        Err(RpcError::invalid(format!("invalid recipient '{who}'")))
    }

    pub(crate) async fn resolve_aci(&self, who: &str) -> Result<Uuid, RpcError> {
        match self.resolve(who).await? {
            ServiceId::Aci(aci) => Ok(aci.into()),
            ServiceId::Pni(_) => Err(RpcError::invalid(format!("'{who}' is not an ACI"))),
        }
    }

    /// signal-cli's targets: "recipient"/"recipients" and "groupId"/"groupIds".
    pub(crate) async fn targets(&self, p: &Params) -> Result<Vec<Target>, RpcError> {
        let mut out = Vec::new();
        for who in p.strings("recipient").into_iter().chain(p.strings("recipients")) {
            out.push(Target::Contact(self.resolve(&who).await?));
        }
        for id in p.strings("groupId").into_iter().chain(p.strings("groupIds")) {
            out.push(Target::Group(self.group_key(&id).await?));
        }
        if out.is_empty() {
            return Err(RpcError::invalid("no recipient or group given"));
        }
        Ok(out)
    }

    pub(crate) fn address_json(&self, sid: &ServiceId) -> Value {
        let uuid = sid.raw_uuid();
        json!({"uuid": uuid.to_string(), "number": self.dir.borrow().get(&uuid).number})
    }

    /// Sends one body to every target. Group messages get the group context set here.
    pub(crate) async fn send_to(&self, targets: &[Target], body: ContentBody, timestamp: u64) -> RpcResult {
        let _guard = self.send_lock.lock().await;
        let mut results = Vec::new();
        for target in targets {
            let mut m = self.manager.clone();
            match target {
                Target::Contact(sid) => {
                    // Like signal-cli: nothing goes to a changed key the user has not accepted.
                    if self.trust_level(sid.raw_uuid()).await.map(|t| t.1) == Some(Level::Untrusted) {
                        let who = self.dir.borrow().get(&sid.raw_uuid()).number.unwrap_or_else(|| sid.raw_uuid().to_string());
                        return Err(RpcError::failed(identities::untrusted_error(&who)));
                    }
                    self.wait_for_outbound_slot().await?;
                    let send_result = m.send_message(*sid, body.clone(), timestamp).await;
                    let error_message = send_result.as_ref().err().map(ToString::to_string);
                    self.record_outbound_result(error_message.as_deref());
                    send_result?;
                    results.push(json!({"recipientAddress": self.address_json(sid), "type": "SUCCESS"}));
                }
                Target::Group(key) => {
                    let mut body = body.clone();
                    let ctx = self.group_context(*key).await;
                    match &mut body {
                        ContentBody::DataMessage(dm) => dm.group_v2 = Some(ctx),
                        ContentBody::EditMessage(EditMessage { data_message: Some(dm), .. }) => dm.group_v2 = Some(ctx),
                        _ => {}
                    }
                    // Members with an unaccepted key are left out and reported, as signal-cli does.
                    let members: Vec<Aci> = match self.store().group(*key).await? {
                        Some(group) => group.members.iter().map(|m| m.aci).filter(|a| Uuid::from(*a) != self.self_aci).collect(),
                        None => Vec::new(),
                    };
                    let mut untrusted = Vec::new();
                    for aci in &members {
                        if self.trust_level(Uuid::from(*aci)).await.map(|t| t.1) == Some(Level::Untrusted) {
                            untrusted.push(*aci);
                        }
                    }
                    self.wait_for_outbound_slot().await?;
                    let send_result = m.send_message_to_group_except(key, body, timestamp, &untrusted).await;
                    let error_message = send_result.as_ref().err().map(ToString::to_string);
                    self.record_outbound_result(error_message.as_deref());
                    send_result?;
                    for aci in members {
                        let sid = ServiceId::Aci(aci);
                        let kind = if untrusted.contains(&aci) { "IDENTITY_FAILURE" } else { "SUCCESS" };
                        results.push(json!({"recipientAddress": self.address_json(&sid), "type": kind}));
                    }
                }
            }
        }
        // presage stored a sent transcript for every send; it must not linger either (F1).
        self.purge_messages().await;
        Ok(json!({"timestamp": timestamp, "results": results}))
    }

    // ---- identities ------------------------------------------------------------------------

    async fn identity_key(&self, uuid: Uuid) -> Option<IdentityKey> {
        let address = ProtocolAddress::new(uuid.to_string(), DeviceId::new(1).ok()?);
        self.store().aci_protocol_store().get_identity(&address).await.ok().flatten()
    }

    /// The current key of `uuid` with its trust level and since when (None: no session yet).
    async fn trust_level(&self, uuid: Uuid) -> Option<(IdentityKey, Level, u64)> {
        let key = self.identity_key(uuid).await?;
        let (level, added) = self.trust.borrow_mut().level(uuid, &key.serialize(), now_ms());
        Some((key, level, added))
    }

    async fn identity_json(&self, uuid: Uuid) -> Option<Value> {
        let (key, level, added) = self.trust_level(uuid).await?;
        let own = self.store().aci_protocol_store().get_identity_key_pair().await.ok()?;
        let number = identities::safety_number(self.self_aci, own.identity_key(), uuid, &key)?;
        Some(json!({
            "number": self.dir.borrow().get(&uuid).number,
            "uuid": uuid.to_string(),
            "fingerprint": identities::hex(&key.serialize()),
            "safetyNumber": number.display,
            "scannableSafetyNumber": number.scannable,
            "trustLevel": level.as_str(),
            "addedTimestamp": added,
        }))
    }

    async fn list_identities(&self, p: &Params) -> RpcResult {
        let uuids: Vec<Uuid> = match p.str("number") {
            Some(who) => vec![self.resolve(who).await?.raw_uuid()],
            None => {
                let mut all: Vec<Uuid> = self.dir.borrow().people.keys().copied().collect();
                for (_, group) in self.groups().await? {
                    all.extend(group.members.iter().map(|m| Uuid::from(m.aci)));
                }
                all.sort();
                all.dedup();
                all
            }
        };
        let mut out = Vec::new();
        for uuid in uuids.into_iter().filter(|u| *u != self.self_aci) {
            if let Some(identity) = self.identity_json(uuid).await {
                out.push(identity);
            }
        }
        Ok(Value::Array(out))
    }

    async fn trust(&self, p: &Params) -> RpcResult {
        let uuid = self.resolve_aci(p.required_str("recipient")?).await?;
        let Some((key, _, _)) = self.trust_level(uuid).await else {
            return Err(RpcError::failed("No identity known for this recipient"));
        };
        if p.bool("trustAllKnownKeys") {
            self.trust.borrow_mut().accept(uuid, &key.serialize(), Level::TrustedUnverified, now_ms());
            return Ok(json!({}));
        }
        let given = identities::digits(p.required_str("verifiedSafetyNumber")?);
        let own = self.store().aci_protocol_store().get_identity_key_pair().await?;
        let actual = identities::safety_number(self.self_aci, own.identity_key(), uuid, &key)
            .map(|n| identities::digits(&n.display))
            .unwrap_or_default();
        if given.is_empty() || given != actual {
            return Err(RpcError::failed("Failed to verify safety number"));
        }
        self.trust.borrow_mut().accept(uuid, &key.serialize(), Level::TrustedVerified, now_ms());
        Ok(json!({}))
    }

    // ---- receiving -------------------------------------------------------------------------

    pub async fn receive_loop(self: Rc<Self>) {
        let mut delay = Duration::from_secs(1);
        let mut requested_contacts = false;
        loop {
            let mut m = self.manager.clone();
            match m.receive_messages().await {
                Ok(messages) => {
                    pin_mut!(messages);
                    while let Some(item) = messages.next().await {
                        delay = Duration::from_secs(1);
                        match item {
                            Received::QueueEmpty => {
                                debug!("message queue drained");
                                let no_contacts = self.store().contacts().await.map(|c| c.count() == 0).unwrap_or(false);
                                if !requested_contacts && no_contacts {
                                    // Fresh link: ask the primary device for its contacts.
                                    requested_contacts = true;
                                    if let Err(e) = self.manager.clone().request_contacts().await {
                                        warn!(%e, "cannot request contacts");
                                    }
                                }
                            }
                            Received::Contacts => {
                                info!("contacts synchronised");
                                self.reload_directory().await;
                                self.clone().refresh_storage().await;
                            }
                            Received::DecryptionError(sender) => {
                                // Some undecryptable envelopes can coexist with successfully
                                // delivered messages. Keep this diagnostic out of Corvus'
                                // user-facing warning area; a failed recovery is still warned
                                // about by recover_decryption_error().
                                debug!(sender = %sender.service_id_string(), "cannot decrypt an incoming envelope; attempting session recovery");
                                self.recover_decryption_error(sender).await;
                            }
                            Received::Content(content) => {
                                if self.clone().handle_content(&content).await {
                                    self.clone().acknowledge(&content);
                                }
                            }
                        }
                    }
                    warn!("message stream ended, reconnecting");
                }
                Err(e) => warn!(%e, "cannot open message stream"),
            }
            tokio::time::sleep(delay).await;
            delay = (delay * 2).min(Duration::from_secs(60));
        }
    }

    /// Recover the pairwise session after a trusted sealed-sender envelope failed to decrypt.
    /// This is Signal's automatic-session-reset fallback when a resend request cannot be used.
    async fn recover_decryption_error(&self, sender: ServiceId) {
        let ServiceId::Aci(aci) = sender else { return };
        let uuid = Uuid::from(aci);
        let timestamp = now_ms();
        const COOLDOWN_MS: u64 = 60_000;

        {
            let mut retry_at = self.decryption_reset_retry_at.borrow_mut();
            if retry_at.get(&uuid).is_some_and(|until| timestamp < *until) {
                debug!(sender = %sender.service_id_string(), "session reset is cooling down after a decryption error");
                return;
            }
            retry_at.insert(uuid, timestamp.saturating_add(COOLDOWN_MS));
        }

        let _guard = self.send_lock.lock().await;
        if let Some(remaining) = self.outbound_cooldown_remaining() {
            let retry_ms = remaining.as_millis().min(u64::MAX as u128) as u64;
            self.decryption_reset_retry_at
                .borrow_mut()
                .insert(uuid, timestamp.saturating_add(retry_ms));
            debug!(
                sender = %sender.service_id_string(),
                retry_after_seconds = remaining.as_secs(),
                "skipping session reset while Signal outbound sending is rate-limited"
            );
            return;
        }
        if self.wait_for_outbound_slot().await.is_err() {
            return;
        }

        let mut manager = self.manager.clone();
        let reset_result = manager.send_session_reset(&sender, timestamp).await;
        let error_message = reset_result.as_ref().err().map(ToString::to_string);
        self.record_outbound_result(error_message.as_deref());
        match reset_result {
            Ok(()) => info!(sender = %sender.service_id_string(), "requested a fresh Signal session after a decryption error"),
            Err(error) => {
                let message = error.to_string();
                let delay = session_reset_backoff(&message);
                let retry_ms = delay.as_millis().min(u64::MAX as u128) as u64;
                self.decryption_reset_retry_at
                    .borrow_mut()
                    .insert(uuid, now_ms().saturating_add(retry_ms));
                warn!(
                    %error,
                    sender = %sender.service_id_string(),
                    retry_after_seconds = delay.as_secs(),
                    "could not reset the Signal session after a decryption error; retry is delayed"
                );
            }
        }
    }

    /// Announces a received message; false if it was ignored or could not be forwarded to Corvus.
    async fn handle_content(self: Rc<Self>, content: &Content) -> bool {
        let sender = content.metadata.sender.raw_uuid();
        if sender == self.self_aci {
            // The phone changed the storage service (blocked someone, archived a chat, …).
            if let ContentBody::SynchronizeMessage(sync) = &content.body {
                if matches!(sync.content, Some(SyncContent::FetchLatest(_))) {
                    self.refresh_storage().await;
                    return false;
                }
            }
        } else if self.is_blocked(sender) || self.group_of(&content.body).is_some_and(|k| self.is_group_blocked(&k)) {
            // Like signal-cli: messages from blocked people and groups are ignored.
            debug!("ignoring a message from a blocked contact or group");
            return false;
        } else if !self.group_message_allowed(sender, &content.body).await {
            // Like signal-cli and the official clients: a group message is only shown when the
            // sender is a member of the group it names (F3). Everything in the group context is
            // sender-controlled, and the master key leaks with every invite link — without this
            // check, a removed member could keep posting into the group as far as Corvus sees.
            debug!(sender = %sender, "dropping a group message from someone who is not in the group");
            return false;
        }
        self.ensure_person(sender).await;
        // Trust on first use: the first key is remembered as unverified; a changed one stays
        // untrusted until the user accepts it (L6).
        let untrusted_identity =
            sender != self.self_aci && self.trust_level(sender).await.map(|t| t.1) == Some(Level::Untrusted);
        let mut pointers = Vec::new();
        match &content.body {
            ContentBody::DataMessage(dm) => {
                collect_pointers(dm, &mut pointers);
                if dm.group_v2.is_some() {
                    self.reload_groups().await;
                }
            }
            ContentBody::EditMessage(EditMessage { data_message: Some(dm), .. }) => collect_pointers(dm, &mut pointers),
            ContentBody::SynchronizeMessage(sync) => {
                if let Some(SyncContent::Sent(sent)) = &sync.content {
                    if let Some(dm) = &sent.message {
                        collect_pointers(dm, &mut pointers);
                    }
                    if let Some(EditMessage { data_message: Some(dm), .. }) = &sent.edit_message {
                        collect_pointers(dm, &mut pointers);
                    }
                }
            }
            _ => {}
        }
        // The message is announced before its attachments are downloaded (F4): a stranger
        // cannot stall the receive loop with big files, and Corvus sees the message right
        // away. The background worker (bounded queue, timeout each) notifies Corvus when a
        // file is ready.
        let stickers = sticker_pointers(&content.body);
        // The ids the index keeps for remote deletes (F1): the names everything is stored under.
        let mut ids: Vec<String> = pointers.iter().filter_map(envelope::attachment_id).collect();
        ids.extend(stickers.iter().map(|(_, name)| name.clone()));
        let pointers = filtered_for_download(&pointers);
        // Downloaded automatically only for accepted senders (F4): self, full members of the
        // group the message names, and known senders. Everyone else is a message request — a
        // first-time sender is not in the hidden set, so the old hidden-only gate still
        // downloaded whatever they sent.
        let in_group = match self.group_of(&content.body) {
            Some(key) => matches!(self.store().group(key).await, Ok(Some(group)) if group.is_member(&Aci::from(sender))),
            None => false,
        };
        let hidden = sender != self.self_aci && self.storage_state.borrow().hidden.contains(&sender);
        let known = self.known_sender(sender).await;
        if downloads_automatically(sender, self.self_aci, in_group, known, hidden) {
            for pointer in &pointers {
                self.queue_download(pointer, None);
            }
            for (pointer, name) in &stickers {
                self.queue_download(pointer, Some(name.clone()));
            }
        } else {
            // A message request is never downloaded automatically (F4): nothing is fetched
            // until Corvus accepts it and calls downloadAttachment. The pointers are kept
            // (bounded) so that call can still fetch them.
            let mut pending = self.pending_pointers.borrow_mut();
            for (pointer, name) in pointers.into_iter().map(|p| (p, None)).chain(stickers.into_iter().map(|(p, n)| (p, Some(n)))) {
                let Some(id) = envelope::attachment_id(&pointer) else { continue };
                while pending.len() >= PENDING_POINTER_CACHE {
                    pending.pop_front();
                }
                pending.push_back((id, pointer, name));
            }
        }
        // A remote delete removes the message in Corvus; the files of its attachments must go
        // too (F1). The index below remembers which stored files belonged to which message.
        if let Some(timestamp) = remote_delete_target(&content.body) {
            for id in self.attachment_index.borrow_mut().take(sender, timestamp).unwrap_or_default() {
                if let Err(e) = tokio::fs::remove_file(self.attachments.join(&id)).await {
                    debug!(%e, id, "cannot remove the attachment of a remotely deleted message");
                }
            }
        }
        let envelope = envelope::to_envelope(&self.dir.borrow(), content);
        let envelope = envelope.map(|mut env| {
            if untrusted_identity {
                envelope::set_untrusted(&mut env);
            }
            env
        });
        if let Some(envelope) = envelope {
            if !self.emit(rpc::notification("receive", json!({"envelope": envelope, "account": self.account}))).await {
                warn!("cannot forward received message to Corvus; leaving it unacknowledged");
                return false;
            }
        }
        // The notification reached Corvus (or the message stays unacknowledged and Signal
        // delivers it again): presage's own copy of the message has served its purpose. Corvus
        // keeps the history, so the store must not become a second, never-pruned copy of every
        // message (F1) — only which files belong to which message is kept, for remote deletes.
        if let Some(timestamp) = message_timestamp(&content.body).filter(|_| !ids.is_empty()) {
            self.attachment_index.borrow_mut().remember(sender, timestamp, ids);
        }
        self.purge_messages().await;
        true
    }

    /// Like signal-cli: a delivery receipt for every message someone sent us, in the background.
    fn acknowledge(self: Rc<Self>, content: &Content) {
        let sender = content.metadata.sender;
        if sender.raw_uuid() == self.self_aci {
            return;
        }
        let timestamp = match &content.body {
            ContentBody::DataMessage(dm) => dm.timestamp,
            ContentBody::EditMessage(EditMessage { data_message: Some(dm), .. }) => dm.timestamp,
            _ => None,
        }
        .unwrap_or_else(|| content.metadata.client_timestamp.timestamp_millis() as u64);
        self.queue_delivery_receipt(sender, timestamp);
    }

    /// The master key of the group a message belongs to.
    fn group_of(&self, body: &ContentBody) -> Option<[u8; 32]> {
        let ctx = match body {
            ContentBody::DataMessage(dm) => dm.group_v2.as_ref(),
            ContentBody::EditMessage(EditMessage { data_message: Some(dm), .. }) => dm.group_v2.as_ref(),
            ContentBody::TypingMessage(t) => {
                let id = BASE64_STANDARD.encode(t.group_id.as_deref()?);
                return self.group_keys.borrow().get(&id).copied();
            }
            _ => None,
        };
        ctx?.master_key.as_deref()?.try_into().ok()
    }

    /// Whether a group message may be shown: only when the sender is a member of the group it
    /// names (security review F3). presage upserts the group the message's master key names
    /// from the server before the content reaches this function, so a message in a group we
    /// belong to always finds it here; pending or requesting members are allowed only while
    /// the message carries a group change (their join announcement). An unknown group cannot
    /// prove membership and is dropped, like signal-cli and the official clients do.
    async fn group_message_allowed(&self, sender: Uuid, body: &ContentBody) -> bool {
        match body {
            // Typing carries the 16-byte group identifier, not the master key; only groups we
            // know (and whose state is in the store) can be checked. A 1:1 typing indicator
            // has no group and is always allowed.
            ContentBody::TypingMessage(t) => {
                let Some(id) = t.group_id.as_deref().map(|g| BASE64_STANDARD.encode(g)) else { return true };
                let Some(key) = self.group_keys.borrow().get(&id).copied() else { return false };
                matches!(
                    self.store().group(key).await,
                    Ok(Some(group)) if group_member_or_pending(&group, sender, false)
                )
            }
            _ => {
                let Some(key) = self.group_of(body) else { return true };
                let change = match body {
                    ContentBody::DataMessage(dm) => group_change_present(dm.group_v2.as_ref()),
                    ContentBody::EditMessage(EditMessage { data_message: Some(dm), .. }) => {
                        group_change_present(dm.group_v2.as_ref())
                    }
                    _ => false,
                };
                matches!(
                    self.store().group(key).await,
                    Ok(Some(group)) if group_member_or_pending(&group, sender, change)
                )
            }
        }
    }

    pub(crate) fn attachments_path(&self, name: &str) -> PathBuf {
        self.attachments.join(name)
    }

    /// Saves an attachment under its id, or under `name` (received stickers). Encrypted when a
    /// secret unlocked the data; without one (and on an encryption failure, which is reported)
    /// nothing plaintext is written.
    async fn download(&self, pointer: &AttachmentPointer, name: Option<String>) {
        let Some(id) = name.or_else(|| envelope::attachment_id(pointer)) else { return };
        let path = self.attachments.join(&id);
        if path.exists() {
            return;
        }
        match self.manager.get_attachment(pointer).await {
            // The declared size passed filtered_for_download, but the sender controls it: the
            // bytes actually received are capped here, too (F4) — the declared cap alone is
            // only a promise.
            Ok(data) if data.len() as u64 > MAX_ATTACHMENT_BYTES => {
                warn!(id, size = data.len(), "not storing an attachment over the size limit");
            }
            Ok(data) => {
                if let Err(e) = save_attachment(&path, &id, &data, self.crypto.as_ref()).await {
                    warn!(%e, id, "cannot save attachment");
                }
            }
            Err(e) => warn!(%e, id, "cannot download attachment"),
        }
    }

    /// Clears presage's own copy of the message history (F1). Corvus keeps the history; the
    /// store must not become a second, never-pruned copy of every message, attachment and
    /// edit. presage itself only reads old messages to apply edits and remote deletes to its
    /// own copy — which is removed here right away anyway, before Corvus has anything to
    /// apply them to.
    async fn purge_messages(&self) {
        let mut store = self.store().clone();
        if let Err(e) = store.clear_messages().await {
            warn!(%e, "cannot clear presage's stored message history");
        }
    }

    /// Backstop for F1: attachments of messages that expired, were deleted or were opened
    /// view-once are removed actively (deleteAttachment RPC, remote deletes); files that no
    /// one asked for in this many days are swept at startup, so the folder cannot grow for
    /// ever. Corvus keeps the message history — a file whose age passed the limit while its
    /// message is still shown cannot be fetched again, so the age is configurable
    /// (CORVUS_SWEEP_DAYS, 0 disables the sweep): Corvus sets it and owns the life cycle
    /// through deleteAttachment; standalone use keeps the default.
    async fn sweep_old_attachments(&self) {
        let sweep_after_days = sweep_days();
        if sweep_after_days == 0 {
            return;
        }
        let cutoff = now_ms().saturating_sub(sweep_after_days.saturating_mul(86_400_000));
        let Ok(mut entries) = tokio::fs::read_dir(&self.attachments).await else { return };
        while let Ok(Some(entry)) = entries.next_entry().await {
            let Ok(meta) = entry.metadata().await else { continue };
            if !meta.is_file() {
                continue;
            }
            let modified = meta
                .modified()
                .ok()
                .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                .map(|d| d.as_millis() as u64)
                .unwrap_or(0);
            // 0 means "unknown modification time"; such a file is kept.
            if modified != 0 && modified < cutoff {
                if let Err(e) = tokio::fs::remove_file(entry.path()).await {
                    debug!(%e, id = %entry.file_name().to_string_lossy(), "cannot sweep an old attachment");
                }
            }
        }
    }

    /// Removes a stored attachment file (Corvus calls this when a message expires, is deleted
    /// or a view-once was opened — see the security review, F1).
    async fn delete_attachment(&self, p: &Params) -> RpcResult {
        let id = p.required_str("id")?;
        if !valid_attachment_id(id) {
            return Err(RpcError::invalid("invalid attachment id"));
        }
        match tokio::fs::remove_file(self.attachments.join(id)).await {
            Ok(()) => Ok(json!({})),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                Err(RpcError::failed("Could not find attachment"))
            }
            Err(e) => Err(e.into()),
        }
    }

    async fn emit(&self, value: Value) -> bool {
        let (written_tx, written_rx) = oneshot::channel();
        if self.out.send(Output { value, written: Some(written_tx) }).is_err() {
            return false;
        }
        matches!(written_rx.await, Ok(Ok(())))
    }

    // ---- methods ---------------------------------------------------------------------------

    pub async fn call(&self, method: &str, p: &Params) -> RpcResult {
        match method {
            "version" => Ok(json!({"version": crate::VERSION})),
            "listContacts" => self.list_contacts(p).await,
            "listGroups" => self.list_groups(p).await,
            "send" => self.send(p).await,
            "sendReaction" => self.send_reaction(p).await,
            "sendPinMessage" => self.send_pin_message(p).await,
            "sendUnpinMessage" => self.send_unpin_message(p).await,
            "sendPollCreate" => self.send_poll_create(p).await,
            "sendPollVote" => self.send_poll_vote(p).await,
            "sendPollTerminate" => self.send_poll_terminate(p).await,
            "sendContact" => self.send_contact(p).await,
            "remoteDelete" => self.remote_delete(p).await,
            "sendReceipt" => self.send_receipt(p).await,
            "syncReadMessages" => self.sync_read_messages(p).await,
            "sendTyping" => self.send_typing(p).await,
            "getAttachment" => self.get_attachment(p).await,
            "downloadAttachment" => self.download_attachment(p).await,
            "deleteAttachment" => self.delete_attachment(p).await,
            "getAvatar" => self.get_avatar(p).await,
            "updateContact" => self.update_contact(p).await,
            "listIdentities" => self.list_identities(p).await,
            "updateGroup" => self.update_group(p).await,
            "quitGroup" => self.quit_group(p).await,
            "joinGroup" => self.join_group(p).await,
            "listStickerPacks" => self.list_sticker_packs().await,
            "addStickerPack" => self.add_sticker_pack(p).await,
            "getSticker" => self.get_sticker(p).await,
            "block" => self.set_blocked(p, true).await,
            "unblock" => self.set_blocked(p, false).await,
            "removeContact" => self.remove_contact(p).await,
            "updateProfile" => self.update_profile(p).await,
            "updateAccount" => self.update_account(p).await,
            "trust" => self.trust(p).await,
            // Chat history transferred from the phone while linking (Signal's synchronized
            // start): Corvus replays it into its own store and clears it afterwards.
            "listHistoryImport" => self.list_history_import(),
            "fetchHistoryImport" => self.fetch_history_import(p),
            "clearHistoryImport" => self.clear_history_import(),
            other => Err(RpcError::unsupported(other)),
        }
    }

    async fn list_contacts(&self, p: &Params) -> RpcResult {
        let wanted: Vec<Uuid> = p
            .strings("recipient")
            .into_iter()
            .chain(p.strings("recipients"))
            .filter_map(|w| self.resolve_local(&w).ok().map(|s| s.raw_uuid()))
            .collect();
        let mut out = Vec::new();
        if wanted.contains(&self.self_aci) {
            let profile = self.manager.clone().retrieve_profile().await.ok();
            let (given, family) = profile.and_then(|p| p.name).map(|n| (Some(n.given_name), n.family_name)).unwrap_or_default();
            out.push(json!({
                "number": self.account, "uuid": self.self_aci.to_string(), "name": "",
                "username": self.storage_state.borrow().username,
                "profile": {"givenName": given, "familyName": family},
                "givenName": given, "familyName": family,
                "isBlocked": false, "isHidden": false, "isArchived": false, "messageExpirationTime": 0,
            }));
        }
        let mut listed = std::collections::HashSet::new();
        for contact in self.store().contacts().await?.flatten() {
            if contact.uuid == self.self_aci || (!wanted.is_empty() && !wanted.contains(&contact.uuid)) {
                continue;
            }
            listed.insert(contact.uuid);
            let profile_name = self.profile_name(contact.uuid).await;
            let mut entry = json!({
                "number": contact.phone_number.as_ref().map(e164),
                "uuid": contact.uuid.to_string(),
                "name": contact.name,
                "profileName": profile_name,
                "messageExpirationTime": contact.expire_timer,
            });
            if let (Value::Object(entry), Value::Object(flags)) = (&mut entry, self.contact_flags(contact.uuid)) {
                entry.extend(flags);
            }
            out.push(entry);
        }
        // Like signal-cli, everyone known is listed: also group members and people who wrote,
        // with the profile name where the profile is known.
        let mut others: Vec<Uuid> = self.dir.borrow().people.keys().copied().collect();
        others.extend(self.storage_state.borrow().people.keys().copied());
        for (_, group) in self.groups().await? {
            others.extend(group.members.iter().map(|m| Uuid::from(m.aci)));
        }
        others.sort();
        others.dedup();
        for uuid in others {
            if uuid == self.self_aci || listed.contains(&uuid) || (!wanted.is_empty() && !wanted.contains(&uuid)) {
                continue;
            }
            let (system_name, stored_profile_name) = self.storage_names(uuid);
            let profile_name = self.profile_name(uuid).await.or(stored_profile_name);
            let mut entry = json!({
                "number": self.dir.borrow().get(&uuid).number,
                "uuid": uuid.to_string(),
                "name": system_name.unwrap_or_default(),
                "profileName": profile_name,
                "messageExpirationTime": 0,
            });
            if let (Value::Object(entry), Value::Object(flags)) = (&mut entry, self.contact_flags(uuid)) {
                entry.extend(flags);
            }
            out.push(entry);
        }
        Ok(Value::Array(out))
    }

    /// Fetches the profiles of group members not known yet, with the profile keys the groups
    /// carry, so their names are there (in the background: one request per person).
    pub async fn prefetch_profiles(&self) {
        let Ok(groups) = self.groups().await else { return };
        let mut seen = std::collections::HashSet::new();
        for (_, group) in groups {
            for member in group.members {
                let uuid = Uuid::from(member.aci);
                if uuid == self.self_aci || !seen.insert(uuid) || self.profile_name(uuid).await.is_some() {
                    continue;
                }
                let mut store = self.store().clone();
                let _ = store.upsert_profile_key(&uuid, member.profile_key).await;
                if let Err(e) = self.manager.clone().retrieve_profile_by_uuid(uuid, member.profile_key).await {
                    debug!(%e, "cannot fetch a group member's profile");
                }
            }
        }
        self.reload_directory().await;
    }

    async fn list_groups(&self, p: &Params) -> RpcResult {
        let filter = p.strings("groupId");
        let mut out = Vec::new();
        for (key, group) in self.groups().await? {
            let Some(id) = envelope::group_id(&key) else { continue };
            if !filter.is_empty() && !filter.contains(&id) {
                continue;
            }
            let extras = self.group_extras(&key, &group).await;
            let pending = group.pending_members.iter().map(|m| self.pending_json(m)).collect();
            let mut entry = groups::to_json(&self.dir.borrow(), &id, key, &group, self.self_aci, &extras, pending);
            entry["isBlocked"] = json!(self.is_group_blocked(&key));
            out.push(entry);
        }
        Ok(Value::Array(out))
    }

    pub(crate) async fn upload(&self, paths: &[String], voice_note: bool) -> Result<Vec<AttachmentPointer>, RpcError> {
        let mut specs = Vec::new();
        for path in paths {
            // Staged files (e.g. a contact avatar written below) are encrypted like the stored
            // attachments; files corvus passes in are read as they are.
            let file_name = Path::new(path).file_name().map(|n| n.to_string_lossy().into_owned());
            let data = read_maybe_encrypted(Path::new(path), file_name.as_deref().unwrap_or(""), self.crypto.as_ref())
                .await
                .map_err(|e| RpcError::failed(format!("{path}: {e}")))?;
            let spec = AttachmentSpec {
                content_type: mime_guess::from_path(path).first_or_octet_stream().to_string(),
                length: data.len(),
                file_name,
                preview: None,
                voice_note: voice_note.then_some(true),
                borderless: None,
                width: None,
                height: None,
                caption: None,
                blur_hash: None,
            };
            specs.push((spec, data));
        }
        let mut pointers = Vec::new();
        for result in self.manager.upload_attachments(specs).await? {
            pointers.push(result.map_err(|e| RpcError::failed(format!("attachment upload failed: {e}")))?);
        }
        Ok(pointers)
    }

    async fn send(&self, p: &Params) -> RpcResult {
        let targets = self.targets(p).await?;
        let timestamp = now_ms();
        let mut dm = DataMessage {
            body: p.str("message").filter(|m| !m.is_empty()).map(str::to_owned),
            timestamp: Some(timestamp),
            body_ranges: textstyle::from_strings(p.strings("textStyle").iter().map(String::as_str)).map_err(RpcError::invalid)?,
            is_view_once: p.bool("viewOnce").then_some(true),
            ..Default::default()
        };
        dm.attachments = self.upload(&p.strings("attachments"), p.bool("voiceNote")).await?;
        if let Some(id) = p.u64("quoteTimestamp") {
            let author = self.resolve_aci(p.required_str("quoteAuthor")?).await?;
            dm.quote = Some(Quote {
                id: Some(id),
                author_aci: Some(author.to_string()),
                author_aci_binary: Some(author.as_bytes().to_vec()),
                text: p.str("quoteMessage").map(str::to_owned),
                r#type: Some(quote::Type::Normal as i32),
                ..Default::default()
            });
        }
        if let Some(url) = p.str("previewUrl") {
            let image = match p.str("previewImage") {
                Some(path) => self.upload(&[path.to_owned()], false).await?.into_iter().next(),
                None => None,
            };
            dm.preview = vec![Preview {
                url: Some(url.to_owned()),
                title: p.str("previewTitle").map(str::to_owned),
                description: p.str("previewDescription").map(str::to_owned),
                image,
                date: None,
            }];
        }
        if let Some(sticker) = p.str("sticker") {
            dm.sticker = Some(self.sticker_for_send(sticker).await?);
        }
        if dm.body.is_none() && dm.attachments.is_empty() && dm.sticker.is_none() {
            return Err(RpcError::invalid("no message text or attachments"));
        }
        let body = match p.u64("editTimestamp") {
            Some(target) => ContentBody::EditMessage(EditMessage { target_sent_timestamp: Some(target), data_message: Some(dm) }),
            None => ContentBody::DataMessage(dm),
        };
        self.send_to(&targets, body, timestamp).await
    }

    async fn send_reaction(&self, p: &Params) -> RpcResult {
        let targets = self.targets(p).await?;
        let author = self.resolve_aci(p.required_str("targetAuthor")?).await?;
        let timestamp = now_ms();
        let dm = DataMessage {
            reaction: Some(Reaction {
                emoji: Some(p.required_str("emoji")?.to_owned()),
                remove: Some(p.bool("remove")),
                target_author_aci: Some(author.to_string()),
                target_author_aci_binary: Some(author.as_bytes().to_vec()),
                target_sent_timestamp: Some(p.required_u64("targetTimestamp")?),
            }),
            timestamp: Some(timestamp),
            ..Default::default()
        };
        self.send_to(&targets, ContentBody::DataMessage(dm), timestamp).await
    }

    // signal-cli's sendPinMessage: an empty dataMessage that pins a message of this chat for
    // everyone. pinDuration is seconds (-1 = forever); it is optional and defaults to forever.
    async fn send_pin_message(&self, p: &Params) -> RpcResult {
        let targets = self.targets(p).await?;
        let author = self.resolve_aci(p.required_str("targetAuthor")?).await?;
        let timestamp = now_ms();
        let dm = DataMessage {
            pin_message: Some(PinMessage {
                target_author_aci_binary: Some(author.as_bytes().to_vec()),
                target_sent_timestamp: Some(p.required_u64("targetTimestamp")?),
                pin_duration: match p.i64("pinDuration").unwrap_or(-1) {
                    -1 => Some(PinDuration::PinDurationForever(true)),
                    seconds if seconds > 0 => Some(PinDuration::PinDurationSeconds(seconds as u32)),
                    _ => None, // unspecified: receivers keep their own policy (corvus pins for good)
                },
            }),
            timestamp: Some(timestamp),
            ..Default::default()
        };
        self.send_to(&targets, ContentBody::DataMessage(dm), timestamp).await
    }

    async fn send_unpin_message(&self, p: &Params) -> RpcResult {
        let targets = self.targets(p).await?;
        let author = self.resolve_aci(p.required_str("targetAuthor")?).await?;
        let timestamp = now_ms();
        let dm = DataMessage {
            unpin_message: Some(UnpinMessage {
                target_author_aci_binary: Some(author.as_bytes().to_vec()),
                target_sent_timestamp: Some(p.required_u64("targetTimestamp")?),
            }),
            timestamp: Some(timestamp),
            ..Default::default()
        };
        self.send_to(&targets, ContentBody::DataMessage(dm), timestamp).await
    }

    // signal-cli's sendPollCreate: a new poll for this chat. Like signal-cli, the question is
    // limited to 200 characters and there are 2..=10 options of at most 100 characters each.
    async fn send_poll_create(&self, p: &Params) -> RpcResult {
        let targets = self.targets(p).await?;
        let question = p.required_str("question")?.trim().to_owned();
        if question.is_empty() {
            return Err(RpcError::invalid("poll question must not be empty"));
        }
        if question.chars().count() > 200 {
            return Err(RpcError::invalid("poll question exceeds the maximum length of 200 characters"));
        }
        let mut options = p.strings("option");
        if options.is_empty() {
            options = p.strings("options");
        }
        if options.len() < 2 {
            return Err(RpcError::invalid("poll needs at least two options"));
        }
        if options.len() > 10 {
            return Err(RpcError::invalid("poll cannot have more than 10 options"));
        }
        for option in &mut options {
            *option = option.trim().to_owned();
            if option.is_empty() {
                return Err(RpcError::invalid("poll options must not be empty"));
            }
            if option.chars().count() > 100 {
                return Err(RpcError::invalid("poll option exceeds the maximum length of 100 characters"));
            }
        }
        // signal-cli takes --no-multi ("one option only"); an explicit allowMultiple wins if set.
        let allow_multiple = if p.0.contains_key("allowMultiple") {
            p.bool("allowMultiple")
        } else {
            !p.bool("noMulti")
        };
        let timestamp = now_ms();
        let dm = DataMessage {
            poll_create: Some(PollCreate {
                question: Some(question),
                allow_multiple: Some(allow_multiple),
                options,
            }),
            timestamp: Some(timestamp),
            ..Default::default()
        };
        self.send_to(&targets, ContentBody::DataMessage(dm), timestamp).await
    }

    // signal-cli's sendPollVote: vote on the poll identified by pollAuthor/pollTimestamp.
    // option holds the selected option indexes; an empty list takes the vote back.
    // voteCount counts up with every vote of the same voter (signal-cli requires it).
    async fn send_poll_vote(&self, p: &Params) -> RpcResult {
        let targets = self.targets(p).await?;
        let author = self.resolve_aci(p.required_str("pollAuthor")?).await?;
        let mut indexes = p.u64s("optionIndexes");
        if indexes.is_empty() {
            indexes = p.u64s("option");
        }
        if indexes.len() > 10 {
            return Err(RpcError::invalid("poll vote cannot contain more than 10 option indexes"));
        }
        let timestamp = now_ms();
        let dm = DataMessage {
            poll_vote: Some(PollVote {
                target_author_aci_binary: Some(author.as_bytes().to_vec()),
                target_sent_timestamp: Some(p.required_u64("pollTimestamp")?),
                option_indexes: indexes.into_iter().map(|i| u32::try_from(i).unwrap_or(u32::MAX)).collect(),
                vote_count: Some(u32::try_from(p.required_u64("voteCount")?).unwrap_or(u32::MAX)),
            }),
            timestamp: Some(timestamp),
            ..Default::default()
        };
        self.send_to(&targets, ContentBody::DataMessage(dm), timestamp).await
    }

    // signal-cli's sendPollTerminate: end the poll identified by pollTimestamp early.
    // Only the poll's author can do that; the wire format carries no author on purpose.
    async fn send_poll_terminate(&self, p: &Params) -> RpcResult {
        let targets = self.targets(p).await?;
        let timestamp = now_ms();
        let dm = DataMessage {
            poll_terminate: Some(PollTerminate { target_sent_timestamp: Some(p.required_u64("pollTimestamp")?) }),
            timestamp: Some(timestamp),
            ..Default::default()
        };
        self.send_to(&targets, ContentBody::DataMessage(dm), timestamp).await
    }

    // corvus-cli 1.6.0 (extension): a contact card as a DataMessage.contact entry — the
    // same wire format the official clients send. The name is carried as displayName in
    // the Name sub-message, an optional phone number as the first Phone entry, the
    // optional serviceId as the 16-byte aciBinary (field 8, the way the official clients
    // carry it — it lets the recipient open a chat for a UUID-only contact), and an
    // optional avatar as an AttachmentPointer (the image is uploaded like any attachment).
    // signal-cli cannot send or report contacts, so only Corvus understands these.
    async fn send_contact(&self, p: &Params) -> RpcResult {
        let targets = self.targets(p).await?;
        let name = p.required_str("name")?.trim().to_owned();
        if name.is_empty() {
            return Err(RpcError::invalid("contact name must not be empty"));
        }
        let number = p.str("number").map(|n| n.trim().to_owned()).filter(|n| !n.is_empty());
        // A malformed serviceId must not end up on the wire half-parsed.
        let aci = match p.str("uuid").filter(|u| !u.trim().is_empty()) {
            Some(raw) => match Uuid::parse_str(raw.trim()) {
                Ok(id) => Some(id.as_bytes().to_vec()),
                Err(_) => return Err(RpcError::invalid("contact uuid must be a valid serviceId (UUID)")),
            },
            None => None,
        };
        let avatar = match p.str("avatar").filter(|b| !b.trim().is_empty()) {
            Some(b64) => {
                use base64::{prelude::BASE64_STANDARD, Engine as _};
                let bytes = BASE64_STANDARD
                    .decode(b64.trim())
                    .map_err(|_| RpcError::invalid("contact avatar must be valid base64"))?;
                if bytes.len() > 1_000_000 {
                    return Err(RpcError::invalid("contact avatar exceeds the maximum size of 1 MB"));
                }
                // Staged with a matching extension so the upload derives the MIME type;
                // the staging file itself can go away once the pointer exists.
                let staged = format!("contact-avatar-{}.{}", now_ms(), Self::sniff_avatar_extension(&bytes));
                let path = self.attachments_path(&staged);
                if let Err(e) = save_attachment(&path, &staged, &bytes, self.crypto.as_ref()).await {
                    return Err(RpcError::failed(format!("avatar staging failed: {e}")));
                }
                let uploaded = self.upload(&[path.to_string_lossy().to_string()], false).await?;
                let _ = tokio::fs::remove_file(&path).await;
                uploaded.into_iter().next().map(|pointer| ContactAvatar { avatar: Some(pointer), ..Default::default() })
            }
            None => None,
        };
        let timestamp = now_ms();
        let dm = DataMessage {
            contact: vec![Contact {
                avatar,
                name: Some(ContactName { given_name: Some(name), ..Default::default() }),
                number: number
                    .map(|n| vec![ContactPhone { value: Some(n), ..Default::default() }])
                    .unwrap_or_default(),
                aci_binary: aci,
                ..Default::default()
            }],
            timestamp: Some(timestamp),
            ..Default::default()
        };
        self.send_to(&targets, ContentBody::DataMessage(dm), timestamp).await
    }

    // Avatar images are staged with an extension matching their magic bytes.
    fn sniff_avatar_extension(bytes: &[u8]) -> &'static str {
        if bytes.starts_with(&[0x89, b'P', b'N', b'G']) {
            "png"
        } else if bytes.starts_with(&[0xFF, 0xD8]) {
            "jpg"
        } else if bytes.starts_with(b"GIF8") {
            "gif"
        } else if bytes.len() >= 12 && bytes.starts_with(b"RIFF") && &bytes[8..12] == b"WEBP" {
            "webp"
        } else {
            "bin"
        }
    }

    async fn remote_delete(&self, p: &Params) -> RpcResult {
        let targets = self.targets(p).await?;
        let timestamp = now_ms();
        let dm = DataMessage {
            delete: Some(Delete { target_sent_timestamp: Some(p.required_u64("targetTimestamp")?) }),
            timestamp: Some(timestamp),
            ..Default::default()
        };
        self.send_to(&targets, ContentBody::DataMessage(dm), timestamp).await
    }

    async fn send_receipt(&self, p: &Params) -> RpcResult {
        let recipient = self.resolve(p.required_str("recipient")?).await?;
        let kind = match p.str("type").unwrap_or("read") {
            "read" => ReceiptType::Read,
            "viewed" => ReceiptType::Viewed,
            "delivery" => ReceiptType::Delivery,
            other => return Err(RpcError::invalid(format!("unknown receipt type '{other}'"))),
        };
        self.queue_receipt(recipient, kind as i32, p.u64s("targetTimestamps")).await
    }

    /// Synchronizes messages read in Corvus to this account's other Signal devices.
    /// This is separate from a ReceiptMessage sent to the author: it tells the phone that
    /// the linked desktop has already displayed the incoming messages.
    async fn sync_read_messages(&self, p: &Params) -> RpcResult {
        let reads = p.0.get("reads").and_then(Value::as_array)
            .ok_or_else(|| RpcError::invalid("missing parameter 'reads'"))?;
        if reads.is_empty() {
            return Ok(json!({}));
        }
        if reads.len() > 500 {
            return Err(RpcError::invalid("at most 500 read sync entries may be sent at once"));
        }

        let mut sync_reads = Vec::with_capacity(reads.len());
        for item in reads {
            let sender = item.get("sender").and_then(Value::as_str)
                .filter(|s| !s.trim().is_empty())
                .ok_or_else(|| RpcError::invalid("each read sync entry needs a sender"))?;
            let timestamp = item.get("timestamp").and_then(Value::as_u64)
                .filter(|ts| *ts > 0)
                .ok_or_else(|| RpcError::invalid("each read sync entry needs a positive timestamp"))?;
            let sender_aci = self.resolve_aci(sender).await?;
            sync_reads.push(SyncRead {
                sender_aci: Some(sender_aci.to_string()),
                timestamp: Some(timestamp),
                ..Default::default()
            });
        }

        let sync = SyncMessage {
            read: sync_reads,
            ..SyncMessage::with_padding(&mut rand::rng())
        };
        let timestamp = now_ms();
        let _guard = self.send_lock.lock().await;
        self.wait_for_outbound_slot().await?;
        let mut manager = self.manager.clone();
        let result = manager.send_message(
            ServiceId::Aci(Aci::from(self.self_aci)),
            ContentBody::SynchronizeMessage(sync),
            timestamp,
        ).await;
        let error_message = result.as_ref().err().map(ToString::to_string);
        self.record_outbound_result(error_message.as_deref());
        result?;
        // Presage stores sent transcripts locally; sync messages are transient as well.
        self.purge_messages().await;
        Ok(json!({"timestamp": timestamp, "results": []}))
    }

    async fn send_typing(&self, p: &Params) -> RpcResult {
        let timestamp = now_ms();
        let started = !p.bool("stop");
        let action = if started { Action::Started } else { Action::Stopped };
        let _guard = self.send_lock.lock().await;
        for target in self.targets(p).await? {
            let mut m = self.manager.clone();
            match target {
                Target::Contact(sid) => {
                    // Typing indicators are ephemeral. Never queue them behind a server cooldown.
                    if self.outbound_cooldown_remaining().is_some() {
                        debug!("dropping typing indicator while Signal outbound sending is rate-limited");
                        continue;
                    }
                    let typing_key = format!("contact:{}", sid.service_id_string());
                    if !self.should_send_typing(typing_key, started) {
                        continue;
                    }
                    self.wait_for_outbound_slot().await?;
                    let typing = TypingMessage { timestamp: Some(timestamp), action: Some(action as i32), group_id: None };
                    let send_result = m.send_message(sid, ContentBody::TypingMessage(typing), timestamp).await;
                    let error_message = send_result.as_ref().err().map(ToString::to_string);
                    self.record_outbound_result(error_message.as_deref());
                    if let Err(error) = send_result {
                        if error_message.as_deref().is_some_and(is_signal_rate_limit) {
                            debug!(%error, "Signal rate-limited a typing indicator; dropping it");
                            return Ok(json!({"timestamp": timestamp, "results": []}));
                        }
                        return Err(error.into());
                    }
                }
                Target::Group(key) => {
                    if self.outbound_cooldown_remaining().is_some() {
                        debug!("dropping group typing indicator while Signal outbound sending is rate-limited");
                        continue;
                    }
                    let typing_key = format!("group:{}", BASE64_STANDARD.encode(key));
                    if !self.should_send_typing(typing_key, started) {
                        continue;
                    }
                    let id = envelope::group_id(&key).and_then(|id| BASE64_STANDARD.decode(id).ok());
                    let typing = TypingMessage { timestamp: Some(timestamp), action: Some(action as i32), group_id: id };
                    // Typing has no sent transcript to sync, but send_message_to_group
                    // tries to build one for a multi-device account and logs an error
                    // when there is none (libsignal-service sender.rs). Send to the
                    // members directly instead, like the group fan-out does internally;
                    // a group unknown to the store keeps the old call (it resolves the
                    // members from the server).
                    match self.store().group(key).await? {
                        Some(group) => {
                            for aci in group.members.iter().map(|m| m.aci).filter(|a| Uuid::from(*a) != self.self_aci) {
                                if self.outbound_cooldown_remaining().is_some() {
                                    debug!("stopping group typing fan-out because Signal outbound sending is rate-limited");
                                    break;
                                }
                                self.wait_for_outbound_slot().await?;
                                let result = m.send_message(ServiceId::Aci(aci), ContentBody::TypingMessage(typing.clone()), timestamp).await;
                                let error_message = result.as_ref().err().map(ToString::to_string);
                                self.record_outbound_result(error_message.as_deref());
                                if let Err(error) = result {
                                    if error_message.as_deref().is_some_and(is_signal_rate_limit) {
                                        debug!(%error, "Signal rate-limited a group typing indicator; stopping fan-out");
                                        break;
                                    }
                                    warn!(%error, "cannot send a typing notification");
                                }
                            }
                        }
                        None => {
                            self.wait_for_outbound_slot().await?;
                            let result = m.send_message_to_group(&key, ContentBody::TypingMessage(typing), timestamp).await;
                            let error_message = result.as_ref().err().map(ToString::to_string);
                            self.record_outbound_result(error_message.as_deref());
                            if let Err(error) = result {
                                if error_message.as_deref().is_some_and(is_signal_rate_limit) {
                                    debug!(%error, "Signal rate-limited a group typing indicator; dropping it");
                                    return Ok(json!({"timestamp": timestamp, "results": []}));
                                }
                                return Err(error.into());
                            }
                        }
                    }
                }
            }
        }
        Ok(json!({"timestamp": timestamp, "results": []}))
    }

    async fn get_attachment(&self, p: &Params) -> RpcResult {
        let id = p.required_str("id")?;
        if !valid_attachment_id(id) {
            return Err(RpcError::invalid("invalid attachment id"));
        }
        let data = self
            .read_stored(id)
            .await
            .map_err(|_| RpcError::failed("Could not find attachment"))?;
        Ok(rpc::data_result(&data))
    }

    /// Reads a file stored in the attachments dir. With a secret, stored files are frames (the
    /// migration encrypted the leftovers at startup, new ones are written encrypted): a
    /// plaintext file in their place is not served (L1). Files Corvus passes to `send` are
    /// read leniently instead (read_maybe_encrypted) — they are not stored data.
    pub(crate) async fn read_stored(&self, name: &str) -> anyhow::Result<Vec<u8>> {
        let path = self.attachments.join(name);
        match self.crypto.as_ref() {
            Some(crypto) => {
                let data = tokio::fs::read(&path).await?;
                crypto.open(crypto::purpose::ATTACH, name, &data)
            }
            None => Ok(tokio::fs::read(&path).await?),
        }
    }

    /// Downloads the attachment of a message from a hidden (unaccepted) sender on demand (F4):
    /// nothing is fetched automatically for message requests. Corvus calls this once the
    /// request is accepted, with the id from the envelope; the pointers of those messages are
    /// kept (bounded) for exactly this. For any other id, the file must exist already.
    async fn download_attachment(&self, p: &Params) -> RpcResult {
        let id = p.required_str("id")?;
        if !valid_attachment_id(id) {
            return Err(RpcError::invalid("invalid attachment id"));
        }
        if !self.attachments.join(id).exists() {
            let from_receive = self
                .pending_pointers
                .borrow_mut()
                .iter()
                .find(|(pending, _, _)| pending == id)
                .map(|(_, pointer, name)| (pointer.clone(), name.clone()));
            let pointer = match from_receive {
                Some((pointer, name)) => (pointer, name),
                // History transferred while linking recorded its transit-tier pointers in the
                // account directory: fetch those like live ones, too.
                None => match self.transfer_pointer(id) {
                    Some(pointer) => (pointer, Some(id.to_owned())),
                    None => return Err(RpcError::failed("Could not find attachment")),
                },
            };
            let (pointer, name) = pointer;
            match tokio::time::timeout(DOWNLOAD_TIMEOUT, self.download(&pointer, name)).await {
                Ok(()) => {}
                Err(_) => return Err(RpcError::failed("download timed out")),
            }
        }
        self.get_attachment(p).await
    }

    /// The CDN pointer the history transfer recorded for an imported attachment id.
    fn transfer_pointer(&self, id: &str) -> Option<AttachmentPointer> {
        let index = std::fs::read(crate::transfer::attachments_file(&self.account_dir)).ok()?;
        let index: Value = serde_json::from_slice(&index).ok()?;
        crate::transfer::pointer_from_index(index.get(id)?)
    }

    /// Whether a chat history transfer was imported while linking (listHistoryImport).
    fn list_history_import(&self) -> RpcResult {
        match crate::transfer::import_available(&self.account_dir) {
            Some(count) => Ok(json!({"available": true, "count": count})),
            None => Ok(json!({"available": false})),
        }
    }

    /// One page of the transferred history: envelope JSONs like live receive notifications,
    /// paginated by line index. Served only after the import finished (meta says done). The
    /// lines are read from disk once and cached for the rest of the replay.
    fn fetch_history_import(&self, p: &Params) -> RpcResult {
        if crate::transfer::import_available(&self.account_dir).is_none() {
            return Ok(json!({"messages": [], "nextCursor": Value::Null}));
        }
        let mut cache = self.history_lines.borrow_mut();
        if cache.is_none() {
            let content = std::fs::read_to_string(crate::transfer::history_file(&self.account_dir))
                .map_err(|e| RpcError::failed(format!("cannot read the transferred history: {e}")))?;
            *cache = Some(content.lines().map(str::to_owned).collect());
        }
        let lines = cache.as_deref().unwrap_or(&[]);
        let start = p.u64("cursor").unwrap_or(0) as usize;
        let limit = p.u64("limit").unwrap_or(500).clamp(1, 2000) as usize;
        let end = start.saturating_add(limit).min(lines.len());
        let messages: Vec<Value> = lines
            .get(start..end)
            .unwrap_or(&[])
            .iter()
            .filter_map(|line| serde_json::from_str(line).ok())
            .collect();
        let next_cursor = if end < lines.len() { json!(end) } else { Value::Null };
        Ok(json!({"messages": messages, "nextCursor": next_cursor}))
    }

    /// Drops the transferred history after Corvus replayed it. The attachment pointer index
    /// stays: Corvus fetches imported attachments by id long after the replay.
    fn clear_history_import(&self) -> RpcResult {
        *self.history_lines.borrow_mut() = None;
        for file in [crate::transfer::history_file(&self.account_dir), crate::transfer::meta_file(&self.account_dir)] {
            if let Err(e) = std::fs::remove_file(&file) {
                if e.kind() != std::io::ErrorKind::NotFound {
                    warn!(path = %file.display(), %e, "cannot remove the transferred history");
                }
            }
        }
        Ok(json!({}))
    }

    async fn get_avatar(&self, p: &Params) -> RpcResult {
        let mut m = self.manager.clone();
        let avatar = if let Some(id) = p.str("groupId") {
            let ctx = self.group_context(self.group_key(id).await?).await;
            m.retrieve_group_avatar(ctx).await?
        } else if let Some(who) = p.str("contact") {
            let sid = self.resolve(who).await?;
            self.store().contact_by_id(&sid).await?.and_then(|c| c.avatar).map(|a| a.reader.to_vec())
        } else if let Some(who) = p.str("profile") {
            let uuid = self.resolve(who).await?.raw_uuid();
            let key: Option<ProfileKey> = if uuid == self.self_aci {
                Some(self.manager.registration_data().profile_key())
            } else {
                self.store().profile_key(&ServiceId::Aci(uuid.into())).await?
            };
            match key {
                Some(key) => m.retrieve_profile_avatar_by_uuid(uuid, key).await?,
                None => None,
            }
        } else {
            return Err(RpcError::invalid("one of groupId, contact or profile is required"));
        };
        match avatar {
            Some(data) if !data.is_empty() => Ok(rpc::data_result(&data)),
            _ => Err(RpcError::failed("No avatar found")),
        }
    }

    async fn update_contact(&self, p: &Params) -> RpcResult {
        let recipient = self.resolve(p.required_str("recipient")?).await?;
        let Some(expiration) = p.u64("expiration") else {
            // Local contact names are kept by corvus itself; nothing else to do.
            return Ok(json!({}));
        };
        let timestamp = now_ms();
        let dm = DataMessage {
            flags: Some(Flags::ExpirationTimerUpdate as u32),
            expire_timer: Some(u32::try_from(expiration).map_err(|_| RpcError::invalid("expiration out of range"))?),
            timestamp: Some(timestamp),
            ..Default::default()
        };
        self.send_to(&[Target::Contact(recipient)], ContentBody::DataMessage(dm), timestamp).await?;
        Ok(json!({}))
    }
}

/// Whether Signal explicitly rejected an outbound request because of its rate limit.
fn is_signal_rate_limit(message: &str) -> bool {
    message.contains("Rate limit exceeded")
}

/// How long to wait before attempting another session reset after a failure.
fn session_reset_backoff(message: &str) -> Duration {
    if is_signal_rate_limit(message) {
        // Signal often returns PT600S. If it omits a parseable hint, use ten minutes.
        signal_retry_after(message)
            .unwrap_or(Duration::from_secs(600))
            .saturating_add(Duration::from_secs(1))
    } else {
        Duration::from_secs(60)
    }
}

/// Parses Signal's "retry after PT..." hint. A missing or unfamiliar format is handled by
/// the caller with a conservative fallback delay.
fn signal_retry_after(message: &str) -> Option<Duration> {
    let lower = message.to_ascii_lowercase();
    let marker = "retry after ";
    let position = lower.find(marker)?;
    let value = message.get(position + marker.len()..)?.split_whitespace().next()?;
    let value = value.strip_prefix("PT")?;

    let mut number = String::new();
    let mut seconds = 0u64;
    for unit in value.chars() {
        if unit.is_ascii_digit() {
            number.push(unit);
            continue;
        }
        let amount: u64 = number.parse().ok()?;
        number.clear();
        let multiplier = match unit {
            'H' => 60 * 60,
            'M' => 60,
            'S' => 1,
            _ => return None,
        };
        seconds = seconds.checked_add(amount.checked_mul(multiplier)?)?;
    }
    if !number.is_empty() {
        return None;
    }
    Some(Duration::from_secs(seconds))
}

/// The image of a received sticker, kept so getAttachment serves it for packs that are not
/// installed. It is stored under the attachment pointer's id — the same name the envelope
/// reports as attachmentId and getAttachment serves — never under the pack id and sticker
/// id the sender claims (F5): keyed by the pack, the first sender of a pack id would decide
/// the image every later sticker of that pack shows.
fn sticker_pointers(body: &ContentBody) -> Vec<(AttachmentPointer, String)> {
    let dm = match body {
        ContentBody::DataMessage(dm) => Some(dm),
        ContentBody::SynchronizeMessage(sync) => match &sync.content {
            Some(SyncContent::Sent(sent)) => sent.message.as_ref(),
            _ => None,
        },
        _ => None,
    };
    dm.and_then(|dm| dm.sticker.as_ref())
        .and_then(|s| {
            let pointer = s.data.clone()?;
            let id = envelope::attachment_id(&pointer)?;
            Some((pointer, id))
        })
        .into_iter()
        .collect()
}

/// Migrates the sticker files the first F5 fix wrote as "sticker-<id>": getAttachment serves
/// "<id>", so received stickers of packs that are not installed could not be fetched at all
/// (the follow-up fix stores the plain id). One-time at startup; cheap when nothing matches.
///
/// The file name is part of an encrypted frame's authenticated data, so a plain rename would
/// leave every migrated file undecryptable: the frame is opened under the old name and
/// re-sealed under the new one instead. A frame that does not open under the old name is left
/// alone (it may already have been migrated by an interrupted run, or it is not ours).
async fn rename_legacy_sticker_files(dir: &Path, crypto: Option<&Crypto>) {
    let Ok(mut entries) = tokio::fs::read_dir(dir).await else { return };
    while let Ok(Some(entry)) = entries.next_entry().await {
        let name = entry.file_name();
        let Some(rest) = name.to_str().and_then(|n| n.strip_prefix("sticker-")) else {
            continue;
        };
        if !valid_attachment_id(rest) || dir.join(rest).exists() {
            continue;
        }
        let Ok(data) = tokio::fs::read(entry.path()).await else { continue };
        match crypto {
            Some(crypto) => {
                let Ok(plain) = crypto.open(crypto::purpose::ATTACH, name.to_str().unwrap_or_default(), &data) else {
                    debug!(id = rest, "cannot decrypt a legacy sticker file; leaving it alone");
                    continue;
                };
                let Ok(frame) = crypto.seal(crypto::purpose::ATTACH, rest, &plain) else {
                    debug!(id = rest, "cannot re-seal a legacy sticker file");
                    continue;
                };
                if let Err(e) = write_private(&dir.join(rest), &frame).await {
                    // The new file goes into place before the old one is removed, so an
                    // interrupted migration only leaves a duplicate, never a gap.
                    debug!(%e, id = rest, "cannot re-seal a legacy sticker file");
                    continue;
                }
            }
            None => {
                if let Err(e) = tokio::fs::rename(entry.path(), dir.join(rest)).await {
                    debug!(%e, id = rest, "cannot rename a legacy sticker file");
                    continue;
                }
            }
        }
        if let Err(e) = tokio::fs::remove_file(entry.path()).await {
            debug!(%e, id = rest, "cannot remove the migrated legacy sticker file");
        }
    }
}

fn collect_pointers(dm: &DataMessage, out: &mut Vec<AttachmentPointer>) {
    out.extend(dm.attachments.iter().cloned());
    out.extend(dm.preview.iter().filter_map(|p| p.image.clone()));
}

/// Whether a sender's attachments are downloaded automatically (F4): self, full members of
/// the group the message names, and senders known from the contacts or the storage service —
/// unless the user hid the request. Everyone else is a message request; their attachments are
/// parked until Corvus accepts it and calls downloadAttachment.
fn downloads_automatically(sender: Uuid, self_aci: Uuid, in_group: bool, known: bool, hidden: bool) -> bool {
    sender == self_aci || in_group || (!hidden && known)
}

/// The attachment sweep age in days: 30 by default, overridden by CORVUS_SWEEP_DAYS. 0
/// disables the sweep; values above ten years are clamped, a broken value keeps the default.
fn sweep_days() -> u64 {
    sweep_days_from(std::env::var("CORVUS_SWEEP_DAYS").ok().as_deref())
}

fn sweep_days_from(value: Option<&str>) -> u64 {
    const DEFAULT_DAYS: u64 = 30;
    const MAX_DAYS: u64 = 3650;
    match value.map(str::trim).filter(|v| !v.is_empty()).and_then(|v| v.parse::<u64>().ok()) {
        Some(0) => 0,
        Some(days) => days.min(MAX_DAYS).max(1),
        None => DEFAULT_DAYS,
    }
}

/// The pointers that are downloaded automatically (F4): Signal clients send at most 32
/// attachments per message; anything that declares more than 100 MiB is skipped, and the
/// per-message total is capped. Pointers without a usable id are skipped (they cannot be
/// fetched later either). Stickers go through the same size limit but not the count cap:
/// there is at most one per message.
fn filtered_for_download(pointers: &[AttachmentPointer]) -> Vec<AttachmentPointer> {
    let mut out = Vec::new();
    let mut total = 0u64;
    for pointer in pointers {
        if out.len() >= MAX_ATTACHMENTS_PER_MESSAGE || total >= MAX_ATTACHMENT_BYTES_PER_MESSAGE {
            break;
        }
        let Some(id) = envelope::attachment_id(pointer) else { continue };
        let size = u64::try_from(pointer.size.unwrap_or(0)).unwrap_or(u64::MAX);
        if size > MAX_ATTACHMENT_BYTES {
            debug!(id, size, "skipping an attachment over the size limit");
            continue;
        }
        total += size;
        out.push(pointer.clone());
    }
    out
}

/// Only file-name-safe ids are stored under attachments/ and served by getAttachment.
pub(crate) fn valid_attachment_id(id: &str) -> bool {
    !id.is_empty() && id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

/// The timestamp a remote delete points at, if this message is one.
fn remote_delete_target(body: &ContentBody) -> Option<u64> {
    match body {
        ContentBody::DataMessage(dm) => dm.delete.as_ref().and_then(|d| d.target_sent_timestamp),
        ContentBody::SynchronizeMessage(sync) => match &sync.content {
            Some(SyncContent::Sent(sent)) => sent
                .message
                .as_ref()
                .and_then(|dm| dm.delete.as_ref())
                .and_then(|d| d.target_sent_timestamp),
            _ => None,
        },
        _ => None,
    }
}

/// The timestamp of the message itself (the attachment index is keyed by sender and timestamp).
fn message_timestamp(body: &ContentBody) -> Option<u64> {
    match body {
        ContentBody::DataMessage(dm) => dm.timestamp,
        ContentBody::EditMessage(EditMessage { data_message: Some(dm), .. }) => dm.timestamp,
        ContentBody::SynchronizeMessage(sync) => match &sync.content {
            Some(SyncContent::Sent(sent)) => sent
                .edit_message
                .as_ref()
                .and_then(|e| e.data_message.as_ref())
                .and_then(|dm| dm.timestamp)
                .or_else(|| sent.message.as_ref().and_then(|dm| dm.timestamp)),
            _ => None,
        },
        _ => None,
    }
}

/// Whether the message's group context announces a group change.
fn group_change_present(ctx: Option<&GroupContextV2>) -> bool {
    ctx.and_then(|c| c.group_change.as_ref()).is_some_and(|c| !c.is_empty())
}

/// Whether `sender` is a member of `group` (F3). A pending or requesting member may only send
/// while a group change is present: that is their join announcement, which other members need
/// to see; any other message from them is not theirs to send yet.
fn group_member_or_pending(group: &Group, sender: Uuid, change: bool) -> bool {
    let member = group.members.iter().any(|m| Uuid::from(m.aci) == sender);
    let pending = change
        && (group.pending_members.iter().any(|m| m.uuid == sender)
            || group.requesting_members.iter().any(|m| Uuid::from(m.aci) == sender));
    member || pending
}

/// Which stored attachment files belong to which message, so a remote delete can remove them
/// (security review F1). Corvus calls deleteAttachment when a message expires, is deleted or
/// a view-once was opened; this index covers remote deletes, which arrive without any RPC.
/// It is kept small: entries expire after 30 days, and the file lives in the account
/// directory, encrypted when a secret unlocked the data.
struct AttachmentIndex {
    /// "<sender uuid>:<message timestamp>" -> (added at, attachment/sticker file ids)
    entries: BTreeMap<String, (u64, Vec<String>)>,
    /// The plaintext path; when a secret unlocked the data, the file lives at `<path>.enc`.
    path: PathBuf,
    crypto: Option<Crypto>,
}

impl AttachmentIndex {
    const NAME: &str = "attachments-index.json";
    const MAX_AGE_MS: u64 = 30 * 86_400_000;
    const MAX_ENTRIES: usize = 512;

    fn load(account_dir: &Path, crypto: Option<&Crypto>) -> Self {
        let path = account_dir.join(Self::NAME);
        let enc_path = path.with_extension("json.enc");
        let entries = match crypto {
            Some(crypto) => match crypto.read_file(crypto::purpose::ATTACH, Self::NAME, &enc_path) {
                Ok(data) => parse_index(&data),
                Err(e) if enc_path.exists() => {
                    warn!(%e, "cannot read the attachment index; remote deletes will not free their files");
                    Default::default()
                }
                Err(_) => Default::default(),
            },
            None => std::fs::read(&path).map(|data| parse_index(&data)).unwrap_or_default(),
        };
        Self { entries, path, crypto: crypto.cloned() }
    }

    fn remember(&mut self, sender: Uuid, timestamp: u64, ids: Vec<String>) {
        if timestamp == 0 || ids.is_empty() {
            return;
        }
        let now = now_ms();
        self.entries.retain(|_, (added, _)| now.saturating_sub(*added) < Self::MAX_AGE_MS);
        self.entries.insert(format!("{sender}:{timestamp}"), (now, ids));
        while self.entries.len() > Self::MAX_ENTRIES {
            self.entries.pop_first();
        }
        self.save();
    }

    /// Removes (and returns) the stored ids of a deleted message.
    fn take(&mut self, sender: Uuid, timestamp: u64) -> Option<Vec<String>> {
        let ids = self.entries.remove(&format!("{sender}:{timestamp}")).map(|(_, ids)| ids);
        if ids.is_some() {
            self.save();
        }
        ids
    }

    fn save(&self) {
        let mut map = serde_json::Map::new();
        for (key, (added, ids)) in &self.entries {
            map.insert(key.clone(), json!({"added": added, "ids": ids}));
        }
        let data = Value::Object(map).to_string();
        let written = match &self.crypto {
            Some(crypto) => {
                crypto.seal_file(crypto::purpose::ATTACH, Self::NAME, &self.path.with_extension("json.enc"), data.as_bytes())
            }
            // Plaintext mode: before any secret unlocked this data (see crypto.rs).
            None => crate::store::write_private_file(&self.path, data.as_bytes()).map_err(anyhow::Error::from),
        };
        if let Err(e) = written {
            warn!(%e, "cannot save the attachment index");
        }
    }
}

fn parse_index(data: &[u8]) -> BTreeMap<String, (u64, Vec<String>)> {
    let mut out = BTreeMap::new();
    if let Some(Value::Object(map)) = serde_json::from_slice(data).ok() {
        for (key, value) in map {
            let ids = value["ids"].as_array().map(|a| a.iter().filter_map(|v| v.as_str().map(str::to_owned)).collect::<Vec<String>>());
            if let (Some(ids), Some(added)) = (ids, value["added"].as_u64()) {
                out.insert(key, (added, ids));
            }
        }
    }
    out
}

async fn write_private(path: &Path, data: &[u8]) -> std::io::Result<()> {
    let tmp = path.with_extension("part");
    // 0600 from the moment of creation (L7), like crypto::write_atomic's files; narrowing the
    // permissions afterwards leaves a window a second could read.
    let mut options = tokio::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    options.mode(0o600);
    {
        use tokio::io::AsyncWriteExt as _;
        let mut f = options.open(&tmp).await?;
        f.write_all(data).await?;
    }
    tokio::fs::rename(tmp, path).await
}

/// Reads `path` and decrypts it when it is an encrypted attachment. Plain files (written by an
/// older version, or user files passed to `send` by corvus) are returned as they are.
pub(crate) async fn read_maybe_encrypted(path: &Path, name: &str, crypto: Option<&Crypto>) -> anyhow::Result<Vec<u8>> {
    let data = tokio::fs::read(path).await?;
    match crypto {
        Some(crypto) if Crypto::is_frame(&data) => Ok(crypto.open(crypto::purpose::ATTACH, name, &data)?),
        _ => Ok(data),
    }
}

/// Saves attachment bytes: encrypted when a secret is available, otherwise plain like before.
/// On an encryption failure nothing is written — an attachment stays downloadable again
/// (signal-cli keeps the pointer), while a plaintext copy could not be taken back.
pub(crate) async fn save_attachment(path: &Path, name: &str, data: &[u8], crypto: Option<&Crypto>) -> anyhow::Result<()> {
    match crypto {
        Some(crypto) => {
            let frame = crypto.seal(crypto::purpose::ATTACH, name, data)?;
            write_private(path, &frame).await?;
        }
        None => write_private(path, data).await?,
    }
    Ok(())
}


#[cfg(test)]
mod receipt_queue_tests {
    use super::*;

    #[test]
    fn parses_signal_retry_after_seconds() {
        assert_eq!(
            signal_retry_after("Rate limit exceeded: retry after PT600S"),
            Some(Duration::from_secs(600))
        );
    }

    #[test]
    fn parses_signal_retry_after_minutes_and_hours() {
        assert_eq!(
            signal_retry_after("retry after PT10M"),
            Some(Duration::from_secs(600))
        );
        assert_eq!(
            signal_retry_after("retry after PT1H2M3S"),
            Some(Duration::from_secs(3723))
        );
    }

    #[test]
    fn unknown_retry_after_format_uses_fallback() {
        assert_eq!(signal_retry_after("Rate limit exceeded"), None);
        assert_eq!(signal_retry_after("retry after 600 seconds"), None);
    }

    #[test]
    fn detects_signal_rate_limit_messages() {
        assert!(is_signal_rate_limit("service error: Rate limit exceeded: retry after PT600S"));
        assert!(!is_signal_rate_limit("network unavailable"));
    }

    #[test]
    fn session_reset_backoff_honors_rate_limit_cooldown() {
        assert_eq!(
            session_reset_backoff("Rate limit exceeded: retry after PT600S"),
            Duration::from_secs(601)
        );
        assert_eq!(
            session_reset_backoff("Rate limit exceeded"),
            Duration::from_secs(601)
        );
        assert_eq!(
            session_reset_backoff("network unavailable"),
            Duration::from_secs(60)
        );
    }
}

#[cfg(test)]
mod attachment_index_tests {
    use super::*;
    use crate::crypto;

    fn tmp(name: &str) -> PathBuf {        let dir = std::env::temp_dir().join(format!("corvus-cli-attach-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    const SENDER: Uuid = Uuid::from_u128(0x4444_4444_4444_4444_8444_4444_4444_4444);

    #[test]
    fn remembers_takes_and_persists_ids() {
        let dir = tmp("roundtrip");
        let mut index = AttachmentIndex::load(&dir, None);
        // Nothing is known about a message that was never seen.
        assert!(index.take(SENDER, 1).is_none());
        index.remember(SENDER, 1, vec!["a1".into(), "a2".into()]);
        // A restart reads the same entries back (plaintext mode: no secret, plain file).
        let mut again = AttachmentIndex::load(&dir, None);
        assert_eq!(again.take(SENDER, 1).unwrap(), ["a1", "a2"]);
        // take removes the entry: a second delete finds nothing.
        assert!(again.take(SENDER, 1).is_none());
        // Messages without timestamp or without attachments are not recorded.
        index.remember(SENDER, 0, vec!["x".into()]);
        index.remember(SENDER, 2, vec![]);
        let mut fresh = AttachmentIndex::load(&dir, None);
        assert!(fresh.take(SENDER, 0).is_none());
        assert!(fresh.take(SENDER, 2).is_none());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn the_stored_index_is_encrypted_with_the_rest_of_the_data() {
        let dir = tmp("encrypted");
        let crypto = crypto::unlock(&dir, "pw", None).unwrap();
        let mut index = AttachmentIndex::load(&dir, Some(&crypto));
        index.remember(SENDER, 5, vec!["file1".into()]);
        assert!(dir.join("attachments-index.json.enc").exists());
        assert!(!dir.join("attachments-index.json").exists());
        // The ids are not readable on disk.
        let raw = std::fs::read(dir.join("attachments-index.json.enc")).unwrap();
        assert!(!raw.windows(5).any(|w| w == b"file1"));
        // And a restart (with the same secret) reads them back.
        let mut again = AttachmentIndex::load(&dir, Some(&crypto::unlock(&dir, "pw", None).unwrap()));
        assert_eq!(again.take(SENDER, 5).unwrap(), ["file1"]);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn only_file_name_safe_ids_are_valid() {
        assert!(valid_attachment_id("a-b_C9"));
        assert!(!valid_attachment_id(""));
        assert!(!valid_attachment_id("../secret"));
        assert!(!valid_attachment_id("a/b"));
        assert!(!valid_attachment_id("a.b"));
    }
}

#[cfg(test)]
mod download_caps_tests {
    use super::*;
    use presage::proto::attachment_pointer::AttachmentIdentifier;

    fn pointer(key: &str, size: Option<u32>) -> AttachmentPointer {
        AttachmentPointer {
            attachment_identifier: Some(AttachmentIdentifier::CdnKey(key.into())),
            content_type: Some("image/png".into()),
            size,
            ..Default::default()
        }
    }

    #[test]
    fn at_most_32_attachments_per_message() {
        let pointers: Vec<_> = (0..100).map(|i| pointer(&format!("a{i}"), Some(1))).collect();
        let filtered = filtered_for_download(&pointers);
        assert_eq!(filtered.len(), MAX_ATTACHMENTS_PER_MESSAGE);
        // The first ones in order: nothing is dropped arbitrarily.
        assert_eq!(envelope::attachment_id(&filtered[0]).as_deref(), Some("a0"));
        assert_eq!(envelope::attachment_id(&filtered[31]).as_deref(), Some("a31"));
    }

    #[test]
    fn oversized_attachments_are_skipped() {
        let pointers = vec![pointer("small", Some(1)), pointer("huge", Some(MAX_ATTACHMENT_BYTES as u32 + 1)), pointer("small2", Some(1))];
        let filtered = filtered_for_download(&pointers);
        let ids: Vec<_> = filtered.iter().filter_map(envelope::attachment_id).collect();
        assert_eq!(ids, ["small", "small2"]);
    }

    #[test]
    fn the_total_bytes_per_message_are_capped() {
        // Each is under the single-file limit, together they exceed the message limit.
        let pointers: Vec<_> = (0..MAX_ATTACHMENTS_PER_MESSAGE * 2)
            .map(|i| pointer(&format!("b{i}"), Some((MAX_ATTACHMENT_BYTES_PER_MESSAGE / 16) as u32)))
            .collect();
        let filtered = filtered_for_download(&pointers);
        assert!(filtered.len() < MAX_ATTACHMENTS_PER_MESSAGE);
        assert!(filtered.len() >= 16);
    }

    #[test]
    fn pointers_without_id_are_not_downloaded() {
        let pointers = vec![AttachmentPointer::default(), pointer("ok", Some(1))];
        let filtered = filtered_for_download(&pointers);
        let ids: Vec<_> = filtered.iter().filter_map(envelope::attachment_id).collect();
        assert_eq!(ids, ["ok"]);
    }
}

#[cfg(test)]
mod group_membership_tests {
    use super::*;
    use presage::libsignal_service::groups_v2::Role;
    use presage::libsignal_service::prelude::ProfileKey;
    use presage::model::groups::{Member, PendingMember, RequestingMember};

    const ALICE: Uuid = Uuid::from_u128(0x1111_1111_1111_4111_8111_1111_1111_1111);
    const BOB: Uuid = Uuid::from_u128(0x2222_2222_2222_4222_8222_2222_2222_2222);

    /// A group with ALICE as its only full member.
    fn group(pending: &[Uuid], requesting: &[Uuid]) -> Group {
        Group {
            title: "Team".into(),
            avatar: String::new(),
            disappearing_messages_timer: None,
            access_control: None,
            revision: 3,
            members: vec![Member {
                aci: ALICE.into(),
                role: Role::Default,
                profile_key: ProfileKey::create([0; 32]),
                joined_at_revision: 0,
                label: None,
                label_emoji: None,
            }],
            pending_members: pending
                .iter()
                .map(|uuid| PendingMember {
                    uuid: *uuid,
                    service_id_type: presage::model::ServiceIdType::AccountIdentity,
                    role: Role::Default,
                    added_by_aci: ALICE.into(),
                    timestamp: 1,
                })
                .collect(),
            requesting_members: requesting
                .iter()
                .map(|uuid| RequestingMember { aci: (*uuid).into(), profile_key: ProfileKey::create([0; 32]), timestamp: 1 })
                .collect(),
            invite_link_password: vec![9; 16],
            description: None,
        }
    }

    #[test]
    fn only_members_may_send() {
        let group = group(&[], &[]);
        // A member may send; anyone else — removed member, invite-link holder — may not (F3).
        assert!(group_member_or_pending(&group, ALICE, false));
        assert!(!group_member_or_pending(&group, BOB, false));
    }

    #[test]
    fn pending_and_requesting_members_only_during_a_change() {
        let group = group(&[BOB], &[BOB]);
        // Their join announcement carries a group change and must reach the members.
        assert!(group_member_or_pending(&group, BOB, true));
        // Everything else from a not-yet-member is dropped.
        assert!(!group_member_or_pending(&group, BOB, false));
    }

    #[test]
    fn a_group_change_is_recognised() {
        // The group change travels as its serialized bytes.
        let empty = GroupContextV2 { master_key: Some([7; 32].to_vec()), revision: Some(3), group_change: None };
        let mut announced = empty.clone();
        announced.group_change = Some(vec![1, 2, 3]);
        assert!(!group_change_present(Some(&empty)));
        assert!(group_change_present(Some(&announced)));
        assert!(!group_change_present(None));
    }
}

#[cfg(test)]
mod received_sticker_tests {
    use super::*;
    use presage::proto::attachment_pointer::AttachmentIdentifier;
    use presage::proto::data_message::Sticker;

    fn tmp(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("corvus-cli-sticker-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn sticker_body(attachment_key: &str) -> ContentBody {
        ContentBody::DataMessage(DataMessage {
            sticker: Some(Sticker {
                pack_id: Some(vec![0x0a, 0x1b]),
                sticker_id: Some(3),
                data: Some(AttachmentPointer {
                    attachment_identifier: Some(AttachmentIdentifier::CdnKey(attachment_key.into())),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            ..Default::default()
        })
    }

    #[test]
    fn received_stickers_are_stored_under_the_attachment_id() {
        // getAttachment serves "<id>" and the envelope reports the same id as attachmentId:
        // the file name must be exactly that id (F5), not a variant getAttachment never finds.
        let pointers = sticker_pointers(&sticker_body("ab_c-d9"));
        assert_eq!(pointers.len(), 1);
        assert_eq!(pointers[0].1, "ab_c-d9");
        assert_eq!(envelope::attachment_id(&pointers[0].0).as_deref(), Some("ab_c-d9"));
    }

    #[test]
    fn legacy_sticker_files_are_renamed_to_the_attachment_id() {
        let dir = tmp("sticker-rename");
        std::fs::write(dir.join("sticker-ab_c-d9"), b"old").unwrap();
        // A name that is not a valid attachment id is never renamed (and never served).
        std::fs::write(dir.join("sticker-planted*"), b"evil").unwrap();
        // An existing file with the target name is kept, not overwritten.
        std::fs::write(dir.join("ee11-22"), b"target").unwrap();
        std::fs::write(dir.join("sticker-ee11-22"), b"legacy").unwrap();
        std::fs::write(dir.join("keep.webp"), b"plain").unwrap();
        tokio::runtime::Builder::new_current_thread().build().unwrap().block_on(rename_legacy_sticker_files(&dir, None));
        assert!(!dir.join("sticker-ab_c-d9").exists());
        assert_eq!(std::fs::read(dir.join("ab_c-d9")).unwrap(), b"old");
        assert!(dir.join("sticker-planted*").exists());
        assert_eq!(std::fs::read(dir.join("ee11-22")).unwrap(), b"target");
        assert!(dir.join("sticker-ee11-22").exists());
        assert!(dir.join("keep.webp").exists());
    }

    #[test]
    fn legacy_sticker_frames_are_re_sealed_under_the_attachment_id() {
        // The file name is part of an encrypted frame's authenticated data: a plain rename
        // would leave every migrated file undecryptable, so the migration re-seals (F5
        // follow-up). After the migration the frame opens under the new name and the old file
        // is gone.
        let dir = tmp("sticker-reseal");
        let keyring = tmp("sticker-reseal-keyring");
        let crypto = crypto::unlock(&keyring, "pw", None).unwrap();
        std::fs::write(
            dir.join("sticker-ab_c-d9"),
            crypto.seal(crypto::purpose::ATTACH, "sticker-ab_c-d9", b"image bytes").unwrap(),
        )
        .unwrap();
        tokio::runtime::Builder::new_current_thread().build().unwrap().block_on(rename_legacy_sticker_files(&dir, Some(&crypto)));
        assert!(!dir.join("sticker-ab_c-d9").exists());
        let frame = std::fs::read(dir.join("ab_c-d9")).unwrap();
        assert_eq!(crypto.open(crypto::purpose::ATTACH, "ab_c-d9", &frame).unwrap(), b"image bytes");
        // The old binding no longer accepts the frame either way: the name in it changed.
        assert!(crypto.open(crypto::purpose::ATTACH, "sticker-ab_c-d9", &frame).is_err());
        std::fs::remove_dir_all(dir).unwrap();
        std::fs::remove_dir_all(keyring).unwrap();
    }
}

#[cfg(test)]
mod accepted_sender_tests {
    use super::*;

    const ME: Uuid = Uuid::from_u128(0x1111_1111_1111_4111_8111_1111_1111_1111);
    const STRANGER: Uuid = Uuid::from_u128(0x2222_2222_2222_4222_8222_2222_2222_2222);

    #[test]
    fn a_first_time_sender_is_not_downloaded_automatically() {
        // The gate is not the hidden set: a stranger is not hidden, and the old hidden-only
        // check still downloaded whatever they sent (F4 follow-up).
        assert!(!downloads_automatically(STRANGER, ME, false, false, false));
    }

    #[test]
    fn known_senders_download_unless_the_request_was_hidden() {
        assert!(downloads_automatically(STRANGER, ME, false, true, false));
        // The user explicitly hid the request: nothing downloads until they accept.
        assert!(!downloads_automatically(STRANGER, ME, false, true, true));
    }

    #[test]
    fn group_members_and_self_download() {
        // Membership of the group the message names is accepted (the F3 check ran before).
        assert!(downloads_automatically(STRANGER, ME, true, false, false));
        assert!(downloads_automatically(STRANGER, ME, true, false, true));
        // The other devices of this account are always accepted.
        assert!(downloads_automatically(ME, ME, false, false, false));
    }

    #[test]
    fn the_sweep_age_is_configurable() {
        // The default stays; a file Corvus still displays must not depend on a magic
        // constant (F1 follow-up).
        assert_eq!(sweep_days_from(None), 30);
        assert_eq!(sweep_days_from(Some("")), 30);
        assert_eq!(sweep_days_from(Some("nonsense")), 30);
        assert_eq!(sweep_days_from(Some(" 14 ")), 14);
        // 0 disables the sweep entirely; absurd ages are clamped.
        assert_eq!(sweep_days_from(Some("0")), 0);
        assert_eq!(sweep_days_from(Some("99999")), 3650);
        assert_eq!(sweep_days_from(Some("-5")), 30);
    }
}
