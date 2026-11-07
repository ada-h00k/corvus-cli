// Contact and group state kept in Signal's storage service: blocked, hidden (message requests) and
// archived, as signal-cli reports them; and changes to it (block, unblock, accepting a message
// request), so the phone and other devices follow.
//
// A record is changed in its decrypted bytes: only the one field is set, so fields this program's
// protobuf definitions don't know (newer clients') survive the write.

use std::collections::{HashMap, HashSet};

use presage::libsignal_service::prelude::{ProtobufMessage, Uuid};
use presage::libsignal_service::StorageService;
use presage::proto::manifest_record::identifier::Type as RecordType;
use presage::proto::manifest_record::Identifier;
use presage::proto::storage_record::Record;
use presage::proto::sync_message::fetch_latest::Type as FetchType;
use presage::proto::sync_message::{Content as SyncContent, FetchLatest};
use presage::proto::{ContactRecord, StorageRecord, SyncMessage, WriteOperation};
use rand::RngCore;
use tracing::{info, warn};

// Field numbers in StorageService.proto.
const STORAGE_RECORD_CONTACT: u32 = 1;
const STORAGE_RECORD_GROUP_V2: u32 = 3;
const STORAGE_RECORD_ACCOUNT: u32 = 4;
const STORAGE_RECORD_STICKER_PACK: u32 = 6;
pub const ACCOUNT_USERNAME: u32 = 33;
pub const ACCOUNT_USERNAME_LINK: u32 = 35;
pub const CONTACT_BLOCKED: u32 = 9;
pub const CONTACT_HIDDEN: u32 = 20;
pub const GROUP_BLOCKED: u32 = 2;
// Identifier.Type values: installed sticker packs are records of their own. These protobuf
// definitions do not know them (they predate the type), so it is matched as the raw number.
const STICKER_PACK_RECORD_TYPE: i32 = 6;

/// A sticker pack the storage service says is installed (StorageService.proto's
/// InstalledStickerPackRecord: packId = 1 with 16 bytes, packKey = 2 with 32 bytes,
/// position = 3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StickerPackSync {
    pub id: [u8; 16],
    pub key: [u8; 32],
    pub position: u32,
}

/// A contact as the storage service has it.
#[derive(Debug, Default, Clone)]
pub struct Person {
    pub number: Option<String>,
    /// From the phone's address book, or the nickname given in Signal.
    pub system_name: Option<String>,
    pub profile_name: Option<String>,
    pub profile_key: Option<[u8; 32]>,
}

fn join_name(given: &str, family: &str) -> Option<String> {
    let name = format!("{given} {family}").trim().to_owned();
    (!name.is_empty()).then_some(name)
}

/// What the storage service says about contacts and groups.
#[derive(Debug, Default, Clone)]
pub struct State {
    pub people: HashMap<Uuid, Person>,
    /// Our username, from the account record.
    pub username: Option<String>,
    pub blocked: HashSet<Uuid>,
    pub hidden: HashSet<Uuid>,
    pub archived: HashSet<Uuid>,
    pub blocked_numbers: HashSet<String>,
    pub blocked_groups: HashSet<[u8; 32]>,
    pub archived_groups: HashSet<[u8; 32]>,
    /// Installed sticker packs, in the order the phone keeps (position, then pack id).
    pub sticker_packs: Vec<StickerPackSync>,
    /// Packs the storage service explicitly marks uninstalled (deletedAtTimestamp is set).
    pub removed_sticker_packs: HashSet<[u8; 16]>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Target {
    Contact(Uuid),
    Group([u8; 32]),
    /// Our own account record (there is one).
    Account,
}

impl Target {
    fn outer_field(self) -> u32 {
        match self {
            Target::Contact(_) => STORAGE_RECORD_CONTACT,
            Target::Group(_) => STORAGE_RECORD_GROUP_V2,
            Target::Account => STORAGE_RECORD_ACCOUNT,
        }
    }

    fn kind(self) -> RecordType {
        match self {
            Target::Contact(_) => RecordType::Contact,
            Target::Group(_) => RecordType::Groupv2,
            Target::Account => RecordType::Account,
        }
    }
}

// ---- protobuf wire format ------------------------------------------------------------------

fn put_varint(out: &mut Vec<u8>, mut v: u64) {
    while v >= 0x80 {
        out.push((v as u8) | 0x80);
        v >>= 7;
    }
    out.push(v as u8);
}

fn get_varint(bytes: &[u8], pos: &mut usize) -> Option<u64> {
    let mut v = 0u64;
    for shift in (0..64).step_by(7) {
        let b = *bytes.get(*pos)?;
        *pos += 1;
        v |= u64::from(b & 0x7f) << shift;
        if b & 0x80 == 0 {
            return Some(v);
        }
    }
    None
}

/// The byte range of the value of length-delimited field `field` (the first one) in `bytes`.
fn find_len_field(bytes: &[u8], field: u32) -> Option<(usize, std::ops::Range<usize>)> {
    let mut pos = 0;
    while pos < bytes.len() {
        let start = pos;
        let tag = get_varint(bytes, &mut pos)?;
        let (number, wire) = ((tag >> 3) as u32, tag & 7);
        match wire {
            0 => {
                get_varint(bytes, &mut pos)?;
            }
            1 => pos += 8,
            5 => pos += 4,
            2 => {
                let len = get_varint(bytes, &mut pos)? as usize;
                let value = pos..pos.checked_add(len)?;
                if value.end > bytes.len() {
                    return None;
                }
                if number == field {
                    return Some((start, value));
                }
                pos = value.end;
            }
            _ => return None,
        }
    }
    None
}

/// `record` (a StorageRecord's bytes) with `field` of its `outer` message set to `value`.
/// The field is appended to the inner message (the last occurrence of a scalar wins); everything
/// else stays byte for byte.
pub fn set_field(record: &[u8], outer: u32, field: u32, value: &Value) -> Option<Vec<u8>> {
    let (start, inner) = find_len_field(record, outer)?;
    let mut extra = Vec::new();
    match value {
        Value::Bool(v) => {
            put_varint(&mut extra, u64::from(field) << 3);
            put_varint(&mut extra, u64::from(*v));
        }
        Value::Bytes(v) => {
            put_varint(&mut extra, (u64::from(field) << 3) | 2);
            put_varint(&mut extra, v.len() as u64);
            extra.extend_from_slice(v);
        }
    }
    let mut out = Vec::with_capacity(record.len() + extra.len() + 2);
    out.extend_from_slice(&record[..start]);
    put_varint(&mut out, (u64::from(outer) << 3) | 2);
    put_varint(&mut out, (inner.len() + extra.len()) as u64);
    out.extend_from_slice(&record[inner.clone()]);
    out.extend_from_slice(&extra);
    out.extend_from_slice(&record[inner.end..]);
    Some(out)
}

#[cfg(test)]
fn set_bool(record: &[u8], outer: u32, field: u32, value: bool) -> Option<Vec<u8>> {
    set_field(record, outer, field, &Value::Bool(value))
}

/// AccountRecord.UsernameLink { entropy = 1; serverId = 2; }
pub fn username_link_message(entropy: &[u8], server_id: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    for (field, bytes) in [(1u64, entropy), (2, server_id)] {
        put_varint(&mut out, (field << 3) | 2);
        put_varint(&mut out, bytes.len() as u64);
        out.extend_from_slice(bytes);
    }
    out
}

fn contact_uuid(c: &ContactRecord) -> Option<Uuid> {
    Uuid::from_slice(&c.aci_binary).ok().or_else(|| Uuid::parse_str(&c.aci).ok())
}

fn record_target(record: &StorageRecord) -> Option<Target> {
    match record.record.as_ref()? {
        Record::Contact(c) => contact_uuid(c).map(Target::Contact),
        Record::GroupV2(g) => g.master_key.as_slice().try_into().ok().map(Target::Group),
        Record::Account(_) => Some(Target::Account),
        _ => None,
    }
}

// ---- reading -------------------------------------------------------------------------------

/// Reads the contact and group records.
pub async fn read_state(service: &StorageService) -> anyhow::Result<State> {
    let manifest = service.manifest().await?;
    let keys: Vec<Vec<u8>> = manifest
        .identifiers
        .iter()
        .filter(|i| {
            matches!(RecordType::try_from(i.r#type), Ok(RecordType::Contact | RecordType::Groupv2 | RecordType::Account))
        })
        .map(|i| i.raw.clone())
        .collect();
    let ikm = (!manifest.record_ikm.is_empty()).then_some(manifest.record_ikm.as_slice());
    let mut state = State::default();
    // The server reads at most a few hundred items per request.
    for chunk in keys.chunks(500) {
        for record in service.read_items(chunk.to_vec(), ikm).await? {
            match record.record {
                Some(Record::Contact(c)) => {
                    let Some(uuid) = contact_uuid(&c) else { continue };
                    let nickname = c.nickname.as_ref().and_then(|n| join_name(&n.given, &n.family));
                    state.people.insert(
                        uuid,
                        Person {
                            number: (!c.e164.is_empty()).then(|| c.e164.clone()),
                            system_name: nickname.or_else(|| join_name(&c.system_given_name, &c.system_family_name)),
                            profile_name: join_name(&c.given_name, &c.family_name),
                            profile_key: c.profile_key.as_slice().try_into().ok(),
                        },
                    );
                    if c.blocked {
                        state.blocked.insert(uuid);
                        if !c.e164.is_empty() {
                            state.blocked_numbers.insert(c.e164.clone());
                        }
                    }
                    if c.hidden {
                        state.hidden.insert(uuid);
                    }
                    if c.archived {
                        state.archived.insert(uuid);
                    }
                }
                Some(Record::Account(a)) => {
                    state.username = (!a.username.is_empty()).then(|| a.username.clone());
                }
                Some(Record::GroupV2(g)) => {
                    let Ok(key) = <[u8; 32]>::try_from(g.master_key.as_slice()) else { continue };
                    if g.blocked {
                        state.blocked_groups.insert(key);
                    }
                    if g.archived {
                        state.archived_groups.insert(key);
                    }
                }
                _ => {}
            }
        }
    }
    // Installed sticker packs: their type is unknown to these protobuf definitions, so their
    // decrypted bytes are read raw and parsed here.
    let pack_keys: Vec<Vec<u8>> = manifest
        .identifiers
        .iter()
        .filter(|i| i.r#type == STICKER_PACK_RECORD_TYPE)
        .map(|i| i.raw.clone())
        .collect();
    for chunk in pack_keys.chunks(500) {
        for (_, bytes) in service.read_items_raw(chunk.to_vec(), ikm).await? {
            match sticker_record(&bytes) {
                StickerRecord::Installed(pack) => state.sticker_packs.push(pack),
                StickerRecord::Removed(id) => drop(state.removed_sticker_packs.insert(id)),
                StickerRecord::Other => {}
            }
        }
    }
    // Signal's display order: ascending position, then pack id.
    state.sticker_packs.sort_by_key(|p| (p.position, p.id));
    Ok(state)
}

/// An installed sticker pack record, or the news that one was uninstalled.
enum StickerRecord {
    Installed(StickerPackSync),
    Removed([u8; 16]),
    Other,
}

/// Parses a record of type STICKER_PACK: its bytes are a StorageRecord whose oneof carries
/// InstalledStickerPackRecord (packId = 1, packKey = 2, position = 3, deletedAtTimestamp = 4).
/// A non-zero deletedAtTimestamp means the pack was uninstalled (packKey unset then); unknown
/// fields of newer clients are skipped, as everywhere here.
fn sticker_record(record: &[u8]) -> StickerRecord {
    let Some((_, inner)) = find_len_field(record, STORAGE_RECORD_STICKER_PACK) else {
        return StickerRecord::Other;
    };
    let (mut id, mut key, mut position, mut deleted) = (None, None, 0u32, 0u64);
    let mut pos = inner.start;
    while pos < inner.end {
        let Some(tag) = get_varint(record, &mut pos) else { return StickerRecord::Other };
        let (field, wire) = ((tag >> 3) as u32, tag & 7);
        match wire {
            0 => {
                let Some(v) = get_varint(record, &mut pos) else { return StickerRecord::Other };
                match field {
                    3 => position = u32::try_from(v).unwrap_or(u32::MAX),
                    4 => deleted = v,
                    _ => {}
                }
            }
            1 => pos += 8,
            5 => pos += 4,
            2 => {
                let Some(len) = get_varint(record, &mut pos) else { return StickerRecord::Other };
                let Some(end) = pos.checked_add(len as usize) else { return StickerRecord::Other };
                if end > inner.end {
                    return StickerRecord::Other;
                }
                if field == 1 {
                    id = Some(record[pos..end].to_vec());
                }
                if field == 2 {
                    key = Some(record[pos..end].to_vec());
                }
                pos = end;
            }
            _ => return StickerRecord::Other,
        }
    }
    let Ok(id) = <[u8; 16]>::try_from(id.as_deref().unwrap_or_default()) else {
        return StickerRecord::Other;
    };
    if deleted != 0 {
        return StickerRecord::Removed(id);
    }
    let Ok(key) = <[u8; 32]>::try_from(key.as_deref().unwrap_or_default()) else {
        return StickerRecord::Other;
    };
    StickerRecord::Installed(StickerPackSync { id, key, position })
}

// ---- writing -------------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub enum Value {
    Bool(bool),
    /// Strings, bytes and embedded messages.
    Bytes(Vec<u8>),
}

/// A field to set on the record of a contact, a group or the account.
#[derive(Debug, Clone)]
pub struct Change {
    pub target: Target,
    pub field: u32,
    pub value: Value,
}

/// A record for a contact the storage service doesn't have yet (Signal's apps create one too).
fn new_contact_record(uuid: Uuid, number: Option<&str>) -> Vec<u8> {
    StorageRecord {
        record: Some(Record::Contact(ContactRecord {
            aci: uuid.to_string(),
            aci_binary: uuid.as_bytes().to_vec(),
            e164: number.unwrap_or_default().to_owned(),
            ..Default::default()
        })),
    }
    .encode_to_vec()
}

fn new_raw_id() -> Vec<u8> {
    let mut id = vec![0u8; 16];
    rand::rng().fill_bytes(&mut id);
    id
}

/// Applies `changes` and writes them with a new manifest version, again on a conflict.
/// `numbers` gives the phone number of contacts that may need a new record.
pub async fn write_changes(
    service: &StorageService,
    device_id: u32,
    changes: &[Change],
    numbers: &HashMap<Uuid, String>,
) -> anyhow::Result<()> {
    const ATTEMPTS: usize = 3;
    for attempt in 1..=ATTEMPTS {
        let manifest = service.manifest().await?;
        let ikm = (!manifest.record_ikm.is_empty()).then_some(manifest.record_ikm.clone());
        let wanted: Vec<&Identifier> = manifest
            .identifiers
            .iter()
            .filter(|i| {
                matches!(
                    RecordType::try_from(i.r#type),
                    Ok(RecordType::Contact | RecordType::Groupv2 | RecordType::Account)
                )
            })
            .collect();
        let mut found: HashMap<Target, (Vec<u8>, Vec<u8>)> = HashMap::new();
        for chunk in wanted.chunks(500) {
            let keys = chunk.iter().map(|i| i.raw.clone()).collect();
            for (raw, bytes) in service.read_items_raw(keys, ikm.as_deref()).await? {
                let Ok(record) = StorageRecord::decode(bytes.as_slice()) else { continue };
                if let Some(target) = record_target(&record) {
                    if changes.iter().any(|c| c.target == target) {
                        found.insert(target, (raw, bytes));
                    }
                }
            }
        }

        let mut identifiers: Vec<Identifier> = manifest.identifiers.clone();
        let mut insert = Vec::new();
        let mut delete = Vec::new();
        let mut edited: HashMap<Target, Vec<u8>> = HashMap::new();
        for change in changes {
            let current = match edited.get(&change.target) {
                Some(bytes) => bytes.clone(),
                None => match (found.get(&change.target), change.target) {
                    (Some((raw, bytes)), _) => {
                        delete.push(raw.clone());
                        identifiers.retain(|i| &i.raw != raw);
                        bytes.clone()
                    }
                    (None, Target::Contact(uuid)) => new_contact_record(uuid, numbers.get(&uuid).map(String::as_str)),
                    // A group the storage service doesn't list can't be marked there; the account
                    // record is made by the phone.
                    (None, Target::Group(_) | Target::Account) => continue,
                },
            };
            let bytes = set_field(&current, change.target.outer_field(), change.field, &change.value)
                .ok_or_else(|| anyhow::anyhow!("unreadable storage record"))?;
            edited.insert(change.target, bytes);
        }
        if edited.is_empty() {
            return Ok(());
        }
        for (target, bytes) in edited {
            // A changed record gets a new id, so other devices see that it changed.
            let raw = new_raw_id();
            insert.push(StorageService::encrypt_item_raw(service.storage_key(), raw.clone(), &bytes, ikm.as_deref()));
            identifiers.push(Identifier { raw, r#type: target.kind() as i32 });
        }
        let new_manifest = presage::proto::ManifestRecord {
            version: manifest.version + 1,
            source_device: device_id,
            identifiers,
            record_ikm: manifest.record_ikm.clone(),
        };
        let operation = WriteOperation {
            manifest: Some(StorageService::encrypt_manifest(service.storage_key(), &new_manifest)),
            insert_item: insert,
            delete_key: delete,
            clear_all: false,
        };
        if service.write(&operation).await? {
            info!(version = new_manifest.version, "storage service updated");
            return Ok(());
        }
        warn!(attempt, "storage service changed meanwhile, trying again");
    }
    anyhow::bail!("the storage service kept changing; try again later")
}

/// Tells our other devices (the phone) to read the storage service again.
pub fn fetch_latest_sync() -> SyncMessage {
    SyncMessage {
        content: Some(SyncContent::FetchLatest(FetchLatest { r#type: Some(FetchType::StorageManifest as i32) })),
        ..Default::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use presage::proto::GroupV2Record;

    fn len_field(field: u32, bytes: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        put_varint(&mut out, (u64::from(field) << 3) | 2);
        put_varint(&mut out, bytes.len() as u64);
        out.extend_from_slice(bytes);
        out
    }

    fn varint_field(field: u32, v: u64) -> Vec<u8> {
        let mut out = Vec::new();
        put_varint(&mut out, u64::from(field) << 3);
        put_varint(&mut out, v);
        out
    }

    #[test]
    fn sticker_pack_records() {
        let (id, key) = ([7u8; 16], [9u8; 32]);
        let mut pack = len_field(1, &id);
        pack.extend(len_field(2, &key));
        pack.extend(varint_field(3, 4));
        // A field of a newer client must not hurt.
        pack.extend(varint_field(11, 1));
        let record = len_field(STORAGE_RECORD_STICKER_PACK, &pack);
        let StickerRecord::Installed(p) = sticker_record(&record) else { panic!("must parse as installed") };
        assert_eq!(p, StickerPackSync { id, key, position: 4 });

        // Uninstalled: deletedAtTimestamp is set and the pack key is gone.
        let mut removed = len_field(1, &id);
        removed.extend(varint_field(4, 12345));
        let record = len_field(STORAGE_RECORD_STICKER_PACK, &removed);
        let StickerRecord::Removed(removed_id) = sticker_record(&record) else { panic!("must parse as removed") };
        assert_eq!(removed_id, id);

        // Broken records: not a sticker pack, wrong key length, garbage.
        let mut bad = len_field(1, &id);
        bad.extend(len_field(2, &[1, 2, 3]));
        assert!(matches!(sticker_record(&len_field(STORAGE_RECORD_STICKER_PACK, &bad)), StickerRecord::Other));
        assert!(matches!(sticker_record(b"nothing here"), StickerRecord::Other));
        assert!(matches!(sticker_record(&varint_field(6, 1)), StickerRecord::Other));
    }

    #[test]
    fn set_bool_changes_only_that_field() {
        let uuid = Uuid::from_u128(7);
        let original = StorageRecord {
            record: Some(Record::Contact(ContactRecord {
                aci: uuid.to_string(),
                e164: "+491234".into(),
                given_name: "Alice".into(),
                archived: true,
                ..Default::default()
            })),
        }
        .encode_to_vec();
        // A field this program doesn't know (as from a newer client) must survive.
        let mut with_unknown = original.clone();
        let (start, inner) = find_len_field(&with_unknown, 1).unwrap();
        let mut inner_bytes = with_unknown[inner.clone()].to_vec();
        inner_bytes.extend_from_slice(&[0xf8, 0x06, 0x01]); // field 111, varint 1
        let mut rebuilt = with_unknown[..start].to_vec();
        put_varint(&mut rebuilt, (1 << 3) | 2);
        put_varint(&mut rebuilt, inner_bytes.len() as u64);
        rebuilt.extend_from_slice(&inner_bytes);
        with_unknown = rebuilt;

        let blocked = set_bool(&with_unknown, STORAGE_RECORD_CONTACT, CONTACT_BLOCKED, true).unwrap();
        let Some(Record::Contact(c)) = StorageRecord::decode(blocked.as_slice()).unwrap().record else { panic!() };
        assert!(c.blocked);
        assert!(c.archived);
        assert_eq!(c.given_name, "Alice");
        assert_eq!(c.e164, "+491234");
        // The unknown field is still there, byte for byte.
        let (_, inner) = find_len_field(&blocked, 1).unwrap();
        assert!(blocked[inner].windows(3).any(|w| w == [0xf8, 0x06, 0x01]));

        // An explicit false undoes it.
        let unblocked = set_bool(&blocked, STORAGE_RECORD_CONTACT, CONTACT_BLOCKED, false).unwrap();
        let Some(Record::Contact(c)) = StorageRecord::decode(unblocked.as_slice()).unwrap().record else { panic!() };
        assert!(!c.blocked);
        assert_eq!(c.given_name, "Alice");
    }

    #[test]
    fn groups_and_targets() {
        let record = StorageRecord {
            record: Some(Record::GroupV2(GroupV2Record { master_key: vec![5; 32], ..Default::default() })),
        };
        assert_eq!(record_target(&record), Some(Target::Group([5; 32])));
        let bytes = set_bool(&record.encode_to_vec(), STORAGE_RECORD_GROUP_V2, GROUP_BLOCKED, true).unwrap();
        let Some(Record::GroupV2(g)) = StorageRecord::decode(bytes.as_slice()).unwrap().record else { panic!() };
        assert!(g.blocked);
        // Not a contact record: nothing to change.
        assert!(set_bool(&bytes, STORAGE_RECORD_CONTACT, CONTACT_BLOCKED, true).is_none());
    }

    #[test]
    fn new_contact_records_carry_the_aci() {
        let uuid = Uuid::from_u128(9);
        let bytes = new_contact_record(uuid, Some("+4999"));
        let record = StorageRecord::decode(bytes.as_slice()).unwrap();
        assert_eq!(record_target(&record), Some(Target::Contact(uuid)));
    }

    #[test]
    fn account_username() {
        use presage::proto::AccountRecord;
        let record = StorageRecord {
            record: Some(Record::Account(AccountRecord { given_name: "Me".into(), ..Default::default() })),
        }
        .encode_to_vec();
        let bytes = set_field(&record, STORAGE_RECORD_ACCOUNT, ACCOUNT_USERNAME, &Value::Bytes(b"me.42".to_vec())).unwrap();
        let link = username_link_message(&[1; 32], &[2; 16]);
        let bytes = set_field(&bytes, STORAGE_RECORD_ACCOUNT, ACCOUNT_USERNAME_LINK, &Value::Bytes(link)).unwrap();
        let Some(Record::Account(a)) = StorageRecord::decode(bytes.as_slice()).unwrap().record else { panic!() };
        assert_eq!(a.given_name, "Me");
        assert_eq!(a.username, "me.42");
        let l = a.username_link.unwrap();
        assert_eq!(l.entropy, vec![1; 32]);
        assert_eq!(l.server_id, vec![2; 16]);
    }

    #[test]
    fn varints() {
        for v in [0u64, 1, 127, 128, 300, u32::MAX as u64] {
            let mut buf = Vec::new();
            put_varint(&mut buf, v);
            let mut pos = 0;
            assert_eq!(get_varint(&buf, &mut pos), Some(v));
            assert_eq!(pos, buf.len());
        }
    }
}
