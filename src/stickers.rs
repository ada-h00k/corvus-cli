// signal-cli's sticker commands: listStickerPacks, addStickerPack, getSticker, and the sticker
// option of `send`. Plus the sync of the packs the phone has installed (their records live in
// the storage service, like Signal Desktop's).

use std::collections::HashSet;
use std::rc::Rc;

use base64::prelude::*;
use futures::io::AsyncReadExt;
use presage::libsignal_service::prelude::ProtobufMessage;
use presage::libsignal_service::proto::Pack;
use presage::libsignal_service::sender::AttachmentSpec;
use presage::libsignal_service::sticker_cipher::{derive_key, decrypt_in_place};
use presage::libsignal_service::websocket::{Identified, SignalWebSocket};
use presage::proto::data_message::Sticker;
use presage::store::{ContentsStore, StickerPack, StickerPackManifest};
use presage_store_sqlite::SqliteStore;
use serde_json::{json, Value};
use tracing::{info, warn};

use crate::daemon::Daemon;
use crate::rpc::{Params, RpcError, RpcResult};
use crate::storage::StickerPackSync;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(text: &str) -> Option<Vec<u8>> {
    if text.len() % 2 != 0 {
        return None;
    }
    (0..text.len()).step_by(2).map(|i| u8::from_str_radix(text.get(i..i + 2)?, 16).ok()).collect()
}

/// "https://signal.art/addstickers/#pack_id=…&pack_key=…" -> (id, key)
pub fn parse_pack_uri(uri: &str) -> Option<(Vec<u8>, Vec<u8>)> {
    let fragment = uri.split_once('#')?.1;
    let (mut id, mut key) = (None, None);
    for pair in fragment.split('&') {
        match pair.split_once('=')? {
            ("pack_id", v) => id = unhex(v),
            ("pack_key", v) => key = unhex(v),
            _ => {}
        }
    }
    Some((id?, key?))
}

/// File name under which the image of a received sticker is kept.
pub fn received_sticker_file(pack_id: &[u8], sticker_id: u32) -> String {
    format!("sticker-{}-{}", hex(pack_id), sticker_id)
}

impl Daemon {
    /// Brings the local packs in line with the storage service: installs what the phone has
    /// installed there and drops what it uninstalled there. This is what makes the packs of the
    /// phone show up: they are not sent to a new device otherwise (only their records are in the
    /// storage service, like Signal Desktop's are).
    ///
    /// Uninstalls usually also arrive as sync messages (presage handles those); a pack that is
    /// simply absent from the storage service is kept, because the phone may not have noted a
    /// pack this program installed via addStickerPack yet.
    pub(crate) async fn sync_sticker_packs(self: Rc<Self>) {
        // One at a time: every storage change triggers this, and downloads must not race.
        let _guard = match self.pack_sync.try_lock() {
            Ok(guard) => guard,
            Err(_) => return,
        };
        let (wanted, removed) = {
            let state = self.storage_state.borrow();
            (state.sticker_packs.clone(), state.removed_sticker_packs.clone())
        };
        let known: HashSet<Vec<u8>> = match self.store().sticker_packs().await {
            Ok(iter) => iter.flatten().map(|p| p.id).collect(),
            Err(e) => return warn!(%e, "cannot read the stored sticker packs"),
        };
        let missing: Vec<&StickerPackSync> =
            wanted.iter().filter(|p| !known.contains(p.id.as_slice())).collect();
        if !missing.is_empty() {
            // One websocket serves all packs: the images come from the CDN, the connection
            // itself is not used for them.
            let mut push = self.manager.identified_push_service();
            let mut ws: SignalWebSocket<Identified> =
                match push.ws("/v1/websocket/", "/v1/keepalive", &[], None).await {
                    Ok(ws) => ws,
                    Err(e) => {
                        warn!(%e, "cannot reach the sticker CDN");
                        return;
                    }
                };
            for pack in missing {
                let pack_id = hex(&pack.id);
                match download_pack(&mut ws, self.store(), pack).await {
                    Ok(()) => info!(pack = %pack_id, "installed a sticker pack from the storage service"),
                    Err(e) => warn!(pack = %pack_id, %e, "cannot install a sticker pack from the storage service"),
                }
            }
        }
        for id in removed {
            if known.contains(id.as_slice()) {
                let mut store = self.store().clone();
                if let Err(e) = store.remove_sticker_pack(&id).await {
                    warn!(%e, "cannot remove an uninstalled sticker pack");
                } else {
                    info!(pack = %hex(&id), "removed a sticker pack uninstalled on the phone");
                }
            }
        }
    }

    pub(crate) async fn list_sticker_packs(&self) -> RpcResult {
        let mut out = Vec::new();
        // In the order they were stored: the packs of the storage service come in Signal's order
        // (position, then pack id), and later addStickerPacks follow.
        for pack in self.store().sticker_packs().await? {
            let pack = match pack {
                Ok(pack) => pack,
                Err(e) => {
                    warn!(%e, "cannot read a stored sticker pack");
                    continue;
                }
            };
            let stickers: Vec<Value> = pack
                .manifest
                .stickers
                .iter()
                .map(|s| json!({"id": s.id, "emoji": s.emoji, "contentType": s.content_type}))
                .collect();
            out.push(json!({
                "packId": hex(&pack.id),
                "url": format!("https://signal.art/addstickers/#pack_id={}&pack_key={}", hex(&pack.id), hex(&pack.key)),
                "installed": true,
                "title": pack.manifest.title,
                "author": pack.manifest.author,
                "stickers": stickers,
            }));
        }
        Ok(Value::Array(out))
    }

    pub(crate) async fn add_sticker_pack(&self, p: &Params) -> RpcResult {
        let uri = p.required_str("uri")?;
        let (id, key) = parse_pack_uri(uri).ok_or_else(|| RpcError::failed("Sticker pack link is invalid"))?;
        let _guard = self.send_lock.lock().await;
        self.manager.clone().install_sticker_pack(&id, &key).await?;
        Ok(json!({}))
    }

    /// From an installed pack, else the copy saved when the sticker was received.
    async fn sticker_bytes(&self, pack_id: &[u8], sticker_id: u32) -> Option<(Vec<u8>, Option<String>)> {
        if let Ok(Some(pack)) = self.store().sticker_pack(pack_id).await {
            if let Some(s) = pack.manifest.stickers.iter().find(|s| s.id == sticker_id) {
                if let Some(bytes) = &s.bytes {
                    return Some((bytes.clone(), s.content_type.clone()));
                }
            }
        }
        let path = self.attachments_path(&received_sticker_file(pack_id, sticker_id));
        tokio::fs::read(path).await.ok().map(|b| (b, None))
    }

    pub(crate) async fn get_sticker(&self, p: &Params) -> RpcResult {
        let pack_id = unhex(p.required_str("packId")?).ok_or_else(|| RpcError::invalid("invalid packId"))?;
        let sticker_id = u32::try_from(p.required_u64("stickerId")?).map_err(|_| RpcError::invalid("invalid stickerId"))?;
        let (bytes, _) = self
            .sticker_bytes(&pack_id, sticker_id)
            .await
            .ok_or_else(|| RpcError::failed("Could not find sticker pack"))?;
        Ok(json!({"data": BASE64_STANDARD.encode(bytes)}))
    }

    /// The sticker of a `send` ("packId:stickerId"), with its image uploaded as Signal's clients do.
    pub(crate) async fn sticker_for_send(&self, spec: &str) -> Result<Sticker, RpcError> {
        let (pack, id) = spec.split_once(':').ok_or_else(|| RpcError::invalid("sticker must be packId:stickerId"))?;
        let pack_id = unhex(pack).ok_or_else(|| RpcError::invalid("invalid sticker pack id"))?;
        let sticker_id: u32 = id.parse().map_err(|_| RpcError::invalid("invalid sticker id"))?;
        let pack = self
            .store()
            .sticker_pack(&pack_id)
            .await?
            .ok_or_else(|| RpcError::failed("Sticker pack not installed"))?;
        let sticker = pack
            .manifest
            .stickers
            .iter()
            .find(|s| s.id == sticker_id)
            .ok_or_else(|| RpcError::failed("Sticker not found in pack"))?;
        let bytes = sticker.bytes.clone().ok_or_else(|| RpcError::failed("Sticker image not downloaded"))?;
        let spec = AttachmentSpec {
            content_type: sticker.content_type.clone().unwrap_or_else(|| "image/webp".into()),
            length: bytes.len(),
            file_name: None,
            preview: None,
            voice_note: None,
            borderless: Some(true),
            width: None,
            height: None,
            caption: None,
            blur_hash: None,
        };
        let pointer = self
            .manager
            .upload_attachments(vec![(spec, bytes)])
            .await?
            .into_iter()
            .next()
            .ok_or_else(|| RpcError::failed("sticker upload failed"))?
            .map_err(|e| RpcError::failed(format!("sticker upload failed: {e}")))?;
        Ok(Sticker {
            pack_id: Some(pack.id.clone()),
            pack_key: Some(pack.key.clone()),
            sticker_id: Some(sticker_id),
            data: Some(pointer),
            emoji: sticker.emoji.clone(),
        })
    }
}

/// Downloads a pack's manifest and images from the sticker CDN and stores it. Like presage's
/// install_sticker_pack, but without telling the other devices: this pack comes from the
/// storage service, the phone has it already. The websocket is only a carrier for its CDN
/// access; the sticker endpoints are plain, unauthenticated CDN GETs.
async fn download_pack(ws: &mut SignalWebSocket<Identified>, store: &SqliteStore, pack: &StickerPackSync) -> anyhow::Result<()> {
    let mut ciphertext = Vec::new();
    ws.get_sticker_pack_manifest(&hex(&pack.id))
        .await?
        .read_to_end(&mut ciphertext)
        .await?;
    let mut manifest = decrypt_manifest(&mut ciphertext, &pack.key)?;
    for sticker in &mut manifest.stickers {
        match sticker_image(ws, &pack.id, &pack.key, sticker.id).await {
            Ok(bytes) => sticker.bytes = Some(bytes),
            Err(e) => warn!(sticker = sticker.id, %e, "cannot download a sticker image"),
        }
    }
    let mut store = store.clone();
    store
        .add_sticker_pack(&StickerPack { id: pack.id.to_vec(), key: pack.key.to_vec(), manifest })
        .await?;
    Ok(())
}

/// Decrypts a manifest from the sticker CDN (AES-256-CBC with the key from the pack key, MAC
/// checked, like every attachment) and decodes it.
fn decrypt_manifest(ciphertext: &mut Vec<u8>, pack_key: &[u8]) -> anyhow::Result<StickerPackManifest> {
    let key = derive_key(pack_key)?;
    decrypt_in_place(key, ciphertext)?;
    Ok(Pack::decode(ciphertext.as_slice())?.into())
}

/// One sticker image, decrypted with the pack key.
async fn sticker_image(
    ws: &mut SignalWebSocket<Identified>,
    pack_id: &[u8],
    pack_key: &[u8],
    sticker_id: u32,
) -> anyhow::Result<Vec<u8>> {
    let mut ciphertext = Vec::new();
    ws.get_sticker(&hex(pack_id), sticker_id)
        .await?
        .read_to_end(&mut ciphertext)
        .await?;
    let key = derive_key(pack_key)?;
    decrypt_in_place(key, &mut ciphertext)?;
    Ok(ciphertext)
}

#[cfg(test)]
mod tests {
    use super::*;
    use presage::libsignal_service::attachment_cipher::encrypt_in_place;
    use presage::libsignal_service::proto::pack;

    #[test]
    fn pack_links() {
        let (id, key) = parse_pack_uri("https://signal.art/addstickers/#pack_id=0a1b&pack_key=ff00").unwrap();
        assert_eq!(id, [0x0a, 0x1b]);
        assert_eq!(key, [0xff, 0x00]);
        assert!(parse_pack_uri("https://signal.art/addstickers/#pack_id=0a1b").is_none());
        assert!(parse_pack_uri("https://example.org").is_none());
        assert!(parse_pack_uri("https://signal.art/addstickers/#pack_id=0g&pack_key=00").is_none());
        assert_eq!(received_sticker_file(&[1, 2], 3), "sticker-0102-3");
    }

    /// A manifest as the sticker CDN serves it, decrypted and decoded the way download_pack does.
    #[test]
    fn manifest_round_trip() {
        let pack_key = [42u8; 32];
        let mut ciphertext = Pack {
            title: Some("Test pack".into()),
            author: Some("corvus-cli".into()),
            cover: None,
            stickers: vec![pack::Sticker {
                id: Some(7),
                emoji: Some("😀".into()),
                content_type: Some("image/webp".into()),
            }],
        }
        .encode_to_vec();
        encrypt_in_place([9u8; 16], derive_key(&pack_key).unwrap(), &mut ciphertext);

        let manifest = decrypt_manifest(&mut ciphertext, &pack_key).unwrap();
        assert_eq!(manifest.title, "Test pack");
        assert_eq!(manifest.author, "corvus-cli");
        assert_eq!(manifest.stickers.len(), 1);
        assert_eq!(manifest.stickers[0].id, 7);
        assert_eq!(manifest.stickers[0].emoji.as_deref(), Some("😀"));
        assert_eq!(manifest.stickers[0].content_type.as_deref(), Some("image/webp"));
        assert!(manifest.stickers[0].bytes.is_none());
    }

    /// Another pack key must not decrypt the manifest (MAC check).
    #[test]
    fn manifest_with_wrong_key_fails() {
        let mut ciphertext = Pack { stickers: vec![], ..Default::default() }.encode_to_vec();
        encrypt_in_place([9u8; 16], derive_key(&[42u8; 32]).unwrap(), &mut ciphertext);
        assert!(decrypt_manifest(&mut ciphertext, &[1u8; 32]).is_err());
        // And garbage from the CDN fails as well.
        let mut junk = vec![0u8; 100];
        assert!(decrypt_manifest(&mut junk, &[1u8; 32]).is_err());
    }
}
