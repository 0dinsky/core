//! Cryptographic key module.

use std::collections::BTreeMap;
use std::fmt::{self, Write as _};
use std::io::Cursor;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context as _, Result, bail, ensure};
use base64::Engine as _;
use deltachat_contact_tools::EmailAddress;
use pgp::composed::{Deserializable, SignedKeyDetails};
pub use pgp::composed::{SignedPublicKey, SignedSecretKey};
use pgp::crypto::aead::AeadAlgorithm;
use pgp::crypto::hash::HashAlgorithm;
use pgp::crypto::sym::SymmetricKeyAlgorithm;
use pgp::packet::{
    Features, KeyFlags, Notation, PacketTrait as _, SignatureConfig, SignatureType, Subpacket,
    SubpacketData,
};
use pgp::ser::Serialize;
use pgp::types::{CompressionAlgorithm, KeyDetails, KeyVersion};
use rand_old::thread_rng;
use tokio::runtime::Handle;

use crate::config::Config;
use crate::context::Context;
use crate::events::EventType;
use crate::log::LogExt;
use crate::tools::{self, time_elapsed};

/// Convenience trait for working with keys.
///
/// This trait is implemented for rPGP's [SignedPublicKey] and
/// [SignedSecretKey] types and makes working with them a little
/// easier in the deltachat world.
pub trait DcKey: Serialize + Deserializable + Clone {
    /// Create a key from some bytes.
    fn from_slice(bytes: &[u8]) -> Result<Self> {
        let res = <Self as Deserializable>::from_bytes(Cursor::new(bytes));
        if let Ok(res) = res {
            return Ok(res);
        }

        // Workaround for keys imported using
        // Delta Chat core < 1.0.0.
        // Old Delta Chat core had a bug
        // that resulted in treating CRC24 checksum
        // as part of the key when reading ASCII Armor.
        // Some users that started using Delta Chat in 2019
        // have such corrupted keys with garbage bytes at the end.
        //
        // Garbage is at least 3 bytes long
        // and may be longer due to padding
        // at the end of the real key data
        // and importing the key multiple times.
        //
        // If removing 10 bytes is not enough,
        // the key is likely actually corrupted.
        for garbage_bytes in 3..std::cmp::min(bytes.len(), 10) {
            let res = <Self as Deserializable>::from_bytes(Cursor::new(
                bytes
                    .get(..bytes.len().saturating_sub(garbage_bytes))
                    .unwrap_or_default(),
            ));
            if let Ok(res) = res {
                return Ok(res);
            }
        }

        // Removing garbage bytes did not help, return the error.
        Ok(res?)
    }

    /// Create a key from a base64 string.
    fn from_base64(data: &str) -> Result<Self> {
        // strip newlines and other whitespace
        let cleaned: String = data.split_whitespace().collect();
        let bytes = base64::engine::general_purpose::STANDARD.decode(cleaned.as_bytes())?;
        Self::from_slice(&bytes)
    }

    /// Create a key from an ASCII-armored string.
    fn from_asc(data: &str) -> Result<Self> {
        let bytes = data.as_bytes();
        let res = Self::from_armor_single(Cursor::new(bytes));
        let (key, _headers) = match res {
            Err(pgp::errors::Error::NoMatchingPacket { .. }) => match Self::is_private() {
                true => bail!("No private key packet found"),
                false => bail!("No public key packet found"),
            },
            _ => res.context("rPGP error")?,
        };
        Ok(key)
    }

    /// Serialise the key as bytes.
    fn to_bytes(&self) -> Vec<u8> {
        // Not using Serialize::to_bytes() to make clear *why* it is
        // safe to ignore this error.
        // Because we write to a Vec<u8> the io::Write impls never
        // fail and we can hide this error.
        let mut buf = Vec::new();
        self.to_writer(&mut buf).unwrap();
        buf
    }

    /// Serialise the key to a base64 string.
    fn to_base64(&self) -> String {
        base64::engine::general_purpose::STANDARD.encode(DcKey::to_bytes(self))
    }

    /// Serialise the key to ASCII-armored representation.
    ///
    /// Each header line must be terminated by `\r\n`.  Only allows setting one
    /// header as a simplification since that's the only way it's used so far.
    // Since .to_armored_string() are actual methods on SignedPublicKey and
    // SignedSecretKey we can not generically implement this.
    fn to_asc(&self, header: Option<(&str, &str)>) -> String;

    /// The fingerprint for the key.
    fn dc_fingerprint(&self) -> Fingerprint;

    /// Whether the key is private (or public).
    fn is_private() -> bool;
}

/// Converts secret key to public key.
pub(crate) fn secret_key_to_public_key(
    context: &Context,
    mut signed_secret_key: SignedSecretKey,
    timestamp: u32,
    addr: &str,
    relay_addrs: &str,
) -> Result<SignedPublicKey> {
    info!(context, "Converting secret key to public key.");

    // Make sure timestamp of created signatures
    // is not in the past compared to the primary key timestamp.
    let timestamp = std::cmp::max(
        signed_secret_key.primary_key.created_at(),
        pgp::types::Timestamp::from_secs(timestamp),
    );

    // Subpackets that we want to share between DKS and User ID signature.
    let common_subpackets = || -> Result<Vec<Subpacket>> {
        let keyflags = {
            let mut keyflags = KeyFlags::default();
            keyflags.set_certify(true);
            keyflags.set_sign(true);
            keyflags
        };
        let features = {
            let mut features = Features::default();
            features.set_seipd_v1(true);
            features.set_seipd_v2(true);
            features
        };

        Ok(vec![
            Subpacket::regular(SubpacketData::SignatureCreationTime(timestamp))?,
            Subpacket::regular(SubpacketData::IssuerFingerprint(
                signed_secret_key.fingerprint(),
            ))?,
            Subpacket::regular(SubpacketData::KeyFlags(keyflags))?,
            Subpacket::regular(SubpacketData::Features(features))?,
            Subpacket::regular(SubpacketData::PreferredSymmetricAlgorithms(smallvec![
                SymmetricKeyAlgorithm::AES256,
                SymmetricKeyAlgorithm::AES192,
                SymmetricKeyAlgorithm::AES128
            ]))?,
            Subpacket::regular(SubpacketData::PreferredHashAlgorithms(smallvec![
                HashAlgorithm::Sha256,
                HashAlgorithm::Sha384,
                HashAlgorithm::Sha512,
                HashAlgorithm::Sha224,
            ]))?,
            Subpacket::regular(SubpacketData::PreferredCompressionAlgorithms(smallvec![
                CompressionAlgorithm::ZLIB,
                CompressionAlgorithm::ZIP,
            ]))?,
            Subpacket::regular(SubpacketData::PreferredAeadAlgorithms(smallvec![(
                SymmetricKeyAlgorithm::AES256,
                AeadAlgorithm::Ocb
            )]))?,
            Subpacket::regular(SubpacketData::IsPrimary(true))?,
        ])
    };

    // RFC 4880 required that Transferrable Public Key (aka OpenPGP Certificate)
    // contains at least one User ID:
    // <https://www.rfc-editor.org/rfc/rfc4880#section-11.1>
    // RFC 9580 does not require User ID even for V4 certificates anymore:
    // <https://www.rfc-editor.org/rfc/rfc9580.html#name-openpgp-version-4-certifica>
    //
    // We do not use and do not expect User ID in any keys,
    // but nevertheless include User ID in V4 keys for compatibility with clients that follow RFC 4880.
    // RFC 9580 also recommends including User ID into V4 keys:
    // <https://www.rfc-editor.org/rfc/rfc9580.html#section-5.2.3.10-8>
    //
    // We do not support keys older than V4 and are not going
    // to include User ID in newer V6 keys as all clients that support V6
    // should support keys without User ID.
    let users = if signed_secret_key.version() == KeyVersion::V4 {
        let user_id = format!("<{addr}>");

        let mut rng = thread_rng();
        // Self-signature is a "positive certification",
        // see <https://www.ietf.org/archive/id/draft-gallagher-openpgp-signatures-02.html#name-certification-signature-typ>.
        let mut user_id_signature_config = SignatureConfig::from_key(
            &mut rng,
            &signed_secret_key.primary_key,
            SignatureType::CertPositive,
        )?;
        user_id_signature_config.hashed_subpackets = common_subpackets()?;
        user_id_signature_config.unhashed_subpackets = vec![Subpacket::regular(
            SubpacketData::IssuerKeyId(signed_secret_key.legacy_key_id()),
        )?];
        let user_id_packet =
            pgp::packet::UserId::from_str(pgp::types::PacketHeaderVersion::New, &user_id)?;
        let signature = user_id_signature_config.sign_certification(
            &signed_secret_key.primary_key,
            &signed_secret_key.primary_key.public_key(),
            &pgp::types::Password::empty(),
            user_id_packet.tag(),
            &user_id_packet,
        )?;
        vec![user_id_packet.into_signed(signature)]
    } else {
        vec![]
    };

    let direct_signatures = {
        let mut rng = thread_rng();
        let mut direct_key_signature_config = SignatureConfig::from_key(
            &mut rng,
            &signed_secret_key.primary_key,
            SignatureType::Key,
        )?;
        direct_key_signature_config.hashed_subpackets = common_subpackets()?;
        let notation = Notation {
            readable: true,
            name: "relays@chatmail.at".into(),
            value: relay_addrs.to_string().into(),
        };
        direct_key_signature_config
            .hashed_subpackets
            .push(Subpacket::regular(SubpacketData::Notation(notation))?);
        let direct_key_signature = direct_key_signature_config.sign_key(
            &signed_secret_key.primary_key,
            &pgp::types::Password::empty(),
            signed_secret_key.primary_key.public_key(),
        )?;
        vec![direct_key_signature]
    };

    signed_secret_key.details = SignedKeyDetails {
        revocation_signatures: vec![],
        direct_signatures,
        users,
        user_attributes: vec![],
    };

    Ok(signed_secret_key.to_public_key())
}

/// Attempts to load own public key.
///
/// Returns `None` if no secret key is generated yet.
pub(crate) async fn load_self_public_key_opt(context: &Context) -> Result<Option<SignedPublicKey>> {
    let mut lock = context.self_public_key.lock().await;

    if let Some(ref public_key) = *lock {
        return Ok(Some(public_key.clone()));
    }

    let Some(secret_key_bytes) = context
        .sql
        .query_row_optional(
            "SELECT private_key
             FROM keypairs
             WHERE id=(SELECT value FROM config WHERE keyname='key_id')",
            (),
            |row| {
                let bytes: Vec<u8> = row.get(0)?;
                Ok(bytes)
            },
        )
        .await?
    else {
        return Ok(None);
    };
    let signed_secret_key = SignedSecretKey::from_slice(&secret_key_bytes)?;
    let timestamp = context
        .sql
        .query_get_value::<u32>(
            "SELECT MAX(timestamp)
             FROM (SELECT add_timestamp AS timestamp
                   FROM transports
                   UNION ALL
                   SELECT remove_timestamp AS timestamp
                   FROM removed_transports)",
            (),
        )
        .await?
        .context("No transports configured")?;
    let addr = context.get_primary_self_addr().await?;
    let all_addrs = context.get_published_self_addrs().await?.join(",");
    let signed_public_key =
        secret_key_to_public_key(context, signed_secret_key, timestamp, &addr, &all_addrs)?;
    *lock = Some(signed_public_key.clone());

    Ok(Some(signed_public_key))
}

/// Returns which algorithm family (classic or post-quantum) our own current
/// encryption subkey uses, for display in settings/account UI (e.g. "Your
/// key: Post-quantum").
///
/// Returns `None` if we don't have a key yet (it hasn't been generated,
/// e.g. because no message was sent or received yet).
pub async fn self_encryption_kind(context: &Context) -> Result<Option<crate::pgp::EncryptionKind>> {
    let Some(public_key) = load_self_public_key_opt(context).await? else {
        return Ok(None);
    };
    Ok(crate::pgp::encryption_kind(&public_key))
}

/// Loads own public key.
///
/// If no key is generated yet, generates a new one.
pub(crate) async fn load_self_public_key(context: &Context) -> Result<SignedPublicKey> {
    match load_self_public_key_opt(context).await? {
        Some(public_key) => Ok(public_key),
        None => {
            generate_keypair(context).await?;
            let public_key = load_self_public_key_opt(context)
                .await?
                .context("Secret key generated, but public key cannot be created")?;
            Ok(public_key)
        }
    }
}

/// Ensures a private key exists for the configured user.
///
/// Normally the private key is generated when the first message is
/// sent but in a few locations there are no such guarantees,
/// e.g. when exporting keys, and calling this function ensures a
/// private key will be present.
pub async fn ensure_secret_key_exists(context: &Context) -> Result<()> {
    load_self_public_key(context).await?;
    Ok(())
}

/// Returns our own public keyring.
///
/// No keys are generated and at most one key is returned.
pub(crate) async fn load_self_public_keyring(context: &Context) -> Result<Vec<SignedPublicKey>> {
    if let Some(public_key) = load_self_public_key_opt(context).await? {
        Ok(vec![public_key])
    } else {
        Ok(vec![])
    }
}

/// Returns own public key fingerprint in (not human-readable) hex representation.
/// This is the fingerprint format that is used in the database.
///
/// If no key is generated yet, generates a new one.
///
/// For performance reasons, the fingerprint is cached after the first invocation.
/// The cache is invalidated by [`rotate_self_keypair`] when the active key changes.
pub(crate) async fn self_fingerprint(context: &Context) -> Result<String> {
    let mut lock = context.self_fingerprint.lock().await;
    if let Some(ref fp) = *lock {
        Ok(fp.clone())
    } else {
        let fp = load_self_public_key(context).await?.dc_fingerprint().hex();
        *lock = Some(fp.clone());
        Ok(fp)
    }
}

/// Returns own public key fingerprint in (not human-readable) hex representation.
/// This is the fingerprint format that is used in the database.
///
/// Returns `None` if no key is generated yet.
///
/// For performance reasons, the fingerprint is cached after the first invocation.
/// The cache is invalidated by [`rotate_self_keypair`] when the active key changes.
pub(crate) async fn self_fingerprint_opt(context: &Context) -> Result<Option<String>> {
    let mut lock = context.self_fingerprint.lock().await;
    if let Some(ref fp) = *lock {
        Ok(Some(fp.clone()))
    } else if let Some(key) = load_self_public_key_opt(context).await? {
        let fp = key.dc_fingerprint().hex();
        *lock = Some(fp.clone());
        Ok(Some(fp))
    } else {
        Ok(None)
    }
}

pub(crate) async fn load_self_secret_key(context: &Context) -> Result<SignedSecretKey> {
    let private_key = context
        .sql
        .query_row_optional(
            "SELECT private_key
             FROM keypairs
             WHERE id=(SELECT value FROM config WHERE keyname='key_id')",
            (),
            |row| {
                let bytes: Vec<u8> = row.get(0)?;
                Ok(bytes)
            },
        )
        .await?;
    match private_key {
        Some(bytes) => SignedSecretKey::from_slice(&bytes),
        None => {
            let secret = generate_keypair(context).await?;
            Ok(secret)
        }
    }
}

pub(crate) async fn load_self_secret_keyring(context: &Context) -> Result<Vec<SignedSecretKey>> {
    let keys = context
        .sql
        .query_map_vec(
            r#"SELECT private_key
               FROM keypairs
               ORDER BY id=(SELECT value FROM config WHERE keyname='key_id') DESC"#,
            (),
            |row| {
                let bytes: Vec<u8> = row.get(0)?;
                Ok(bytes)
            },
        )
        .await?
        .into_iter()
        .filter_map(|bytes| SignedSecretKey::from_slice(&bytes).log_err(context).ok())
        .collect();
    Ok(keys)
}

/// Select a signing key: PQ when `prefer_pq`, otherwise classic.
/// Falls back to active key if the preferred family is missing.
pub(crate) async fn load_signing_secret_key(
    context: &Context,
    prefer_pq: bool,
) -> Result<SignedSecretKey> {
    let keys = load_self_secret_keyring(context).await?;
    if keys.is_empty() {
        return load_self_secret_key(context).await;
    }
    let mut classic = None;
    let mut pq = None;
    for key in &keys {
        if crate::pgp::is_pq_signing_secret(key) {
            if pq.is_none() {
                pq = Some(key.clone());
            }
        } else if classic.is_none() {
            classic = Some(key.clone());
        }
    }
    if prefer_pq {
        if let Some(k) = pq {
            return Ok(k);
        }
        if let Some(k) = classic {
            return Ok(k);
        }
    } else if let Some(k) = classic {
        return Ok(k);
    } else if let Some(k) = pq {
        info!(
            context,
            "No classic signing key; signing with PQ key (classic peers will not verify)."
        );
        return Ok(k);
    }
    load_self_secret_key(context).await
}


impl DcKey for SignedPublicKey {
    fn to_asc(&self, header: Option<(&str, &str)>) -> String {
        // Not using .to_armored_string() to make clear *why* it is
        // safe to ignore this error.
        // Because we write to a Vec<u8> the io::Write impls never
        // fail and we can hide this error.
        let headers =
            header.map(|(key, value)| BTreeMap::from([(key.to_string(), vec![value.to_string()])]));
        let mut buf = Vec::new();
        self.to_armored_writer(&mut buf, headers.as_ref().into())
            .unwrap_or_default();
        std::string::String::from_utf8(buf).unwrap_or_default()
    }

    fn is_private() -> bool {
        false
    }

    fn dc_fingerprint(&self) -> Fingerprint {
        self.fingerprint().into()
    }
}

impl DcKey for SignedSecretKey {
    fn to_asc(&self, header: Option<(&str, &str)>) -> String {
        // Not using .to_armored_string() to make clear *why* it is
        // safe to do these unwraps.
        // Because we write to a Vec<u8> the io::Write impls never
        // fail and we can hide this error.  The string is always ASCII.
        let headers =
            header.map(|(key, value)| BTreeMap::from([(key.to_string(), vec![value.to_string()])]));
        let mut buf = Vec::new();
        self.to_armored_writer(&mut buf, headers.as_ref().into())
            .unwrap_or_default();
        std::string::String::from_utf8(buf).unwrap_or_default()
    }

    fn is_private() -> bool {
        true
    }

    fn dc_fingerprint(&self) -> Fingerprint {
        self.fingerprint().into()
    }
}

async fn generate_keypair(context: &Context) -> Result<SignedSecretKey> {
    let addr = context.get_primary_self_addr().await?;
    let addr = EmailAddress::new(&addr)?;
    let _public_key_guard = context.self_public_key.lock().await;

    // Check if the key appeared while we were waiting on the lock.
    match load_keypair(context).await? {
        Some(key_pair) => Ok(key_pair),
        None => {
            let start = tools::Time::now();

            // Determine key generation mode:
            //   0 (default) — Classic: Ed25519Legacy + Curve25519 (OpenPGP v4)
            //   1           — Post-quantum hybrid: ML-DSA-65+Ed25519 + ML-KEM-768+X25519 (OpenPGP v6)
            let key_gen_mode = context.get_config_int(Config::KeyGenMode).await?;

            if key_gen_mode == 1 {
                info!(
                    context,
                    "Generating PQ keypair (ML-DSA-65+Ed25519 + ML-KEM-768+X25519, OpenPGP v6)."
                );
            } else {
                info!(context, "Generating classic keypair (Ed25519 + Curve25519).");
            }

            // One keypair only. Previously mode=1 also inserted an orphan classic
            // key "as fallback" without setting key_id; that left a dead row in
            // `keypairs` and did not help decryption (the active key is the PQ one).
            // Classic peers already interoperate via the X25519 half of the hybrid KEM.
            let keypair = Handle::current()
                .spawn_blocking(move || {
                    if key_gen_mode == 1 {
                        crate::pgp::create_pqc_keypair(addr)
                    } else {
                        crate::pgp::create_keypair(addr)
                    }
                })
                .await??;

            store_self_keypair(context, &keypair).await?;
            info!(
                context,
                "Keypair generated in {:.3}s.",
                time_elapsed(&start).as_secs(),
            );
            Ok(keypair)
        }
    }
}

pub(crate) async fn load_keypair(context: &Context) -> Result<Option<SignedSecretKey>> {
    let res = context
        .sql
        .query_row_optional(
            "SELECT private_key
                 FROM keypairs
                 WHERE id=(SELECT value FROM config WHERE keyname='key_id')",
            (),
            |row| {
                let sec_bytes: Vec<u8> = row.get(0)?;
                Ok(sec_bytes)
            },
        )
        .await?;

    let signed_secret_key = if let Some(sec_bytes) = res {
        Some(SignedSecretKey::from_slice(&sec_bytes)?)
    } else {
        None
    };

    Ok(signed_secret_key)
}

/// Stores own keypair in the database and sets it as a default.
///
/// Fails if we already have a key, so it is not possible to
/// have more than one key for new setups. Existing setups
/// may still have more than one key for compatibility.
pub(crate) async fn store_self_keypair(
    context: &Context,
    signed_secret_key: &SignedSecretKey,
) -> Result<()> {
    // This public key is stored in the database
    // only for backwards compatibility.
    //
    // It should not be used e.g. in Autocrypt headers or vCards.
    // Use `secret_key_to_public_key()` function instead,
    // which adds relay list to the signature.
    let signed_public_key = signed_secret_key.to_public_key();
    let mut config_cache_lock = context.sql.config_cache.write().await;
    let new_key_id = context
        .sql
        .transaction(|transaction| {
            let public_key = DcKey::to_bytes(&signed_public_key);
            let secret_key = DcKey::to_bytes(signed_secret_key);

            // private_key and public_key columns
            // are UNIQUE since migration 107,
            // so this fails if we already have this key.
            transaction
                .execute(
                    "INSERT INTO keypairs (public_key, private_key, created)
                     VALUES (?,?,?)",
                    (&public_key, &secret_key, tools::time()),
                )
                .context("Failed to insert keypair")?;

            let new_key_id = transaction.last_insert_rowid();

            // This will fail if we already have `key_id`.
            //
            // Setting default key is only possible if we don't
            // have a key already.
            transaction.execute(
                "INSERT INTO config (keyname, value) VALUES ('key_id', ?)",
                (new_key_id,),
            )?;
            Ok(new_key_id)
        })
        .await?;
    context.emit_event(EventType::AccountsItemChanged);
    config_cache_lock.insert("key_id".to_string(), Some(new_key_id.to_string()));
    Ok(())
}

/// Saves a keypair as the default keys.
///
/// This API is used for testing purposes
/// to avoid generating the key in tests.
/// Use import/export APIs instead.
pub async fn preconfigure_keypair(context: &Context, secret_data: &str) -> Result<()> {
    let secret = SignedSecretKey::from_asc(secret_data)?;
    store_self_keypair(context, &secret).await?;
    Ok(())
}

/// How long, in days, to keep *full keypair rows* that are no longer the
/// active key, before deleting them from the `keypairs` table.
///
/// These rows are redundant once the current key already embeds the old
/// encryption subkeys (see `rotate_encryption_subkey`). Deleting them is
/// relatively safe: decryption still walks the full keyring and the current
/// key continues to hold the recent subkey secrets until the longer
/// [`KEY_FORGET_SUBKEY_GRACE_DAYS`] window elapses.
const KEY_ROTATION_ROW_GRACE_DAYS: i64 = 14;

/// How long, in days, to keep the **secret material** of old encryption
/// subkeys that are still embedded inside the *current* key, before
/// permanently forgetting them via
/// [`crate::pgp::forget_expired_encryption_subkeys`].
///
/// This window must be long enough for:
/// - messages already in flight (slow relays, offline recipients);
/// - second devices that have not yet been re-synced / re-exported after a
///   rotation (Autocrypt Setup Message / QR only transfers the *current*
///   key — if recent subkeys were already forgotten, those devices lose
///   the ability to decrypt mail encrypted to them).
///
/// OpenPGP has no native PFS. A short grace looks good on paper and breaks
/// multi-device in practice. Prefer weeks, not days. The forget step also
/// always retains at least the newest two encryption subkeys regardless of
/// age (see `MIN_RETAINED_ENCRYPTION_SUBKEYS` in `pgp.rs`).
const KEY_FORGET_SUBKEY_GRACE_DAYS: i64 = 30;

/// If `Config::KeyRotationPeriod` is set and our current key is older than
/// that many days, rotates the encryption subkey (or, when switching
/// classic ↔ post-quantum primary, generates a whole new keypair) and makes
/// the result the active key.
///
/// Also:
/// 1. Deletes *old keypair rows* past [`KEY_ROTATION_ROW_GRACE_DAYS`].
/// 2. Forgets encryption-subkey secrets embedded in the *current* key past
///    [`KEY_FORGET_SUBKEY_GRACE_DAYS`], while always keeping the newest few
///    (multi-device safety floor).
///
/// `rotate_encryption_subkey` folds every previous encryption subkey into
/// each new key it produces so in-flight messages and lagging second
/// devices keep decrypting across a rotation. Those old subkeys would
/// otherwise survive inside the current key forever unless pruned here.
/// Without the forget step, deleting old `keypairs` rows only removes
/// redundant snapshots — the current key would still decrypt with
/// arbitrarily old subkey material.
///
/// When only the encryption subkey is rotated the primary fingerprint
/// (and therefore Verified status at contacts) stays stable. A full
/// classic↔PQ primary switch does change the fingerprint and requires
/// re-verification.
///
/// ## Multi-device
///
/// Private keys are transferred to a second device via Autocrypt Setup
/// Message / QR ("Add as second device"). Only the **current** key is
/// exported. As long as that key still contains recent encryption subkeys,
/// the second device can decrypt recent history. Aggressive forget would
/// leave second devices unable to decrypt — do not shorten
/// [`KEY_FORGET_SUBKEY_GRACE_DAYS`] without a coordinated multi-device key
/// sync protocol. After a rotation, re-exporting to secondary devices
/// before the forget window closes keeps them able to read new mail.
pub(crate) async fn maybe_rotate_keypair(context: &Context) -> Result<()> {
    let now = tools::time();

    let period_days = context.get_config_int(Config::KeyRotationPeriod).await?;
    if period_days > 0 {
        let current_key_created: Option<i64> = context
            .sql
            .query_row_optional(
                "SELECT created FROM keypairs
                 WHERE id=(SELECT value FROM config WHERE keyname='key_id')",
                (),
                |row| row.get(0),
            )
            .await?;

        // A `created` of 0 means this key predates the column being
        // populated; treat that the same as "just generated" rather than
        // "infinitely old" so we don't force an immediate rotation on
        // every existing account the first time this code runs.
        let age_days = match current_key_created {
            Some(created) if created > 0 => (now - created) / 86_400,
            _ => 0,
        };

        if age_days >= i64::from(period_days) {
            let key_gen_mode = context.get_config_int(Config::KeyGenMode).await?;
            info!(
                context,
                "Rotating encryption subkey (age {age_days} days >= period {period_days} days, mode={key_gen_mode})."
            );
            let addr = context.get_primary_self_addr().await?;
            let addr = EmailAddress::new(&addr)?;
            // Prefer subkey-only rotation so the primary fingerprint (and
            // Verified status for our contacts) stays stable.
            let current = load_self_secret_key(context).await?;
            let want_pq = key_gen_mode == 1;
            let current_is_pq = crate::pgp::is_pq_signing_secret(&current);
            let new_key = if want_pq == current_is_pq {
                // Same primary family → rotate only encryption subkey.
                Handle::current()
                    .spawn_blocking(move || {
                        crate::pgp::rotate_encryption_subkey(&current, addr, want_pq)
                    })
                    .await??
            } else {
                // Switching classic ↔ PQ primary: full new keypair (fingerprint changes).
                Handle::current()
                    .spawn_blocking(move || {
                        if want_pq {
                            crate::pgp::create_pqc_keypair(addr)
                        } else {
                            crate::pgp::create_keypair(addr)
                        }
                    })
                    .await??
            };
            rotate_self_keypair(context, &new_key).await?;
        }
    }

    // 1) Delete old *keypair rows* that are past the shorter row-grace.
    //    These are full snapshots that became redundant once the current
    //    key already embeds the previous encryption subkeys. Decryption
    //    still uses the full keyring + the current key's embedded secrets.
    let row_cutoff = now - KEY_ROTATION_ROW_GRACE_DAYS * 86_400;
    let deleted = context
        .sql
        .execute(
            "DELETE FROM keypairs
             WHERE id != (SELECT value FROM config WHERE keyname='key_id')
               AND created > 0
               AND created < ?",
            (row_cutoff,),
        )
        .await?;
    if deleted > 0 {
        info!(
            context,
            "Erased {deleted} rotated-out keypair row(s) past their {KEY_ROTATION_ROW_GRACE_DAYS}-day grace."
        );
    }

    // 2) Forget encryption-subkey *secrets* embedded in the current key,
    //    but only after the longer multi-device-safe window. The helper
    //    always keeps at least the newest two subkeys regardless of age.
    let forget_cutoff_secs = now - KEY_FORGET_SUBKEY_GRACE_DAYS * 86_400;
    let forget_cutoff = UNIX_EPOCH + Duration::from_secs(forget_cutoff_secs.max(0) as u64);
    let current = load_self_secret_key(context).await?;
    let subkeys_before = current.secret_subkeys.len();
    let pruned = Handle::current()
        .spawn_blocking(move || {
            crate::pgp::forget_expired_encryption_subkeys(&current, forget_cutoff)
        })
        .await?;
    // Err = nothing safe to prune yet (under retention floor, still within
    // grace, or no prior rotation) — not a hard failure.
    if let Ok(pruned_key) = pruned {
        let forgotten = subkeys_before.saturating_sub(pruned_key.secret_subkeys.len());
        if forgotten > 0 {
            save_current_keypair(context, &pruned_key).await?;
            info!(
                context,
                "Forgot {forgotten} expired encryption subkey(s) past their {KEY_FORGET_SUBKEY_GRACE_DAYS}-day multi-device-safe grace."
            );
        }
    }

    Ok(())
}

/// Immediately generates a fresh keypair — honoring the current
/// `Config::KeyGenMode` — and makes it the active self key, without waiting
/// for `Config::KeyRotationPeriod` to elapse.
///
/// This is meant to be called right after the user changes `KeyGenMode`
/// (e.g. turns on post-quantum key generation) if they want the change to
/// take effect for their existing account immediately, rather than only for
/// the next account they set up or the next scheduled rotation.
///
/// When only the encryption subkey is rotated the primary fingerprint (and
/// Verified status at contacts) stays stable. Switching classic↔PQ primary
/// still changes the fingerprint and requires re-verify (e.g. by scanning a
/// fresh QR code).
///
/// Old encryption-subkey secrets remain inside the current key for
/// [`KEY_FORGET_SUBKEY_GRACE_DAYS`] (and at least the newest two are always
/// retained) so that in-flight mail and second devices that have not yet
/// been re-exported can still decrypt. Full old keypair rows are dropped
/// after the shorter [`KEY_ROTATION_ROW_GRACE_DAYS`]. After a rotation,
/// re-exporting to secondary devices before the forget window closes keeps
/// multi-device setups able to read new mail.
pub async fn rotate_keypair_now(context: &Context) -> Result<()> {
    let key_gen_mode = context.get_config_int(Config::KeyGenMode).await?;
    let addr = context.get_primary_self_addr().await?;
    let addr = EmailAddress::new(&addr)?;
    info!(
        context,
        "Rotating encryption subkey on demand (key_gen_mode={key_gen_mode})."
    );
    let current = load_self_secret_key(context).await?;
    let want_pq = key_gen_mode == 1;
    let current_is_pq = crate::pgp::is_pq_signing_secret(&current);
    let new_key = if want_pq == current_is_pq {
        Handle::current()
            .spawn_blocking(move || {
                crate::pgp::rotate_encryption_subkey(&current, addr, want_pq)
            })
            .await??
    } else {
        // Mode switch: need a new primary → fingerprint changes, Verified resets.
        info!(
            context,
            "KeyGenMode switch requires new primary key; contacts must re-verify."
        );
        Handle::current()
            .spawn_blocking(move || {
                if want_pq {
                    crate::pgp::create_pqc_keypair(addr)
                } else {
                    crate::pgp::create_keypair(addr)
                }
            })
            .await??
    };
    rotate_self_keypair(context, &new_key).await
}

/// Makes `new_key` the active self key, keeping the previously active key
/// in the `keypairs` table (still usable for decryption via
/// [`load_self_secret_keyring`]) until [`maybe_rotate_keypair`] deletes the
/// row after [`KEY_ROTATION_ROW_GRACE_DAYS`]. Encryption-subkey secrets that
/// were folded into `new_key` by [`crate::pgp::rotate_encryption_subkey`]
/// remain until the longer [`KEY_FORGET_SUBKEY_GRACE_DAYS`] window.
async fn rotate_self_keypair(context: &Context, new_key: &SignedSecretKey) -> Result<()> {
    let signed_public_key = new_key.to_public_key();
    let mut config_cache_lock = context.sql.config_cache.write().await;
    let new_key_id = context
        .sql
        .transaction(|transaction| {
            let public_key = DcKey::to_bytes(&signed_public_key);
            let secret_key = DcKey::to_bytes(new_key);

            transaction
                .execute(
                    "INSERT INTO keypairs (public_key, private_key, created)
                     VALUES (?,?,?)",
                    (&public_key, &secret_key, tools::time()),
                )
                .context("Failed to insert rotated keypair")?;
            let new_key_id = transaction.last_insert_rowid();

            transaction.execute(
                "UPDATE config SET value=? WHERE keyname='key_id'",
                (new_key_id,),
            )?;
            Ok(new_key_id)
        })
        .await?;
    // Invalidate the cached public key / fingerprint so that the new key is
    // picked up immediately (e.g. in the very next Autocrypt header we send),
    // rather than only after the next process restart. Both caches are
    // lazily repopulated from the DB (via `key_id`, which we just updated)
    // on next access.
    *context.self_public_key.lock().await = None;
    *context.self_fingerprint.lock().await = None;
    context.emit_event(EventType::AccountsItemChanged);
    config_cache_lock.insert("key_id".to_string(), Some(new_key_id.to_string()));
    Ok(())
}

/// Overwrites the currently active key's stored bytes in place with `key`,
/// without touching its `created` timestamp or its `keypairs` row id, and
/// without changing which row `key_id` points to.
///
/// Unlike [`rotate_self_keypair`], this does not introduce a new key
/// generation — it's for saving an in-place edit of the current key (e.g.
/// after [`forget_expired_encryption_subkeys`](crate::pgp::forget_expired_encryption_subkeys)
/// pruned some of its embedded subkeys), where inserting a fresh row and
/// old-row grace period would be pointless churn.
async fn save_current_keypair(context: &Context, key: &SignedSecretKey) -> Result<()> {
    let public_key = key.to_public_key();
    let public_key_bytes = DcKey::to_bytes(&public_key);
    let secret_key_bytes = DcKey::to_bytes(key);
    context
        .sql
        .execute(
            "UPDATE keypairs SET public_key=?, private_key=?
             WHERE id=(SELECT value FROM config WHERE keyname='key_id')",
            (&public_key_bytes, &secret_key_bytes),
        )
        .await?;
    // The public key content changed (fewer advertised subkeys) even though
    // the fingerprint didn't — drop the cache so the next Autocrypt header
    // we send reflects it, instead of still advertising a subkey we just
    // threw the secret half of away.
    *context.self_public_key.lock().await = None;
    Ok(())
}

/// A key fingerprint
#[derive(Clone, Eq, PartialEq, Hash, serde::Serialize, serde::Deserialize)]
pub struct Fingerprint(Vec<u8>);

impl Fingerprint {
    /// Creates new fingerprint.
    ///
    /// It is 160-bit (20 bytes) for v4 keys and 32 bytes for v6 keys.
    pub fn new(v: Vec<u8>) -> Fingerprint {
        debug_assert!(v.len() == 20 || v.len() == 32);
        Fingerprint(v)
    }

    /// Make a hex string from the fingerprint.
    ///
    /// Use [std::fmt::Display] or [ToString::to_string] to get a
    /// human-readable formatted string.
    pub fn hex(&self) -> String {
        hex::encode_upper(&self.0)
    }

    /// Make a human-readable fingerprint.
    pub fn human_readable(&self) -> String {
        let mut f = String::new();
        // Split key into chunks of 4 with space and newline at 20 chars
        for (i, c) in self.hex().chars().enumerate() {
            if i > 0 && i % 20 == 0 {
                writeln!(&mut f).ok();
            } else if i > 0 && i % 4 == 0 {
                write!(&mut f, " ").ok();
            }
            write!(&mut f, "{c}").ok();
        }
        f
    }
}

impl From<pgp::types::Fingerprint> for Fingerprint {
    fn from(fingerprint: pgp::types::Fingerprint) -> Fingerprint {
        Self::new(fingerprint.as_bytes().into())
    }
}

impl fmt::Debug for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Fingerprint")
            .field("hex", &self.hex())
            .finish()
    }
}

/// Parse a human-readable or otherwise formatted fingerprint.
impl std::str::FromStr for Fingerprint {
    type Err = anyhow::Error;

    fn from_str(input: &str) -> Result<Self> {
        let hex_repr: String = input
            .to_uppercase()
            .chars()
            .filter(|&c| c.is_ascii_hexdigit())
            .collect();
        let v: Vec<u8> = hex::decode(&hex_repr)?;
        ensure!(
            v.len() == 20 || v.len() == 32,
            "wrong fingerprint length: {hex_repr}"
        );
        let fp = Fingerprint::new(v);
        Ok(fp)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, LazyLock};
    use std::time::Duration;

    use super::*;
    use crate::config::Config;
    use crate::test_utils::{TestContext, TestContextManager, alice_keypair};
    use crate::tools::SystemTime;

    static KEYPAIR: LazyLock<SignedSecretKey> = LazyLock::new(alice_keypair);

    #[test]
    fn test_from_armored_string() {
        let private_key = SignedSecretKey::from_asc(
            "-----BEGIN PGP PRIVATE KEY BLOCK-----

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
7yPJeQ==
=KZk/
-----END PGP PRIVATE KEY BLOCK-----",
        )
        .expect("failed to decode");
        let binary = DcKey::to_bytes(&private_key);
        SignedSecretKey::from_slice(&binary).expect("invalid private key");
    }

    #[test]
    fn test_asc_roundtrip() {
        let key = KEYPAIR.clone().to_public_key();
        let asc = key.to_asc(Some(("spam", "ham")));
        let key2 = SignedPublicKey::from_asc(&asc).unwrap();
        assert_eq!(key, key2);

        let key = KEYPAIR.clone();
        let asc = key.to_asc(Some(("spam", "ham")));
        let key2 = SignedSecretKey::from_asc(&asc).unwrap();
        assert_eq!(key, key2);
    }

    #[test]
    fn test_from_slice_roundtrip() {
        let private_key = KEYPAIR.clone();
        let public_key = KEYPAIR.clone().to_public_key();

        let binary = DcKey::to_bytes(&public_key);
        let public_key2 = SignedPublicKey::from_slice(&binary).expect("invalid public key");
        assert_eq!(public_key, public_key2);

        let binary = DcKey::to_bytes(&private_key);
        let private_key2 = SignedSecretKey::from_slice(&binary).expect("invalid private key");
        assert_eq!(private_key, private_key2);
    }

    #[test]
    fn test_from_slice_bad_data() {
        let mut bad_data: [u8; 4096] = [0; 4096];
        for (i, v) in bad_data.iter_mut().enumerate() {
            *v = (i & 0xff) as u8;
        }
        for j in 0..(4096 / 40) {
            let slice = &bad_data.get(j..j + 4096 / 2 + j).unwrap();
            assert!(SignedPublicKey::from_slice(slice).is_err());
            assert!(SignedSecretKey::from_slice(slice).is_err());
        }
    }

    /// Tests workaround for Delta Chat core < 1.0.0
    /// which parsed CRC24 at the end of ASCII Armor
    /// as the part of the key.
    /// Depending on the alignment and the number of
    /// `=` characters at the end of the key,
    /// this resulted in various number of garbage
    /// octets at the end of the key, starting from 3 octets,
    /// but possibly 4 or 5 and maybe more octets
    /// if the key is imported multiple times.
    #[test]
    fn test_ignore_trailing_garbage() {
        // Test several variants of garbage.
        for garbage in [
            b"\x02\xfc\xaa\x38\x4b\x5c".as_slice(),
            b"\x02\xfc\xaa".as_slice(),
            b"\x01\x02\x03\x04\x05".as_slice(),
        ] {
            let private_key = KEYPAIR.clone();

            let mut binary = DcKey::to_bytes(&private_key);
            binary.extend(garbage);

            let private_key2 =
                SignedSecretKey::from_slice(&binary).expect("Failed to ignore garbage");

            assert_eq!(private_key.dc_fingerprint(), private_key2.dc_fingerprint());
        }
    }

    #[test]
    fn test_base64_roundtrip() {
        let key = KEYPAIR.clone().to_public_key();
        let base64 = key.to_base64();
        let key2 = SignedPublicKey::from_base64(&base64).unwrap();
        assert_eq!(key, key2);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_load_self_generate_public() {
        let t = TestContext::new().await;
        t.set_config(Config::ConfiguredAddr, Some("alice@example.org"))
            .await
            .unwrap();
        let key = load_self_public_key(&t).await;
        assert!(key.is_ok());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_load_self_generate_secret() {
        let t = TestContext::new().await;
        t.set_config(Config::ConfiguredAddr, Some("alice@example.org"))
            .await
            .unwrap();
        let key = load_self_secret_key(&t).await;
        assert!(key.is_ok());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_load_self_generate_concurrent() {
        use std::thread;

        let t = TestContext::new().await;
        t.set_config(Config::ConfiguredAddr, Some("alice@example.org"))
            .await
            .unwrap();
        let thr0 = {
            let ctx = t.clone();
            thread::spawn(move || {
                tokio::runtime::Runtime::new()
                    .unwrap()
                    .block_on(load_self_public_key(&ctx))
            })
        };
        let thr1 = {
            let ctx = t.clone();
            thread::spawn(move || {
                tokio::runtime::Runtime::new()
                    .unwrap()
                    .block_on(load_self_public_key(&ctx))
            })
        };
        let res0 = thr0.join().unwrap();
        let res1 = thr1.join().unwrap();
        assert_eq!(res0.unwrap(), res1.unwrap());
    }

    /// Tests that setting a default key second time is not allowed.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_save_self_key_twice() {
        // Saving the same key twice should result in only one row in
        // the keypairs table.
        let t = TestContext::new().await;
        let ctx = Arc::new(t);

        let nrows = || async {
            ctx.sql
                .count("SELECT COUNT(*) FROM keypairs;", ())
                .await
                .unwrap()
        };
        assert_eq!(nrows().await, 0);
        store_self_keypair(&ctx, &KEYPAIR).await.unwrap();
        assert_eq!(nrows().await, 1);

        // Saving a second key fails.
        let res = store_self_keypair(&ctx, &KEYPAIR).await;
        assert!(res.is_err());

        assert_eq!(nrows().await, 1);
    }

    /// Tests that key signature timestamp
    /// is not in the past compared to the primary key creation timestamp.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_signature_not_in_the_past() -> Result<()> {
        let mut tcm = TestContextManager::new();

        let t = &tcm.unconfigured().await;
        t.configure_addr("foo@example.org").await;

        SystemTime::shift(Duration::from_secs(600));

        let key = load_self_public_key(t).await?;
        assert!(
            key.details.direct_signatures[0].created().unwrap() >= key.primary_key.created_at()
        );

        Ok(())
    }

    #[test]
    fn test_fingerprint_from_str() {
        let res = Fingerprint::new(vec![
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
        ]);

        let fp: Fingerprint = "0102030405060708090A0B0c0d0e0F1011121314".parse().unwrap();
        assert_eq!(fp, res);

        let fp: Fingerprint = "zzzz 0102 0304 0506\n0708090a0b0c0D0E0F1011121314 yyy"
            .parse()
            .unwrap();
        assert_eq!(fp, res);

        assert!("1".parse::<Fingerprint>().is_err());
    }

    #[test]
    fn test_fingerprint_hex() {
        let fp = Fingerprint::new(vec![
            1, 2, 4, 8, 16, 32, 64, 128, 255, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
        ]);
        assert_eq!(fp.hex(), "0102040810204080FF0A0B0C0D0E0F1011121314");
    }

    #[test]
    fn test_fingerprint_to_string() {
        let fp = Fingerprint::new(vec![
            1, 2, 4, 8, 16, 32, 64, 128, 255, 1, 2, 4, 8, 16, 32, 64, 128, 255, 19, 20,
        ]);
        assert_eq!(
            fp.human_readable(),
            "0102 0408 1020 4080 FF01\n0204 0810 2040 80FF 1314"
        );
    }

    mod ensure_secret_key_exists {
        use super::*;

        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn test_prexisting() {
            let t = TestContext::new_alice().await;
            assert!(ensure_secret_key_exists(&t).await.is_ok());
        }

        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn test_not_configured() {
            let t = TestContext::new().await;
            assert!(ensure_secret_key_exists(&t).await.is_err());
        }
    }
}
