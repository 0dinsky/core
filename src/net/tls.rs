//! TLS support.
use parking_lot::Mutex;
use std::collections::HashMap;
use std::sync::Arc;

use anyhow::Result;

use crate::net::session::SessionStream;
use crate::sql::Sql;
use crate::tools::time;

use tokio_rustls::rustls;
use tokio_rustls::rustls::client::ClientSessionStore;
use tokio_rustls::rustls::server::ParsedCertificate;

mod danger;
use danger::CustomCertificateVerifier;

mod spki;
pub use spki::SpkiHashStore;

#[expect(clippy::too_many_arguments)]
pub async fn wrap_tls<'a>(
    strict_tls: bool,
    hostname: &str,
    port: u16,
    use_sni: bool,
    alpn: &str,
    stream: impl SessionStream + 'static,
    tls_session_store: &TlsSessionStore,
    spki_hash_store: &SpkiHashStore,
    sql: &Sql,
) -> Result<impl SessionStream + 'a> {
    if strict_tls {
        let tls_stream = wrap_rustls(
            hostname,
            port,
            use_sni,
            alpn,
            stream,
            tls_session_store,
            spki_hash_store,
            sql,
        )
        .await?;
        let boxed_stream: Box<dyn SessionStream> = Box::new(tls_stream);
        Ok(boxed_stream)
    } else {
        // We use native_tls because it accepts 1024-bit RSA keys.
        // Rustls does not support them even if
        // certificate checks are disabled: <https://github.com/rustls/rustls/issues/234>.
        let alpns = if alpn.is_empty() {
            Box::from([])
        } else {
            Box::from([alpn])
        };
        let tls = async_native_tls::TlsConnector::new()
            .min_protocol_version(Some(async_native_tls::Protocol::Tlsv12))
            .use_sni(use_sni)
            .request_alpns(&alpns)
            .danger_accept_invalid_hostnames(true)
            .danger_accept_invalid_certs(true);
        let tls_stream = tls.connect(hostname, stream).await?;
        let boxed_stream: Box<dyn SessionStream> = Box::new(tls_stream);
        Ok(boxed_stream)
    }
}

/// Map to store TLS session tickets.
///
/// Tickets are separated by port and ALPN
/// to avoid trying to use Postfix ticket for Dovecot and vice versa.
/// Doing so would not be a security issue,
/// but wastes the ticket and the opportunity to resume TLS session unnecessarily.
/// Rustls takes care of separating tickets that belong to different domain names.
#[derive(Debug)]
pub(crate) struct TlsSessionStore {
    sessions: Mutex<HashMap<(u16, String), Arc<dyn ClientSessionStore>>>,
}

// This is the default for TLS session store
// as of Rustls version 0.23.16,
// but we want to create multiple caches
// to separate them by port and ALPN.
const TLS_CACHE_SIZE: usize = 256;

impl TlsSessionStore {
    /// Creates a new TLS session store.
    ///
    /// One such store should be created per profile
    /// to keep TLS sessions independent.
    pub fn new() -> Self {
        Self {
            sessions: Default::default(),
        }
    }

    /// Returns session store for given port and ALPN.
    ///
    /// Rustls additionally separates sessions by hostname.
    pub fn get(&self, port: u16, alpn: &str) -> Arc<dyn ClientSessionStore> {
        Arc::clone(
            self.sessions
                .lock()
                .entry((port, alpn.to_string()))
                .or_insert_with(|| {
                    Arc::new(rustls::client::ClientSessionMemoryCache::new(
                        TLS_CACHE_SIZE,
                    ))
                }),
        )
    }
}

#[expect(clippy::too_many_arguments)]
pub async fn wrap_rustls<'a>(
    hostname: &str,
    port: u16,
    use_sni: bool,
    alpn: &str,
    stream: impl SessionStream + 'a,
    tls_session_store: &TlsSessionStore,
    spki_hash_store: &SpkiHashStore,
    sql: &Sql,
) -> Result<impl SessionStream + 'a> {
    let root_cert_store =
        rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let mut config = rustls::ClientConfig::builder()
        .with_root_certificates(root_cert_store)
        .with_no_client_auth();
    config.alpn_protocols = if alpn.is_empty() {
        vec![]
    } else {
        vec![alpn.as_bytes().to_vec()]
    };

    // ── Perfect Forward Secrecy (PFS) ────────────────────────────────────────
    //
    // TLS 1.3 (the default when using rustls) provides PFS unconditionally:
    // every handshake uses a fresh ephemeral key exchange (X25519 or similar)
    // so that compromise of the server's long-term certificate key cannot
    // retroactively decrypt past sessions.
    //
    // TLS 1.2 session resumption (RFC 5246 / RFC 5077) can weaken PFS by
    // reusing earlier session secrets.  We explicitly disable it below.
    // TLS 1.3 ticket resumption (RFC 8446 §2.2) is safe because it does not
    // reuse the ephemeral key; we keep it enabled to reduce handshake latency
    // on repeated connections to the same IMAP/SMTP server.
    //
    // ── Post-Quantum TLS ──────────────────────────────────────────────────────
    //
    // rustls ≥ 0.23 with the `aws-lc-rs` backend supports the
    // X25519MLKEM768 hybrid group (draft-ietf-tls-hybrid-design).
    // The current build uses the `ring` backend (default-features = false),
    // which does not yet support PQ groups.
    //
    // To enable post-quantum TLS key exchange:
    //   1. Switch `tokio-rustls` to `features = ["aws-lc-rs"]` in Cargo.toml.
    //   2. Remove the `ring` feature if present.
    //   3. Uncomment the line below to add X25519MLKEM768 as the preferred group.
    //
    // config.resumption.tls_kx_groups = vec![
    //     rustls::crypto::aws_lc_rs::kx_group::X25519MLKEM768,
    //     rustls::crypto::aws_lc_rs::kx_group::X25519,
    // ];
    //
    // Classic peers negotiate X25519 as a fallback, so this is backward-compatible.
    let resumption_store = tls_session_store.get(port, alpn);
    let resumption = rustls::client::Resumption::store(resumption_store)
        .tls12_resumption(rustls::client::Tls12Resumption::Disabled);
    config.resumption = resumption;
    config.enable_sni = use_sni;

    config
        .dangerous()
        .set_certificate_verifier(Arc::new(CustomCertificateVerifier::new(
            spki_hash_store.get_spki_hash(hostname, sql).await?,
        )));

    let tls = tokio_rustls::TlsConnector::from(Arc::new(config));
    let name = tokio_rustls::rustls::pki_types::ServerName::try_from(hostname)?.to_owned();
    let tls_stream = tls.connect(name, stream).await?;

    // Successfully connected.
    // Remember SPKI hash to accept it later if certificate expires.
    let (_io, client_connection) = tls_stream.get_ref();
    if let Some(end_entity) = client_connection
        .peer_certificates()
        .and_then(|certs| certs.first())
    {
        let now = time();
        let parsed_certificate = ParsedCertificate::try_from(end_entity)?;
        let spki = parsed_certificate.subject_public_key_info();
        spki_hash_store.save_spki(hostname, &spki, sql, now).await?;
    }

    Ok(tls_stream)
}
