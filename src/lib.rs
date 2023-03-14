#![feature(io_error_more)]
#[macro_use]
extern crate log;
extern crate core;

mod fallback;
mod cell;
mod cert;
mod connection;
mod circuit;
mod stream;
mod net_status;
mod con;
mod auth;
mod http;
pub mod hs;
pub mod storage;

use std::ops::Deref;
use rand::prelude::*;
use futures::StreamExt;
use rsa::PublicKey;
use auth::RsaIdentity;

static PAYLOAD_LEN: usize = 509;
static MAX_RELAY_DATA_LEN: usize = PAYLOAD_LEN - 11;
static VERSIONS: [u16; 2] = [3, 4];
static CIRCUIT_WINDOW_INITIAL: isize = 1000;
static CIRCUIT_WINDOW_INCREMENT: isize = 100;
static STREAM_WINDOW_INITIAL: isize = 500;
static STREAM_WINDOW_INCREMENT: isize = 50;
static DEFAULT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
type Aes128 = ctr::Ctr128BE<aes::Aes128>;
type Aes256 = ctr::Ctr128BE<aes::Aes256>;

type Consensus = std::sync::Arc<tokio::sync::RwLock<Option<net_status::consensus::Consensus>>>;

pub struct Client<S: storage::Storage> {
    storage: std::sync::Arc<S>,
    current_consensus: Consensus,
    ds_circuit: std::sync::Arc<tokio::sync::RwLock<Option<circuit::Circuit>>>,
    hs_relays: std::sync::Arc<tokio::sync::RwLock<Option<hs::HSRelays>>>
}

impl<S: storage::Storage> Clone for Client<S> {
    fn clone(&self) -> Self {
        Self {
            storage: self.storage.clone(),
            current_consensus: self.current_consensus.clone(),
            ds_circuit: self.ds_circuit.clone(),
            hs_relays: self.hs_relays.clone()
        }
    }
}

impl<S: storage::Storage + Send + Sync + 'static> Client<S> {
    pub fn new(storage: S) -> Self {
        Self {
            storage: std::sync::Arc::new(storage),
            current_consensus: std::sync::Arc::new(tokio::sync::RwLock::new(None)),
            ds_circuit: std::sync::Arc::new(tokio::sync::RwLock::new(None)),
            hs_relays: std::sync::Arc::new(tokio::sync::RwLock::new(None))
        }
    }

    pub async fn ready(&self) -> bool {
        self.current_consensus.read().await.is_some()
    }

    pub(crate) async fn consensus(&self) -> std::io::Result<net_status::consensus::Consensus> {
        match self.current_consensus.read().await.deref() {
            Some(c) => Ok(c.clone()),
            None => Err(std::io::Error::new(std::io::ErrorKind::NetworkDown, "Not ready"))
        }
    }

    pub(crate) async fn get_ds_circuit(&self) -> std::io::Result<circuit::Circuit> {
        match self.ds_circuit.read().await.deref() {
            Some(c) => {
                if c.is_open().await {
                    return Ok(c.clone());
                }
            },
            None => {}
        }

        let mut l = self.ds_circuit.write().await;
        let consensus = self.consensus().await?;
        let directory_server = net_status::select_directory_server(&consensus)
            .ok_or(std::io::Error::new(
                std::io::ErrorKind::NotFound, "No suitable directory server found"
            ))?;
        let tcp_stream = con::connect_to_router(directory_server).await?;
        let mut con = connection::Connection::connect(tcp_stream, directory_server.identity).await?;
        let circ = con.create_circuit_fast().await?;
        *l = Some(circ.clone());
        Ok(circ)
    }

    pub(crate) async fn get_hs_relays(&self) -> std::io::Result<hs::HSRelays> {
        match self.hs_relays.read().await.deref() {
            Some(h) => {
                return Ok(h.clone());
            },
            None => {}
        }

        let mut l = self.hs_relays.write().await;
        let dirs = hs::get_hs_dirs(&self).await?;
        *l = Some(dirs.clone());
        Ok(dirs)
    }

    pub async fn run(&mut self) {
        match self.storage.load_consensus().await {
            Ok(mut r) => match net_status::consensus::Consensus::parse(&mut r).await {
                Ok(c) => {
                    let authority_keys = futures::stream::iter( auth::default_authorities())
                        .map(|auth| {
                            let storage = self.storage.clone();
                            async move {
                                let mut kr = match storage.load_dir_key_certificate(auth.id).await {
                                    Ok(kr) => kr,
                                    Err(e) => {
                                        error!("Error loading dir key certificate: {}", e);
                                        return (auth.id, None);
                                    }
                                };

                                let directory_key = match net_status::dir_key_certificate::DirectoryKeyCertificate::parse(&mut kr).await {
                                    Ok(dk) => dk,
                                    Err(e) => {
                                        warn!("Failed to parse directory key for authority {} ({}): {}", auth.name, auth.id, e);
                                        return (auth.id, None);
                                    }
                                };

                                let dk = if !directory_key.verify() {
                                    warn!("Failed to verify stored directory key for {}", auth.name);
                                    None
                                } else if directory_key.fingerprint != auth.id {
                                    warn!("Fingerprint mismatch for {}", auth.name);
                                    None
                                } else {
                                    Some(directory_key)
                                };
                                (auth.id, dk)
                            }
                        }).buffer_unordered(10).collect::<std::collections::HashMap<RsaIdentity, _>>().await;

                    if verify_consensus(&c, &authority_keys) {
                        if c.valid_until < chrono::Utc::now() {
                            warn!("Stored consensus is expired");
                        } else {
                            *self.current_consensus.write().await = Some(c);
                        }
                    } else {
                        error!("Failed to verify stored consensus");
                    }
                }
                Err(e) => {
                    error!("Error parsing stored consensus: {}", e);
                }
            }
            Err(e) => {
                error!("Error loading stored consensus: {}", e);
            }
        }

        let storage = self.storage.clone();
        let consensus = self.current_consensus.clone();
        let hs_relays = self.hs_relays.clone();
        tokio::task::spawn(async move {
            Self::consensus_loop(consensus, hs_relays, storage).await;
        });
    }

    async fn consensus_loop(
        consensus: Consensus,
        hs_relays: std::sync::Arc<tokio::sync::RwLock<Option<hs::HSRelays>>>,
        storage: std::sync::Arc<S>
    ) {
        loop {
            let consensus_is_current = consensus.read().await.as_ref().map_or(false, |consensus| {
                consensus.fresh_until > chrono::Utc::now()
            });
            if !consensus_is_current {
                let (tcp_stream, identity) = match consensus.read().await.deref() {
                    None => {
                        // We have no stored consensus
                        let fallback_dirs = fallback::FallbackDirs::new();
                        let fallback = {
                            let mut rng = thread_rng();
                            fallback_dirs.fallbacks.choose(&mut rng).unwrap()
                        };
                        info!("Using fallback {} for consensus", fallback.id);

                        let tcp_stream = match tokio::time::timeout(
                            DEFAULT_TIMEOUT,
                            con::connect_to_fallback(&fallback)
                        ).await {
                            Ok(Ok(s)) => s,
                            Ok(Err(e)) => {
                                warn!("Failed to connect to fallback {}: {}", fallback.id, e);
                                continue;
                            }
                            Err(_) => {
                                warn!("Timed out connecting to fallback {}", fallback.id);
                                continue;
                            }
                        };

                        (tcp_stream, fallback.id)
                    }
                    Some(c) => {
                        let delay_s = {
                            let mut rng = thread_rng();
                            let half_interval = ((c.fresh_until - c.valid_after) / 2).num_seconds();
                            let unfresh_s = std::cmp::max((chrono::Utc::now() - c.fresh_until).num_seconds(), 0);
                            let max_delay = std::cmp::max(half_interval - unfresh_s, 0);
                            rng.gen_range(0, max_delay+1) as u64
                        };
                        tokio::time::sleep(std::time::Duration::from_secs(delay_s)).await;

                        let directory_server = match net_status::select_directory_server(&c) {
                            Some(ds) => ds,
                            None => {
                                warn!("No directory server available");
                                continue;
                            }
                        };
                        info!("Using directory server {} for consensus", directory_server.identity);

                        let tcp_stream = match tokio::time::timeout(
                            DEFAULT_TIMEOUT,
                            con::connect_to_router(&directory_server)
                        ).await {
                            Ok(Ok(s)) => s,
                            Ok(Err(e)) => {
                                warn!("Failed to connect to router {}: {}", directory_server.identity, e);
                                continue;
                            }
                            Err(_) => {
                                warn!("Timed out connecting to router {}", directory_server.identity);
                                continue;
                            }
                        };

                        (tcp_stream, directory_server.identity)
                    }
                };

                let mut con = match tokio::time::timeout(
                    DEFAULT_TIMEOUT,
                    connection::Connection::connect(tcp_stream, identity)
                ).await {
                    Ok(Ok(c)) => c,
                    Ok(Err(e)) => {
                        warn!("Failed to connect to directory server {}: {}", identity, e);
                        continue;
                    }
                    Err(_) => {
                        warn!("Timed out connecting to directory server {}", identity);
                        continue;
                    }
                };
                let dir_circ = match tokio::time::timeout(
                    DEFAULT_TIMEOUT, con.create_circuit_fast()
                ).await {
                    Ok(Ok(c)) => c,
                    Ok(Err(e)) => {
                        warn!("Failed to create directory circuit: {}", e);
                        continue;
                    }
                    Err(_) => {
                        warn!("Timed out creating directory circuit");
                        continue;
                    }
                };
                let dir_client = http::new_directory_client(dir_circ);

                let authority_keys = futures::stream::iter( auth::default_authorities()).map(|auth| {
                    let dir_client = dir_client.clone();
                    let storage = storage.clone();
                    async move {
                        debug!("Fetching key for authority {} ({})", auth.name, auth.id);
                        let url = format!("http://dummy/tor/keys/fp/{}.z", auth.id.to_hex()).parse::<hyper::Uri>().unwrap();
                        let res = http::HyperResponse::new( match tokio::time::timeout(
                            DEFAULT_TIMEOUT, dir_client.get(url)
                        ).await {
                            Ok(Ok(res)) => res,
                            Ok(Err(e)) => {
                                warn!("Failed to fetch key for authority {} ({}): {}", auth.name, auth.id, e);
                                return (auth.id, None);
                            }
                            Err(_) => {
                                warn!("Timed out fetching key for authority {} ({})", auth.name, auth.id);
                                return (auth.id, None);
                            }
                        });
                        if !res.status().is_success() {
                            warn!("Got non-success response fetching key for authority: {}", res.status());
                            return (auth.id, None);
                        }
                        let mut body = match res.read() {
                            Ok(body) => storage::SavingReader::new(body),
                            Err(e) => {
                                warn!("Failed to read response body: {}", e);
                                return (auth.id, None);
                            }
                        };

                        let directory_key = match tokio::time::timeout(
                            DEFAULT_TIMEOUT,
                            net_status::dir_key_certificate::DirectoryKeyCertificate::parse(&mut body)
                        ).await {
                            Ok(Ok(dk)) => dk,
                            Ok(Err(e)) => {
                                warn!("Failed to parse directory key for authority {} ({}): {}", auth.name, auth.id, e);
                                return (auth.id, None);
                            }
                            Err(_) => {
                                warn!("Timed out fetching key for authority {} ({})", auth.name, auth.id);
                                return (auth.id, None);
                            }
                        };

                        let dk = if !directory_key.verify() {
                            warn!("Failed to verify directory key for {}", auth.name);
                            None
                        } else if directory_key.fingerprint != auth.id {
                            warn!("Fingerprint mismatch for {}", auth.name);
                            None
                        } else {
                            let b = body.buf();
                            if let Err(e) = storage.save_dir_key_certificate(auth.id, b).await {
                                warn!("Failed to save directory key certificate for {}: {}", auth.name, e);
                            }
                            Some(directory_key)
                        };
                        (auth.id, dk)
                    }
                }).buffer_unordered(10).collect::<std::collections::HashMap<RsaIdentity, _>>().await;

                let res = http::HyperResponse::new(
                    match tokio::time::timeout(
                        DEFAULT_TIMEOUT,
                        dir_client.get(hyper::Uri::from_static("http://dummy/tor/status-vote/current/consensus.z"))
                    ).await {
                        Ok(Ok(res)) => res,
                        Ok(Err(e)) => {
                            warn!("Failed to fetch consensus: {}", e);
                            continue;
                        }
                        Err(_) => {
                            warn!("Timed out fetching consensus");
                            continue;
                        }
                    }
                );
                if !res.status().is_success() {
                    error!("Got non-success response fetching consensus: {}", res.status());
                    continue;
                }
                let mut body = match res.read() {
                    Ok(body) => storage::SavingReader::new(body),
                    Err(e) => {
                        warn!("Failed to read response body: {}", e);
                        continue;
                    }
                };

                let new_consensus = match tokio::time::timeout(
                    DEFAULT_TIMEOUT * 3, net_status::consensus::Consensus::parse(&mut body)
                ).await {
                    Ok(Ok(dk)) => dk,
                    Ok(Err(e)) => {
                        warn!("Failed to parse consensus: {}", e);
                        continue;
                    }
                    Err(_) => {
                        warn!("Timed out fetching consensus");
                        continue;
                    }
                };

                if verify_consensus(&new_consensus, &authority_keys) {
                    let b = body.buf();
                    if let Err(e) = storage.save_consensus(b).await {
                        warn!("Failed to save consensus: {}", e);
                    }
                    consensus.write().await.replace(new_consensus);
                    *hs_relays.write().await = None;
                } else {
                    continue;
                }
            } else {
                trace!("Consensus is current, not doing anything");
            }
            tokio::time::sleep(std::time::Duration::from_secs(60)).await;
        }
    }
}

fn verify_consensus(
    consensus: &net_status::consensus::Consensus,
    authorities: &std::collections::HashMap<RsaIdentity, Option<net_status::dir_key_certificate::DirectoryKeyCertificate>>
) -> bool {
    let mut num_valid_signatures = 0;
    for sig in &consensus.signatures {
        let auth = match authorities.get(&sig.identity) {
            Some(Some(auth)) => auth,
            Some(None) => continue,
            None => {
                warn!("Unknown authority {}", sig.identity);
                continue;
            }
        };
        let signing_key_digest = ring::digest::digest(&ring::digest::SHA1_FOR_LEGACY_USE_ONLY, &auth.signing_key);
        if signing_key_digest.as_ref() != sig.signing_key_digest {
            warn!("Signing key digest mismatch for {}", sig.identity);
            continue;
        }

        match auth.signing_key_rsa().unwrap().verify(
            rsa::PaddingScheme::new_pkcs1v15_sign_raw(), consensus.digest.as_ref(), &sig.signature
        ) {
            Ok(_) => {
                num_valid_signatures += 1;
            },
            Err(_) => {
                warn!("Failed to verify signature for {}", sig.identity);
            }
        }
    }

    info!("Got network consensus with {} valid and trusted signatures (out of {})", num_valid_signatures, consensus.signatures.len());
    if num_valid_signatures < (authorities.len() / 2) + 1 {
        error!("Not enough valid signatures on network consensus");
        false
    } else {
        true
    }
}