#[macro_use]
extern crate log;
extern crate core;

mod fallback;
mod cell;
mod cert;
mod connection;
pub mod circuit;
mod stream;
pub mod net_status;
pub mod con;
mod auth;
pub mod http;
pub mod hs;
pub mod storage;

use std::fmt::Formatter;
use std::ops::Deref;
use rand::prelude::*;
use futures::StreamExt;
use auth::RsaIdentity;

static PAYLOAD_LEN: usize = 509;
static MAX_RELAY_DATA_LEN: usize = PAYLOAD_LEN - 11;
static VERSIONS: [u16; 2] = [3, 4];
static CIRCUIT_WINDOW_INITIAL: isize = 1000;
static CIRCUIT_WINDOW_INCREMENT: isize = 100;
static STREAM_WINDOW_INITIAL: isize = 500;
static STREAM_WINDOW_INCREMENT: isize = 50;
static DEFAULT_RETRIES: usize = 3;
static DEFAULT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
type Aes128 = ctr::Ctr128BE<aes::Aes128>;
type Aes256 = ctr::Ctr128BE<aes::Aes256>;


pub struct ClientInner<S: storage::Storage> {
    storage: S,
    ds_circuit: tokio::sync::RwLock<Option<circuit::Circuit>>,
    hs_relays: tokio::sync::RwLock<Option<hs::HSRelays>>
}

pub struct Client<S: storage::Storage> {
    inner: std::sync::Arc<ClientInner<S>>,
    current_consensus: tokio::sync::watch::Receiver<Option<net_status::consensus::Consensus>>,
    new_consensus: tokio::sync::watch::Sender<Option<net_status::consensus::Consensus>>,
}

impl<S: storage::Storage> std::fmt::Debug for Client<S> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let mut d = f.debug_struct("Client");
        d.field("storage", &"Arc<Storage>");
        match self.current_consensus.borrow().as_ref() {
            Some(_) => d.field("current_consensus", &"Some(...)"),
            None => d.field("current_consensus", &"None")
        };
        d.field("ds_circuit", &self.inner.ds_circuit);
        d.field("hs_relays", &self.inner.hs_relays);
        d.finish_non_exhaustive()
    }
}

impl<S: storage::Storage> Clone for Client<S> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            current_consensus: self.current_consensus.clone(),
            new_consensus: self.new_consensus.clone()
        }
    }
}

impl<S: storage::Storage + Send + Sync + 'static> Client<S> {
    pub fn new(storage: S) -> Self {
        let (new_consensus, current_consensus) = tokio::sync::watch::channel(None);
        Self {
            inner: std::sync::Arc::new(ClientInner {
                storage,
                ds_circuit: tokio::sync::RwLock::new(None),
                hs_relays: tokio::sync::RwLock::new(None),
            }),
            current_consensus,
            new_consensus,
        }
    }

    pub async fn ready(&self) -> bool {
        self.current_consensus.borrow().is_some()
    }

    pub async fn wait_ready(&mut self) {
        while self.current_consensus.borrow_and_update().is_none() {
            self.current_consensus.changed().await.unwrap();
        }
    }

    pub async fn consensus(&self) -> std::io::Result<net_status::consensus::Consensus> {
        match self.current_consensus.borrow().deref() {
            Some(c) => Ok(c.clone()),
            None => Err(std::io::Error::new(std::io::ErrorKind::NotConnected, "Not ready"))
        }
    }

    pub(crate) async fn get_ds_circuit(&self) -> std::io::Result<circuit::Circuit> {
        match self.inner.ds_circuit.read().await.deref() {
            Some(c) => {
                if c.is_open().await {
                    return Ok(c.clone());
                }
            },
            None => {}
        }

        let mut l = self.inner.ds_circuit.write().await;
        let consensus = self.consensus().await?;
        let directory_server = net_status::select_directory_server(&consensus, false)
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
        match self.inner.hs_relays.read().await.deref() {
            Some(h) => {
                return Ok(h.clone());
            },
            None => {}
        }

        let mut l = self.inner.hs_relays.write().await;
        let dirs = hs::get_hs_dirs(&self).await?;
        *l = Some(dirs.clone());
        Ok(dirs)
    }

    pub async fn run(&mut self) {
        match self.inner.storage.load_consensus().await {
            Ok(mut r) => {
                match net_status::consensus::Consensus::parse(&mut r).await {
                    Ok(c) => {
                        let authority_keys = futures::stream::iter( auth::default_authorities())
                            .map(|auth| {
                                let inner = self.inner.clone();
                                async move {
                                    let mut kr = match inner.storage.load_dir_key_certificate(auth.id).await {
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
                                self.new_consensus.send(Some(c)).unwrap();
                            }
                        } else {
                            error!("Failed to verify stored consensus");
                        }
                    }
                    Err(e) => {
                        error!("Error parsing stored consensus: {}", e);
                    }
                }
            }
            Err(e) => {
                error!("Error loading stored consensus: {}", e);
            }
        }

        let new_self = self.clone();
        tokio::task::spawn(async move {
            new_self.consensus_loop().await;
        });
    }

    async fn consensus_loop(&self) {
        loop {
            let consensus_is_current = self.current_consensus.borrow().as_ref().map_or(false, |consensus| {
                consensus.fresh_until > chrono::Utc::now()
            });
            if !consensus_is_current {
                let c = self.current_consensus.borrow().clone();
                let (tcp_stream, identity) = match c {
                    None => {
                        // We have no stored consensus
                        let fallback_dirs = fallback::FallbackDirs::new();
                        let fallback = {
                            let mut rng = rand::rng();
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
                            let mut rng = rand::rng();
                            let half_interval = ((c.fresh_until - c.valid_after) / 2).num_seconds();
                            let unfresh_s = std::cmp::max((chrono::Utc::now() - c.fresh_until).num_seconds(), 0);
                            let max_delay = std::cmp::max(half_interval - unfresh_s, 0);
                            rng.random_range(0..=max_delay) as u64
                        };
                        tokio::time::sleep(std::time::Duration::from_secs(delay_s)).await;

                        let directory_server = match net_status::select_directory_server(&c, false) {
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

                let authority_keys = futures::stream::iter(auth::default_authorities()).map(|auth| {
                    let new_self = self.clone();
                    let dir_client = dir_client.clone();
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
                            if let Err(e) = new_self.inner.storage.save_dir_key_certificate(auth.id, b).await {
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
                    if let Err(e) = self.inner.storage.save_consensus(b).await {
                        warn!("Failed to save consensus: {}", e);
                    }
                    self.new_consensus.send(Some(new_consensus)).unwrap();
                    *self.inner.hs_relays.write().await = None;
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
            rsa::pkcs1v15::Pkcs1v15Sign::new_unprefixed(), consensus.digest.as_ref(), &sig.signature
        ) {
            Ok(_) => {
                num_valid_signatures += 1;
            },
            Err(_) => {
                warn!("Failed to verify signature for {}", sig.identity);
            }
        }
    }

    info!("Got network consensus with {} valid and trusted signatures (out of {} received signatures, \
     {} known authorities)", num_valid_signatures, consensus.signatures.len(), authorities.len());
    if num_valid_signatures < (authorities.len() / 2) + 1 {
        error!("Not enough valid signatures on network consensus");
        false
    } else {
        true
    }
}