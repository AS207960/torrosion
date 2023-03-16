use base64::Engine;
use base64::prelude::*;
use sha3::Digest;
use futures::StreamExt;
use rand::prelude::*;
use chrono::prelude::*;
use digest::XofReader;

mod descriptor;
mod first_layer;
pub mod second_layer;
pub mod con;
pub mod http;

const BLIND_STRING: &[u8] = b"Derive temporary signing key\0";
const ED25519_BASEPOINT: &[u8] =
    b"(15112221349535400772501151409588531511454012693041857206046113283949847762202, \
               46316835694926478169428394003475163141307993866256225615783033603165251855960)";

#[derive(Debug)]
pub struct HSAddress {
    pub key: [u8; 32]
}

impl HSAddress {
    pub fn from_str(host: &str) -> std::io::Result<Self> {
        let host = host.trim_end_matches(".");
        let (host, tld) = match host.rsplit_once(".") {
            Some(h) => h,
            None => return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput, "Not an onion address"
            )),
        };
        if tld != "onion" {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput, "Not an onion address"
            ));
        }
        let addr = match host.rsplit_once(".") {
            Some(h) => h.1,
            None => host,
        };

        let addr = base32::decode(base32::Alphabet::RFC4648 { padding: false }, addr)
            .ok_or_else(|| std::io::Error::new(
                std::io::ErrorKind::InvalidInput, "Invalid onion address"
            ))?;

        if addr.len() != 35 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput, "Invalid onion address"
            ));
        }

        let key = addr[0..32].try_into().unwrap();
        let version = addr[34];

        let mut hasher = sha3::Sha3_256::new();
        hasher.update(b".onion checksum");
        hasher.update(&key);
        hasher.update(&[version]);

        if hasher.finalize()[..2] != addr[32..34] {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput, "Invalid onion address"
            ));
        }

        if version != 3 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput, "Unsupported onion address"
            ));
        }

        Ok(Self { key })
    }

    pub fn from_uri(uri: &hyper::Uri) -> std::io::Result<Self> {
        let authority = uri.authority().ok_or_else(|| std::io::Error::new(
            std::io::ErrorKind::InvalidInput, "Not an authority"
        ))?;

        Self::from_str(authority.host())
    }

    fn blinding_param(&self, consensus: &crate::net_status::consensus::Consensus) -> [u8; 32] {
        let period_length = time_period_length_minutes(consensus);
        let period_number = current_time_period_number(consensus);

        let mut hasher = sha3::Sha3_256::new();
        hasher.update(BLIND_STRING);
        hasher.update(self.key);
        hasher.update(ED25519_BASEPOINT);
        hasher.update(b"key-blind");
        hasher.update(period_number.to_be_bytes());
        hasher.update(period_length.to_be_bytes());

        hasher.finalize().into()
    }

    fn blinding_factor(mut param: [u8; 32]) -> curve25519_dalek::scalar::Scalar {
        param[0] &= 248;
        param[31] &= 63;
        param[31] |= 64;

        curve25519_dalek::scalar::Scalar::from_bytes_mod_order(param)
    }

    fn blinded_key(&self, consensus: &crate::net_status::consensus::Consensus) -> ([u8; 32], Vec<u8>) {
        let param = self.blinding_param(consensus);
        let factor = Self::blinding_factor(param);

        let pubkey_point = curve25519_dalek::edwards::CompressedEdwardsY(self.key).decompress().unwrap();
        let blinded_pubkey_point = (factor * pubkey_point).compress();

        let mut hasher = sha3::Sha3_256::new();
        hasher.update(b"credential");
        hasher.update(&self.key);
        let hs_cred = hasher.finalize().to_vec();

        let mut hasher = sha3::Sha3_256::new();
        hasher.update(b"subcredential");
        hasher.update(hs_cred);
        hasher.update(&blinded_pubkey_point.0);
        let hs_subcred = hasher.finalize().to_vec();

        (blinded_pubkey_point.0, hs_subcred)
    }

    fn candidates<'a>(
        consensus: &crate::net_status::consensus::Consensus, hs_relays: &'a HSRelays, blinded_key: &[u8; 32]
    ) -> Vec<&'a HSRelay> {
        let hsdir_n_replicas = *consensus.parameters.get("hsdir_n_replicas").unwrap_or(&2);
        let hsdir_spread_fetch = *consensus.parameters.get("hsdir_spread_fetch").unwrap_or(&3);
        let period_length = time_period_length_minutes(consensus);
        let period_number = current_time_period_number(consensus);

        let mut indicies = vec![];
        for replica_num in 0..hsdir_n_replicas {
            let mut hasher = sha3::Sha3_256::new();
            hasher.update(b"store-at-idx");
            hasher.update(blinded_key);
            hasher.update((replica_num as u64).to_be_bytes());
            hasher.update(period_length.to_be_bytes());
            hasher.update(period_number.to_be_bytes());
            indicies.push(HSRelayIndex(hasher.finalize().try_into().unwrap()));
        }

        let mut routers: Vec<&HSRelay> = vec![];

        for index in indicies {
            let mut r = hs_relays.0.iter()
                .filter(|relay| relay.index > index)
                .filter(|relay| !routers.iter().any(|r| r.router.identity == relay.router.identity))
                .take(hsdir_spread_fetch as usize)
                .collect::<Vec<_>>();
            routers.append(&mut r);
        }

        routers
    }

    async fn download_ds<S: crate::storage::Storage + Send + Sync + 'static>(
        &self, consensus: &crate::net_status::consensus::Consensus, client: &crate::Client<S>,
        hs_relays: &HSRelays, blinded_key: &[u8; 32]
    ) -> std::io::Result<descriptor::Descriptor> {
        let mut candidates = Self::candidates(&consensus, hs_relays, &blinded_key);
        candidates.shuffle(&mut thread_rng());

        let mut r = 0;
        let (mut con, first_router_descriptor) = loop {
            if r >= crate::DEFAULT_RETRIES {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::HostUnreachable, "Failed to make rendezvous point",
                ))
            }

            let first_router = crate::net_status::select_node(&consensus).unwrap();
            let first_router_descriptor = match tokio::time::timeout(
                crate::DEFAULT_TIMEOUT,
                crate::net_status::descriptor::get_server_descriptor(
                    &first_router, &client
                )
            ).await {
                Ok(Ok(d)) => d,
                Ok(Err(e)) => {
                    warn!("Failed to get server descriptor: {}", e);
                    r += 1;
                    continue;
                }
                Err(_) => {
                    warn!("Timed out getting server descriptor");
                    r += 1;
                    continue;
                }
            };

            let tcp_stream = match tokio::time::timeout(
                crate::DEFAULT_TIMEOUT,
                crate::con::connect_to_router(&first_router)
            ).await {
                Ok(Ok(s)) => s,
                Ok(Err(e)) => {
                    warn!("Failed to connect to router: {}", e);
                    r += 1;
                    continue;
                }
                Err(_) => {
                    warn!("Timed out connecting to router");
                    r += 1;
                    continue;
                }
            };

             match tokio::time::timeout(
                crate::DEFAULT_TIMEOUT,
                crate::connection::Connection::connect(
                    tcp_stream, first_router_descriptor.identity
                )
            ).await {
                Ok(Ok(c)) => break (c, first_router_descriptor),
                Ok(Err(e)) => {
                    warn!("Failed to connect to router: {}", e);
                    r += 1;
                    continue;
                }
                Err(_) => {
                    warn!("Timed out connecting to router");
                    r += 1;
                    continue;
                }
            }
        };


        for candidate in &candidates {
            let dir_circ = match tokio::time::timeout(
                crate::DEFAULT_TIMEOUT, con.create_circuit(first_router_descriptor.ntor_onion_key)
            ).await {
                Ok(Ok(c)) => c,
                Ok(Err(e)) => {
                    warn!("Failed to create HS directory circuit: {}", e);
                    continue;
                }
                Err(_) => {
                    warn!("Timed out creating HS directory circuit");
                    continue;
                }
            };

            let second_router = crate::net_status::select_node(&consensus).unwrap();
            let second_router_descriptor = crate::net_status::descriptor::get_server_descriptor(
                &second_router, &client
            ).await?;
            match tokio::time::timeout(
                crate::DEFAULT_TIMEOUT, dir_circ.extend_circuit(&second_router_descriptor)
            ).await {
                Ok(Ok(_)) => (),
                Ok(Err(e)) => {
                    warn!("Failed to extend HS directory circuit: {}", e);
                    continue;
                }
                Err(_) => {
                    warn!("Timed out extending HS directory circuit");
                    continue;
                }
            }

            let candidate_descriptor = crate::net_status::descriptor::get_server_descriptor(
                &candidate.router, &client
            ).await?;
            match tokio::time::timeout(
                crate::DEFAULT_TIMEOUT, dir_circ.extend_circuit(&candidate_descriptor)
            ).await {
                Ok(Ok(_)) => (),
                Ok(Err(e)) => {
                    warn!("Failed to extend HS directory circuit: {}", e);
                    continue;
                }
                Err(_) => {
                    warn!("Timed out extending HS directory circuit");
                    continue;
                }
            }

            let dir_client = crate::http::new_directory_client(dir_circ);

            let url = format!("http://dummy/tor/hs/3/{}", BASE64_STANDARD.encode(blinded_key)).parse::<hyper::Uri>().unwrap();
            let res = crate::http::HyperResponse::new(
                match tokio::time::timeout(
                    crate::DEFAULT_TIMEOUT, dir_client.get(url)
                ).await {
                    Ok(Ok(res)) => res,
                    Ok(Err(e)) => {
                        warn!("Failed to fetch HS descriptor: {}", e);
                        continue;
                    }
                    Err(_) => {
                        warn!("Timed out fetching HS descriptor");
                        continue;
                    }
                }
            );

            if !res.status().is_success() {
                error!("Got non-success response fetching HS descriptor: {}", res.status());
                continue;
            }
            let mut body = match res.read() {
                Ok(body) => body,
                Err(e) => {
                    warn!("Failed to read response body: {}", e);
                    continue;
                }
            };

            match descriptor::Descriptor::parse(&mut body).await {
                Ok(descriptor) => return Ok(descriptor),
                Err(e) => {
                    warn!("Failed to parse HS descriptor: {}", e);
                    continue;
                }
            }
        }

        Err(std::io::Error::new(std::io::ErrorKind::Other, "No HS directory servers had descriptor"))
    }

    fn decrypt(
        secret_data: &[u8], hs_subcred: &[u8], revision_counter: u64, string_constant: &[u8],
        data: &[u8]
    ) -> std::io::Result<Vec<u8>> {
        use sha3::digest::{Update, ExtendableOutput};
        use aes::cipher::{KeyIvInit, StreamCipher};

        if data.len() < 96 {
            return Err(std::io::Error::new(std::io::ErrorKind::Other, "Invalid encrypted data"));
        }
        let salt = &data[0..16];
        let mut encrypted = data[16..data.len()-32].to_vec();
        let mac = &data[data.len()-32..];

        let mut hasher = sha3::Shake256::default();
        hasher.update(secret_data);
        hasher.update(hs_subcred);
        hasher.update(&revision_counter.to_be_bytes());
        hasher.update(salt);
        hasher.update(string_constant);
        let mut reader = hasher.finalize_xof();

        let mut secret_key = [0; 32];
        reader.read(&mut secret_key);
        let mut secret_iv = [0; 16];
        reader.read(&mut secret_iv);
        let mut mac_key = [0; 32];
        reader.read(&mut mac_key);

        let mut mac_hasher = sha3::Sha3_256::new();
        sha3::Digest::update(&mut mac_hasher, &(32 as u64).to_be_bytes());
        sha3::Digest::update(&mut mac_hasher, &mac_key);
        sha3::Digest::update(&mut mac_hasher,&(16 as u64).to_be_bytes());
        sha3::Digest::update(&mut mac_hasher,&salt);
        sha3::Digest::update(&mut mac_hasher, &encrypted);
        let d_mac = mac_hasher.finalize().to_vec();

        if ring::constant_time::verify_slices_are_equal(&d_mac, mac).is_err() {
            return Err(std::io::Error::new(std::io::ErrorKind::Other, "Invalid encrypted data"));
        }

        let mut c = crate::Aes256::new(&secret_key.into(), &secret_iv.into());
        c.apply_keystream(&mut encrypted);

        Ok(encrypted)
    }

    pub async fn fetch_ds<'a, S: crate::storage::Storage + Send + Sync + 'static>(
        &self, client: &crate::Client<S>, hs_relays: &'a HSRelays, private_key: Option<[u8; 32]>
    ) -> std::io::Result<(second_layer::Descriptor, Vec<u8>)> {
        let consensus = client.consensus().await?;
        let (blinded_key, hs_subcred) = self.blinded_key(&consensus);

        let descriptor = self.download_ds(&consensus, client, hs_relays, &blinded_key).await?;

        if !descriptor.verify(&blinded_key) {
            return Err(std::io::Error::new(std::io::ErrorKind::Other, "Failed to verify HS descriptor"));
        }

        let inner_descriptor_bytes = Self::decrypt(
            &blinded_key, &hs_subcred, descriptor.revision_counter, b"hsdir-superencrypted-data",
            &descriptor.superencrypted
        )?;
        let first_layer = first_layer::Descriptor::parse(&mut inner_descriptor_bytes.as_slice()).await?;

        let descriptor_cookie = if let Some(private_key) = private_key {
            use sha3::digest::{Update, ExtendableOutput};
            use aes::cipher::{KeyIvInit, StreamCipher};

            let my_pk = x25519_dalek::StaticSecret::from(private_key);
            let their_pk = x25519_dalek::PublicKey::from(first_layer.ephemeral_key);
            let secret_seed = my_pk.diffie_hellman(&their_pk);

            let mut kdf = sha3::Shake256::default();
            kdf.update(&hs_subcred);
            kdf.update(secret_seed.as_bytes());
            let mut reader = kdf.finalize_xof();

            let mut client_id = [0; 8];
            let mut cookie_key = [0; 32];
            reader.read(&mut client_id);
            reader.read(&mut cookie_key);

            if let Some(client) = first_layer.auth_clients.iter().find(|c| c.client_id == client_id) {
                let mut cookie = client.encrypted_cookie.clone();
                let mut c = crate::Aes256::new(&cookie_key.into(), &client.iv.into());
                c.apply_keystream(&mut cookie);
                cookie
            } else {
                vec![]
            }
        } else {
            vec![]
        };

        let mut second_layer_secret_data = blinded_key.to_vec();
        second_layer_secret_data.extend_from_slice(&descriptor_cookie);
        let second_layer_bytes = Self::decrypt(
            &second_layer_secret_data, &hs_subcred, descriptor.revision_counter, b"hsdir-encrypted-data",
            &first_layer.encrypted,
        )?;
        let second_layer = second_layer::Descriptor::parse(&mut second_layer_bytes.as_slice()).await?;

        Ok((second_layer, hs_subcred))
    }
}

#[derive(Debug, Ord, PartialOrd, Eq, PartialEq, Clone, Copy)]
pub struct HSRelayIndex([u8; 32]);

#[derive(Clone)]
pub struct HSRelays(Vec<HSRelay>);

impl std::fmt::Debug for HSRelays {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("[...]")
    }
}

#[derive(Debug, Clone)]
pub struct HSRelay {
    router: crate::net_status::consensus::Router,
    index: HSRelayIndex
}

pub async fn get_hs_dirs<S: crate::storage::Storage + Send + Sync + 'static>(client: &crate::Client<S>) -> std::io::Result<HSRelays> {
    let consensus = client.consensus().await?;
    let shared_rand = shared_random_value(&consensus);
    let period_number = current_time_period_number(&consensus);
    let period_length = time_period_length_minutes(&consensus);
    let hs_dirs = consensus.routers.into_iter().filter(|r| {
        if !r.status.iter().any(|f| f == "HSDir") {
            return false;
        }

        if let Some(proto) = &r.protocols {
            proto.supports("HSDir", 2)
        } else {
            false
        }
    }).collect::<Vec<_>>();

    let mut relays = futures::future::join_all(futures::stream::iter(hs_dirs.into_iter())
        .map(|r| async move { (crate::net_status::descriptor::get_server_descriptor(&r, client).await, r) })
        .buffer_unordered(25)
        .filter_map(|(d, r)| async move {
            match d {
                Ok(d) => Some((d, r)),
                Err(e) => {
                    warn!("Failed to fetch descriptor for {}: {}", r.identity, e);
                    None
                }
            }
        })
        .map(|(d, r)| async move {
            tokio::task::spawn_blocking(move || {
                let mut hasher = sha3::Sha3_256::new();
                hasher.update(b"node-idx");
                hasher.update(&d.ed25519_master_key);
                hasher.update(&shared_rand);
                hasher.update(period_number.to_be_bytes());
                hasher.update(period_length.to_be_bytes());
                HSRelay {
                    router: r,
                    index: HSRelayIndex(hasher.finalize().try_into().unwrap())
                }
            }).await.unwrap()
        }).collect::<Vec<_>>().await).await;

    relays.sort_by_key(|r| r.index);

    Ok(HSRelays(relays))
}

fn time_period_length_minutes(consensus: &crate::net_status::consensus::Consensus) -> u64 {
    if let Some(v) = consensus.parameters.get("hsdir-interval") {
        if *v >= 60 && *v <= 14400 {
            return *v as u64;
        }
    }

    return 1440;
}

fn current_time_period_number(consensus: &crate::net_status::consensus::Consensus) -> i64 {
    let now = consensus.valid_after.timestamp() / 60;
    let voting_period_length = (consensus.fresh_until - consensus.valid_after).num_minutes();
    let offset_now = now - (voting_period_length * 12);
    let time_period_length = time_period_length_minutes(consensus) as i64;
    offset_now / time_period_length
}

fn time_period_started_before_midnight(consensus: &crate::net_status::consensus::Consensus) -> bool {
    let voting_period_length = (consensus.fresh_until - consensus.valid_after).num_minutes();
    let time_period_length = time_period_length_minutes(consensus) as i64;
    let current_time_period = current_time_period_number(consensus);
    let time_period_start = (current_time_period * time_period_length) + (voting_period_length * 12);
    let midnight = consensus.valid_after
        .with_hour(0).unwrap()
        .with_minute(0).unwrap()
        .with_second(0).unwrap()
        .with_nanosecond(0).unwrap().timestamp() / 60;
    time_period_start < midnight
}

fn shared_random_value(consensus: &crate::net_status::consensus::Consensus) -> [u8; 32] {
    match if time_period_started_before_midnight(&consensus) {
        consensus.previous_shared_random_value
            .as_ref()
            .and_then(|c| TryInto::<[u8; 32]>::try_into(c.value.clone()).ok())
    } else {
        consensus.current_shared_random_value
            .as_ref()
            .and_then(|c| TryInto::<[u8; 32]>::try_into(c.value.clone()).ok())
    } {
        Some(v) => v,
        None => {
            let mut hasher = sha3::Sha3_256::new();
            hasher.update(b"shared-random-disaster");
            hasher.update(time_period_length_minutes(consensus).to_be_bytes());
            hasher.update(current_time_period_number(consensus).to_be_bytes());
            hasher.finalize().into()
        }
    }
}

mod test {
    #[test]
    fn test_tp() {
        let mock_consensus = crate::net_status::consensus::Consensus {
            valid_after: Utc.with_ymd_and_hms(2016, 04, 13, 11, 0, 0).unwrap(),
            fresh_until: Utc.with_ymd_and_hms(2016, 04, 13, 12, 0, 0).unwrap(),
            valid_until: Utc.with_ymd_and_hms(2016, 04, 13, 17, 0, 0).unwrap(),
            voting_delay: crate::net_status::consensus::VotingDelay { vote_seconds: 0, dist_seconds: 0 },
            client_versions: vec![],
            server_versions: vec![],
            packages: vec![],
            known_flags: vec![],
            recommended_client_protocols: None,
            recommended_relay_protocols: None,
            required_client_protocols: None,
            current_shared_random_value: None,
            previous_shared_random_value: None,
            parameters: std::collections::HashMap::new(),
            routers: vec![],
            signatures: vec![],
            required_relay_protocols: None,
            authorities: vec![],
            digest: ring::digest::digest(&ring::digest::SHA256, &[]),
        };

        let current_time_period = super::current_time_period_number(&mock_consensus);
        let time_period_length = super::time_period_length_minutes(&mock_consensus);
        assert_eq!(current_time_period, 16903);
        assert_eq!(time_period_length, 1440);
    }
}