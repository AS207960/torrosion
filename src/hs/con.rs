use base64::Engine;
use base64::prelude::*;
use chrono::prelude::*;
use sha3::Digest;
use futures::{SinkExt, StreamExt};
use rand::prelude::*;
use std::io::Write;
use byteorder::{BigEndian, WriteBytesExt};

struct IntroductionInner {
    pub rendezvous_cookie: [u8; 20],
    pub extensions: Vec<IntroductionExtension>,
    pub onion_key: IntroductionOnionKey,
    pub link_specifiers: Vec<crate::cell::LinkSpecifier>,
}

enum IntroductionExtension {
    Unknown((u8, Vec<u8>)),
}

enum IntroductionOnionKey {
    Ntor([u8; 32]),
    Unknown((u8, Vec<u8>)),
}

impl IntroductionInner {
    fn to_bytes(&self) -> Vec<u8> {
        let mut cursor = std::io::Cursor::new(Vec::new());

        cursor.write_all(&self.rendezvous_cookie).unwrap();
        cursor.write_u8(self.extensions.len() as u8).unwrap();
        for ext in &self.extensions {
            match ext {
                IntroductionExtension::Unknown((t, d)) => {
                    cursor.write_u8(*t).unwrap();
                    cursor.write_u8(d.len() as u8).unwrap();
                    cursor.write_all(d).unwrap();
                }
            }
        }

        match &self.onion_key {
            IntroductionOnionKey::Ntor(key) => {
                cursor.write_u8(1).unwrap();
                cursor.write_u16::<BigEndian>(32).unwrap();
                cursor.write_all(key).unwrap();
            }
            IntroductionOnionKey::Unknown((t, d)) => {
                cursor.write_u8(*t).unwrap();
                cursor.write_u8(d.len() as u8).unwrap();
                cursor.write_all(&d).unwrap();
            }
        }

        cursor.write_u8(self.link_specifiers.len() as u8).unwrap();
        for link_spec in &self.link_specifiers {
            let type_id = link_spec.type_id();
            let data = link_spec.data();
            cursor.write_u8(type_id).unwrap();
            cursor.write_u8(data.len() as u8).unwrap();
            cursor.write_all(&data).unwrap();
        }

        cursor.into_inner()
    }
}

#[derive(Debug)]
struct Rendezvous2Inner {
    pub server_pk: [u8; 32],
    pub auth: [u8; 32],
}

impl Rendezvous2Inner {
    fn from_bytes(bytes: &[u8]) -> std::io::Result<Self> {
        use std::io::Read;

        let mut cursor = std::io::Cursor::new(bytes);

        let mut server_pk = [0; 32];
        cursor.read_exact(&mut server_pk)?;

        let mut auth = [0; 32];
        cursor.read_exact(&mut auth)?;

        Ok(Rendezvous2Inner {
            server_pk,
            auth,
        })
    }
}

async fn make_rendezvous_point<S: crate::storage::Storage + Send + Sync + 'static>(
    client: &crate::Client<S>, consensus: &crate::net_status::consensus::Consensus
) -> std::io::Result<(crate::circuit::Circuit, IntroductionInner)> {
    let mut cookie = [0; 20];
    thread_rng().fill_bytes(&mut cookie);

    let rend_router = crate::net_status::select_rendezvous_server(consensus).unwrap();
    let rend_router_descriptor = crate::net_status::descriptor::get_server_descriptor(
        &rend_router, &client
    ).await?;

    let first_router = crate::net_status::select_node(&consensus).unwrap();
    let tcp_stream = crate::con::connect_to_router(&first_router).await?;
    let mut con = crate::connection::Connection::connect(tcp_stream, first_router.identity).await?;

    let rend_circ = con.create_circuit_fast().await?;

    let second_router = crate::net_status::select_node(&consensus).unwrap();
    let second_router_descriptor = crate::net_status::descriptor::get_server_descriptor(
        &second_router, &client
    ).await?;

    rend_circ.extend_circuit(&second_router_descriptor).await?;
    rend_circ.extend_circuit(&rend_router_descriptor).await?;

    rend_circ.establish_rendezvous(cookie).await?;

    Ok((rend_circ, IntroductionInner {
        rendezvous_cookie: cookie,
        extensions: vec![],
        onion_key: IntroductionOnionKey::Ntor(rend_router_descriptor.ntor_onion_key),
        link_specifiers: rend_router_descriptor.to_link_specifiers(),
    }))
}

struct IntroductionInfo {
    my_sk: x25519_dalek::StaticSecret,
    my_pk: x25519_dalek::PublicKey,
    ntor_enc_key: x25519_dalek::PublicKey,
    auth_key: crate::cert::Cert,
}

async fn send_introduction<S: crate::storage::Storage + Send + Sync + 'static>(
    client: &crate::Client<S>, consensus: &crate::net_status::consensus::Consensus,
    intro_points: Vec<super::second_layer::IntroductionPoint>,
    introduction_inner: &IntroductionInner, subcred: &[u8]
) -> std::io::Result<IntroductionInfo> {
    use sha3::digest::{Update, ExtendableOutput, XofReader};
    use aes::cipher::KeyIvInit;
    use aes::cipher::StreamCipher;

    let first_router = crate::net_status::select_node(&consensus).unwrap();
    let tcp_stream = crate::con::connect_to_router(&first_router).await?;
    let mut con = crate::connection::Connection::connect(tcp_stream, first_router.identity).await?;

    let introduction_bytes = introduction_inner.to_bytes();

    for intro_point in intro_points {
        let identity = match intro_point.link_specifiers.iter().find_map(|s| match s {
            crate::cell::LinkSpecifier::LegacyIdentity(i) => Some(i),
            _ => None
        }) {
            Some(i) => *i,
            None => {
                warn!("No identity found in link specifier");
                continue;
            }
        };

        let intro_circ = match tokio::time::timeout(
            crate::DEFAULT_TIMEOUT, con.create_circuit_fast()
        ).await {
            Ok(Ok(c)) => c,
            Ok(Err(e)) => {
                warn!("Failed to create introduction circuit: {}", e);
                continue;
            }
            Err(_) => {
                warn!("Timed out creating introduction circuit");
                continue;
            }
        };

        let second_router = crate::net_status::select_node(&consensus).unwrap();
        let second_router_descriptor = crate::net_status::descriptor::get_server_descriptor(
            &second_router, &client
        ).await?;
        match tokio::time::timeout(
            crate::DEFAULT_TIMEOUT, intro_circ.extend_circuit(&second_router_descriptor)
        ).await {
            Ok(Ok(_)) => (),
            Ok(Err(e)) => {
                warn!("Failed to extend introduction circuit: {}", e);
                continue;
            }
            Err(_) => {
                warn!("Timed out extending introduction circuit");
                continue;
            }
        }

        match tokio::time::timeout(
            crate::DEFAULT_TIMEOUT, intro_circ.extend_circuit_raw(
                intro_point.link_specifiers, identity, intro_point.ntor_onion_key
            )
        ).await {
            Ok(Ok(_)) => (),
            Ok(Err(e)) => {
                warn!("Failed to extend introduction circuit: {}", e);
                continue;
            }
            Err(_) => {
                warn!("Timed out extending introduction circuit");
                continue;
            }
        }

        let my_sk = x25519_dalek::StaticSecret::new(&mut thread_rng());
        let my_pk = x25519_dalek::PublicKey::from(&my_sk);
        let b = x25519_dalek::PublicKey::from(intro_point.ntor_enc_key);
        let xb = my_sk.diffie_hellman(&b);

        let mut hasher = sha3::Shake256::default();
        hasher.update(xb.as_bytes());
        hasher.update(&intro_point.auth_key.key_type.as_bytes());
        hasher.update(&my_pk.to_bytes());
        hasher.update(&intro_point.ntor_enc_key);
        hasher.update(b"tor-hs-ntor-curve25519-sha3-256-1");
        hasher.update(b"tor-hs-ntor-curve25519-sha3-256-1:hs_key_extract");
        hasher.update(b"tor-hs-ntor-curve25519-sha3-256-1:hs_key_expand");
        hasher.update(&subcred);
        let mut kd = hasher.finalize_xof();

        let mut enc_key = [0; 32];
        let mut mac_key = [0; 32];
        kd.read(&mut enc_key);
        kd.read(&mut mac_key);

        let mut d = introduction_bytes.clone();
        let mut c = crate::Aes256::new_from_slices(&enc_key, &[0; 16]).unwrap();
        c.apply_keystream(&mut d);

        let mut introduce_1 = crate::cell::RelayIntroduce1 {
            auth_key: match intro_point.auth_key.key_type {
                crate::cert::KeyType::Ed25519(k) =>
                    crate::cell::RelayIntroduce1AuthKey::Ed25519(k),
                _ => {
                    warn!("Unsupported auth key type");
                    continue;
                }
            },
            extensions: vec![],
            client_pk: my_pk.to_bytes(),
            encrypted_data: d,
            mac: [0; 32],
        };

        let d = introduce_1.data()?;
        let mac = hs_ntor_mac(&mac_key, &d[..d.len()-32]);
        introduce_1.mac = mac;

        let resp = match tokio::time::timeout(
            crate::DEFAULT_TIMEOUT,
            intro_circ.send_introduction(introduce_1)
        ).await {
            Ok(Ok(r)) => r,
            Ok(Err(e)) => {
                warn!("Failed to send introduction: {}", e);
                continue;
            }
            Err(_) => {
                warn!("Timed out sending introduction");
                continue;
            }
        };

        if resp.status != crate::cell::RelayIntroduceAckStatus::Success {
            warn!("Introduction failed: {:?}", resp.status);
            continue;
        }

        return Ok(IntroductionInfo {
            my_sk,
            my_pk,
            ntor_enc_key: b,
            auth_key: intro_point.auth_key,
        })
    }

    return Err(std::io::Error::new(
        std::io::ErrorKind::HostUnreachable, "Failed to send introduction",
    ))
}

pub async fn connect<S: crate::storage::Storage + Send + Sync + 'static>(
    client: &crate::Client<S>, descriptor: &super::second_layer::Descriptor, subcred: &[u8]
) -> std::io::Result<crate::circuit::Circuit> {
    use sha3::digest::{Update, ExtendableOutput, XofReader};
    use aes::cipher::KeyIvInit;
    use aes::cipher::StreamCipher;

    let consensus = client.consensus().await?;
    let mut intro_points = descriptor.intro_points.clone();
    intro_points.shuffle(&mut thread_rng());

    let (rend_circ, introduction_inner) = make_rendezvous_point(&client, &consensus).await?;

    let kex_info = send_introduction(
        &client, &consensus, intro_points, &introduction_inner, subcred,
    ).await?;

    debug!("Waiting for rendezvous reply");
    let resp = rend_circ.recv_rendezvous().await?;
    let rend2 = Rendezvous2Inner::from_bytes(&resp.data)?;

    let other_pk = x25519_dalek::PublicKey::from(rend2.server_pk);
    let xy = kex_info.my_sk.diffie_hellman(&other_pk);
    let xb = kex_info.my_sk.diffie_hellman(&kex_info.ntor_enc_key);

    let mut rend_secret_hs_input = vec![];
    rend_secret_hs_input.extend(xy.as_bytes());
    rend_secret_hs_input.extend(xb.as_bytes());
    rend_secret_hs_input.extend(kex_info.auth_key.key_type.as_bytes());
    rend_secret_hs_input.extend(kex_info.ntor_enc_key.as_bytes());
    rend_secret_hs_input.extend(kex_info.my_pk.as_bytes());
    rend_secret_hs_input.extend(other_pk.as_bytes());
    rend_secret_hs_input.extend(b"tor-hs-ntor-curve25519-sha3-256-1");

    let ntor_key_seed = hs_ntor_mac(&rend_secret_hs_input, b"tor-hs-ntor-curve25519-sha3-256-1:hs_key_extract");
    let verify = hs_ntor_mac(&rend_secret_hs_input, b"tor-hs-ntor-curve25519-sha3-256-1:hs_verify");

    let mut auth_input = vec![];
    auth_input.extend(verify);
    auth_input.extend(kex_info.auth_key.key_type.as_bytes());
    auth_input.extend(kex_info.ntor_enc_key.as_bytes());
    auth_input.extend(other_pk.as_bytes());
    auth_input.extend(kex_info.my_pk.as_bytes());
    auth_input.extend(b"tor-hs-ntor-curve25519-sha3-256-1");
    auth_input.extend(b"Server");

    let auth_input_mac = hs_ntor_mac(&auth_input, b"tor-hs-ntor-curve25519-sha3-256-1:hs_mac");

    if ring::constant_time::verify_slices_are_equal(&auth_input_mac, &rend2.auth).is_err() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData, "Invalid rendezvous MAC",
        ))
    }

    let mut hk = sha3::Shake256::default();
    hk.update(&ntor_key_seed);
    hk.update(b"tor-hs-ntor-curve25519-sha3-256-1:hs_key_expand");
    let mut kd = hk.finalize_xof();

    let mut df = [0; 32];
    let mut db = [0; 32];
    let mut kf = [0; 32];
    let mut kb = [0; 32];
    kd.read(&mut df);
    kd.read(&mut db);
    kd.read(&mut kf);
    kd.read(&mut kb);
    rend_circ.insert_node_hs_v3(df, db, kf, kb).await;

    Ok(rend_circ)
}

fn hs_ntor_mac(key: &[u8], message: &[u8]) -> [u8; 32] {
    let mut d = sha3::Sha3_256::new();
    d.update((key.len() as u64).to_be_bytes());
    d.update(key);
    d.update(message);

    d.finalize().into()
}
