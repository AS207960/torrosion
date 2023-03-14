use std::ops::Deref;
use tokio::io::AsyncReadExt;
use base64::prelude::*;
use futures::StreamExt;
use ring::signature::VerificationAlgorithm;
use rsa::pkcs8::DecodePublicKey;
use rsa::PublicKey;
use x509_parser::prelude::FromDer;

async fn parse_server_descriptor<S: crate::storage::Storage + Send + Sync + 'static>(
    res: crate::http::HyperResponse, client: &crate::Client<S>
) -> std::io::Result<Descriptor> {
    if !res.status().is_success() {
        return Err(std::io::Error::new(std::io::ErrorKind::Other, "Got non-success response for server descriptor"));
    }

    let mut body = match res.read() {
        Ok(body) => crate::storage::SavingReader::new(body),
        Err(_) => {
            return Err(std::io::Error::new(std::io::ErrorKind::Other, "Failed to read response body"));
        }
    };

    let descriptor = Descriptor::parse(&mut body).await?;
    if !descriptor.verify() {
        return Err(std::io::Error::new(std::io::ErrorKind::Other, "Descriptor verification failed"));
    }
    {
        let d = body.buf();
        client.storage.save_server_descriptor(&descriptor.identity, &descriptor.rsa_hash.as_ref(), d)
    }.await?;

    Ok(descriptor)
}

pub(crate) async fn get_server_descriptor<S: crate::storage::Storage + Send + Sync + 'static>(
    router: &super::consensus::Router, client: &crate::Client<S>,
) -> std::io::Result<Descriptor> {
    if let Ok(mut r) = client.storage.load_server_descriptor(&router.identity, &router.digest).await {
        let descriptor = Descriptor::parse(&mut r).await?;

        if descriptor.rsa_hash.as_ref() != router.digest {
            return Err(std::io::Error::new(std::io::ErrorKind::Other, "Descriptor digest mismatch"));
        }

        if !descriptor.verify() {
            return Err(std::io::Error::new(std::io::ErrorKind::Other, "Descriptor verification failed"));
        }

        return Ok(descriptor);
    }

    let circ = client.get_ds_circuit().await?;
    let http_client = crate::http::new_directory_client(circ);

    let url = format!("http://dummy/tor/server/d/{}.z", hex::encode(&router.digest)).parse::<hyper::Uri>().unwrap();
    let res = crate::http::HyperResponse::new(
        match http_client.get(url).await {
            Ok(res) => res,
            Err(e) => return Err(std::io::Error::new(std::io::ErrorKind::Other, format!("Failed to fetch descriptor: {}", e))),
        }
    );

    let descriptor = parse_server_descriptor(res, client).await?;
    if descriptor.rsa_hash.as_ref() != router.digest {
        return Err(std::io::Error::new(std::io::ErrorKind::Other, "Descriptor digest mismatch"));
    }

    Ok(descriptor)
}

pub(crate) async fn get_server_descriptor_by_identity<S: crate::storage::Storage + Send + Sync + 'static>(
    router: crate::RsaIdentity, client: &crate::Client<S>,
) -> std::io::Result<Descriptor> {

    let circ = client.get_ds_circuit().await?;
    let http_client = crate::http::new_directory_client(circ);

    let url = format!("http://dummy/tor/server/fp/{}.z", router.to_hex()).parse::<hyper::Uri>().unwrap();
    let res = crate::http::HyperResponse::new(
        match http_client.get(url).await {
            Ok(res) => res,
            Err(e) => return Err(std::io::Error::new(std::io::ErrorKind::Other, format!("Failed to fetch descriptor: {}", e))),
        }
    );

    let descriptor = parse_server_descriptor(res, client).await?;
    Ok(descriptor)
}

#[derive(Debug)]
pub(crate) struct Descriptor {
    pub(crate) nickname: String,
    pub(crate) identity: crate::RsaIdentity,
    pub(crate) or_addresses: Vec<std::net::SocketAddr>,
    pub(crate) dir_port: Option<u16>,
    pub(crate) ed25519_identity: crate::cert::Cert,
    pub(crate) ed25519_master_key: [u8; 32],
    pub(crate) bandwidth: Bandwidth,
    pub(crate) platform: Option<String>,
    pub(crate) published: chrono::DateTime<chrono::Utc>,
    pub(crate) hibernating: bool,
    pub(crate) uptime: u64,
    pub(crate) onion_key: Vec<u8>,
    pub(crate) onion_key_crosscert: Vec<u8>,
    pub(crate) ntor_onion_key: [u8; 32],
    pub(crate) ntor_onion_key_crosscert: (crate::cert::Cert, bool),
    pub(crate) identity_key: Vec<u8>,
    pub(crate) exit_policy: Vec<ExitPolicy>,
    pub(crate) ipv6_policy: Option<super::consensus::RouterPortPolicy>,
    pub(crate) overload_general: Option<chrono::DateTime<chrono::Utc>>,
    pub(crate) contact: Option<String>,
    pub(crate) family: Vec<String>,
    pub(crate) caches_extra_info: bool,
    pub(crate) hidden_service_dir: bool,
    pub(crate) tunnelled_dir_server: bool,
    pub(crate) extra_info_digest: Option<ExtraInfoDigest>,
    pub(crate) protocols: super::consensus::Entries,
    ed25519_hash: ring::digest::Digest,
    ed25519_signature: Vec<u8>,
    rsa_hash: ring::digest::Digest,
    rsa_signature: Vec<u8>,
}

#[derive(Debug)]
pub(crate) enum ExitPolicy {
    Accept(ExitPattern),
    Reject(ExitPattern),
}

impl Descriptor {
    pub fn ed25519_key(&self) -> [u8; 32] {
        match self.ed25519_identity.key_type {
            crate::cert::KeyType::Ed25519(k) => k,
            _ => panic!("Invalid key type"),
        }
    }

    pub fn to_link_specifiers(&self) -> Vec<crate::cell::LinkSpecifier> {
        let mut link_specifiers = Vec::new();
        link_specifiers.extend(self.or_addresses.iter().filter_map(|addr| match addr {
            std::net::SocketAddr::V4(addr) => Some(crate::cell::LinkSpecifier::IPv4Address(*addr)),
            _ => None,
        }));
        link_specifiers.push(crate::cell::LinkSpecifier::LegacyIdentity(self.identity));
        link_specifiers.extend(self.or_addresses.iter().filter_map(|addr| match addr {
            std::net::SocketAddr::V6(addr) => Some(crate::cell::LinkSpecifier::IPv6Address(*addr)),
            _ => None,
        }));
        link_specifiers.push(crate::cell::LinkSpecifier::Ed25519Identity(self.ed25519_master_key));
        link_specifiers
    }

    fn verify(&self) -> bool {
        if self.ed25519_identity.verify_signature_ed25519(&self.ed25519_master_key).is_err() {
            return false;
        }

        let ed25519_key = match self.ed25519_identity.key_type {
            crate::cert::KeyType::Ed25519(k) => k,
            _ => return false,
        };

        if ring::signature::ED25519.verify(
            ed25519_key.as_slice().into(), self.ed25519_hash.as_ref().into(),
            self.ed25519_signature.as_slice().into()
        ).is_err() {
            return false;
        }

        let identity_key = match x509_parser::public_key::RSAPublicKey::from_der(&self.identity_key) {
            Ok(k) => k.1,
            Err(_) => return false,
        };
        let identity_key = match rsa::RsaPublicKey::new(
            rsa::BigUint::from_bytes_be(identity_key.modulus),
            rsa::BigUint::from_bytes_be(identity_key.exponent)
        ) {
            Ok(k) => k,
            Err(_) => return false,
        };
        if identity_key.verify(
            rsa::PaddingScheme::new_pkcs1v15_sign_raw(), self.rsa_hash.as_ref(), &self.rsa_signature
        ).is_err() {
            return false;
        }

        let mut onion_key_crosscert_sig_data: Vec<u8> = vec![];
        onion_key_crosscert_sig_data.extend(self.identity.deref().iter());
        onion_key_crosscert_sig_data.extend(self.ed25519_master_key.iter());
        let onion_key = match x509_parser::public_key::RSAPublicKey::from_der(&self.onion_key) {
            Ok(k) => k.1,
            Err(_) => return false,
        };
        let onion_key = match rsa::RsaPublicKey::new(
            rsa::BigUint::from_bytes_be(onion_key.modulus),
            rsa::BigUint::from_bytes_be(onion_key.exponent)
        ) {
            Ok(k) => k,
            Err(_) => return false,
        };
        if onion_key.verify(
            rsa::PaddingScheme::new_pkcs1v15_sign_raw(), &onion_key_crosscert_sig_data, &self.onion_key_crosscert
        ).is_err() {
            return false;
        }

        if self.ntor_onion_key_crosscert.0.cert_type != crate::cert::CertType::NtorOnionKey {
            return false;
        }
        match self.ntor_onion_key_crosscert.0.key_type {
            crate::cert::KeyType::Ed25519(k) => {
                if k != self.ed25519_master_key {
                    return false;
                }
            },
            _ => return false,
        }

        let point = curve25519_dalek::montgomery::MontgomeryPoint(self.ntor_onion_key);
        let edpoint = match point.to_edwards(if self.ntor_onion_key_crosscert.1 { 1 } else { 0 }) {
            Some(p) => p,
            None => return false,
        };
        let compressed_y = edpoint.compress();

        if let Err(e) = self.ntor_onion_key_crosscert.0.verify_signature_ed25519(&compressed_y.as_bytes()) {
            return false;
        }

        true
    }

    pub(crate) async fn parse<R: tokio::io::AsyncRead + Unpin + Send>(reader: &mut R) -> std::io::Result<Self> {
        let mut lines = super::LineReader::new(reader).iter_many_digest(&[
            &ring::digest::SHA1_FOR_LEGACY_USE_ONLY, &ring::digest::SHA256,
        ]);

        lines.digests[1].0.update(b"Tor router descriptor signature v1");

        let router = Router::parse(&mut lines).await?;

        let mut line = vec![];
        while let Some(p) = Line::parse(&mut lines).await? {
            line.push(p);
        }

        lines.digests[1].0.update(b"router-sig-ed25519 ");
        let ed25519_hash = lines.digests[1].0.clone().finish();
        let ed25519_signature = Ed25519Signature::parse(&mut lines).await?;

        let rsa_signature = RsaSignature::parse(&mut lines).await?;

        let mut or_addresses = vec![
            std::net::SocketAddr::new(std::net::IpAddr::V4(router.address), router.or_port),
        ];

        for or_addr in super::get_all!(line, Line::OrAddress) {
            or_addresses.push(or_addr);
        }

        let mut exit_policy = vec![];

        for l in &line {
            match l {
                Line::Accept(p) => exit_policy.push(ExitPolicy::Accept(p.clone())),
                Line::Reject(p) => exit_policy.push(ExitPolicy::Reject(p.clone())),
                _ => (),
            }
        }

        let ed25519_identity = match crate::cert::Cert::from_bytes(
            super::get_exactly_once!(line, Line::Ed25519Identity)
        ) {
            Ok(cert) => cert,
            Err(e) => return Err(std::io::Error::new(std::io::ErrorKind::Other, format!("Failed to parse Ed25519 identity: {}", e))),
        };
        let ed25519_master_key = match TryInto::<[u8; 32]>::try_into(
            super::get_exactly_once!(line, Line::Ed25519MasterKey)
        ) {
            Ok(key) => key,
            Err(_) => return Err(std::io::Error::new(std::io::ErrorKind::Other, "Ed25519 master key is not 32 bytes")),
        };
        let ntor_onion_key = match TryInto::<[u8; 32]>::try_into(
            super::get_exactly_once!(line, Line::NtorOnionKey)
        ) {
            Ok(key) => key,
            Err(_) => return Err(std::io::Error::new(std::io::ErrorKind::Other, "Ed25519 master key is not 32 bytes")),
        };
        let ntor_onion_key_crosscert = super::get_exactly_once!(line, Line::NtorOnionKeyCrosscert);
        let ntor_onion_key_crosscert_cert = match crate::cert::Cert::from_bytes(ntor_onion_key_crosscert.0) {
            Ok(cert) => cert,
            Err(e) => return Err(std::io::Error::new(std::io::ErrorKind::Other, format!("Failed to parse ntor onion key crosscert: {}", e))),
        };

        Ok(Descriptor {
            nickname: router.nickname,
            identity: super::get_exactly_once!(line, Line::Fingerprint),
            or_addresses,
            dir_port: if router.dir_port == 0 { None } else { Some(router.dir_port) },
            ed25519_identity,
            ed25519_master_key,
            bandwidth: super::get_exactly_once!(line, Line::Bandwidth),
            platform: super::get_at_most_once!(line, Line::Platform),
            published: super::get_exactly_once!(line, Line::Published),
            hibernating: super::get_at_most_once!(line, Line::Hibernating).unwrap_or(false),
            uptime: super::get_at_most_once!(line, Line::Uptime).unwrap_or(0),
            onion_key: super::get_exactly_once!(line, Line::OnionKey),
            onion_key_crosscert: super::get_exactly_once!(line, Line::OnionKeyCrosscert),
            ntor_onion_key,
            ntor_onion_key_crosscert: (ntor_onion_key_crosscert_cert, ntor_onion_key_crosscert.1),
            identity_key: super::get_exactly_once!(line, Line::SigningKey),
            exit_policy,
            ipv6_policy: super::get_at_most_once!(line, Line::Ipv6Policy),
            overload_general: super::get_at_most_once!(line, Line::Overload),
            contact: super::get_at_most_once!(line, Line::Contact),
            family: super::get_at_most_once!(line, Line::Family).unwrap_or(vec![]),
            caches_extra_info: super::get_at_most_once!(line, Line::CachesExtraInfo).is_some(),
            hidden_service_dir: super::get_at_most_once!(line, Line::HiddenServiceDir).is_some(),
            tunnelled_dir_server: super::get_at_most_once!(line, Line::TunnelledDirServer).is_some(),
            extra_info_digest: super::get_at_most_once!(line, Line::ExtraInfoDigest),
            protocols: super::get_exactly_once!(line, Line::Protocols),
            ed25519_hash,
            ed25519_signature: ed25519_signature.signature,
            rsa_hash: lines.digest_i(0),
            rsa_signature: rsa_signature.signature,
        })
    }
}

struct Router {
    nickname: String,
    address: std::net::Ipv4Addr,
    or_port: u16,
    socks_port: u16,
    dir_port: u16,
}

impl Router {
    async fn parse(reader: &mut super::LineReaderIter<'_>) -> std::io::Result<Self> {
        let line = match reader.next().await {
            Some(l) => l?,
            None => return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput, "Invalid router line",
            )),
        };
        let mut parts = line.trim().split(" ");
        let def = parts.next().ok_or(std::io::Error::new(
            std::io::ErrorKind::InvalidInput, "Invalid router line",
        ))?;
        if def != "router" {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput, "Invalid router line",
            ));
        }
        let nickname = parts.next().ok_or(std::io::Error::new(
            std::io::ErrorKind::InvalidInput, "Invalid router line",
        ))?;
        let address = parts.next().ok_or(std::io::Error::new(
            std::io::ErrorKind::InvalidInput, "Invalid router line",
        ))?;
        let address = address.parse::<std::net::Ipv4Addr>().map_err(|_| std::io::Error::new(
            std::io::ErrorKind::InvalidInput, "Invalid router line",
        ))?;
        let or_port = parts.next().ok_or(std::io::Error::new(
            std::io::ErrorKind::InvalidInput, "Invalid router line",
        ))?;
        let or_port = or_port.parse::<u16>().map_err(|_| std::io::Error::new(
            std::io::ErrorKind::InvalidInput, "Invalid router line",
        ))?;
        let socks_port = parts.next().ok_or(std::io::Error::new(
            std::io::ErrorKind::InvalidInput, "Invalid router line",
        ))?;
        let socks_port = socks_port.parse::<u16>().map_err(|_| std::io::Error::new(
            std::io::ErrorKind::InvalidInput, "Invalid router line",
        ))?;
        let dir_port = parts.next().ok_or(std::io::Error::new(
            std::io::ErrorKind::InvalidInput, "Invalid router line",
        ))?;
        let dir_port = dir_port.parse::<u16>().map_err(|_| std::io::Error::new(
            std::io::ErrorKind::InvalidInput, "Invalid router line",
        ))?;
        Ok(Self {
            nickname: nickname.to_string(),
            address,
            or_port,
            socks_port,
            dir_port,
        })
    }
}

#[derive(Debug)]
enum Line {
    Ed25519Identity(Vec<u8>),
    Ed25519MasterKey(Vec<u8>),
    Bandwidth(Bandwidth),
    Platform(String),
    Published(chrono::DateTime<chrono::Utc>),
    Fingerprint(crate::RsaIdentity),
    Hibernating(bool),
    Uptime(u64),
    OnionKey(Vec<u8>),
    OnionKeyCrosscert(Vec<u8>),
    NtorOnionKey(Vec<u8>),
    NtorOnionKeyCrosscert((Vec<u8>, bool)),
    SigningKey(Vec<u8>),
    Accept(ExitPattern),
    Reject(ExitPattern),
    Ipv6Policy(super::consensus::RouterPortPolicy),
    Overload(chrono::DateTime<chrono::Utc>),
    Contact(String),
    Family(Vec<String>),
    CachesExtraInfo(()),
    ExtraInfoDigest(ExtraInfoDigest),
    HiddenServiceDir(()),
    OrAddress(std::net::SocketAddr),
    TunnelledDirServer(()),
    Protocols(super::consensus::Entries),
}

impl Line {
    async fn parse(reader: &mut super::LineReaderIter<'_>) -> std::io::Result<Option<Self>> {
        loop {
            let line = match reader.next_if(|l| match l {
                Ok(l) => !l.starts_with("router-sig-ed25519") && !l.starts_with("router-signature"),
                Err(_) => true
            }).await {
                Some(l) => l?,
                None => return Ok(None)
            };

            let mut parts = line.trim().split(" ");
            let def = parts.next().ok_or(std::io::Error::new(
                std::io::ErrorKind::InvalidInput, "Invalid server descriptor",
            ))?;
            return Ok(Some(match def {
                "identity-ed25519" => {
                    let cert = super::read_pem(reader).await.map_err(|_| std::io::Error::new(
                        std::io::ErrorKind::InvalidInput, "Invalid ed25519 identity",
                    ))?;
                    Self::Ed25519Identity(cert.contents)
                }
                "master-key-ed25519" => {
                    let key = parts.next().ok_or(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput, "Invalid ed25519 master key",
                    ))?;
                    let key = BASE64_STANDARD_NO_PAD.decode(&key).map_err(|_| std::io::Error::new(
                        std::io::ErrorKind::InvalidInput, "Invalid ed25519 master key",
                    ))?;
                    Self::Ed25519MasterKey(key)
                }
                "bandwidth" => Self::Bandwidth(Bandwidth::parse(&mut parts)?),
                "platform" => {
                    Self::Platform(parts.collect::<Vec<_>>().join(" "))
                }
                "published" => {
                    let date = parts.next().ok_or(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput, "Invalid published line",
                    ))?;
                    let time = parts.next().ok_or(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput, "Invalid published line",
                    ))?;
                    let date_time = chrono::NaiveDateTime::parse_from_str(&format!("{} {}", date, time), "%Y-%m-%d %H:%M:%S").map_err(|_| std::io::Error::new(
                        std::io::ErrorKind::InvalidInput, "Invalid published line",
                    ))?;
                    Self::Published(chrono::DateTime::from_utc(date_time, chrono::Utc))
                }
                "fingerprint" => {
                    let fingerprint = (0..10).map(|_| Ok::<_, std::io::Error>(parts.next().ok_or(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput, "Invalid fingerprint line",
                    ))?.to_string())).collect::<Result<Vec<_>, _>>()?.join("");
                    let fingerprint = crate::RsaIdentity::from_hex(&fingerprint).map_err(|_| std::io::Error::new(
                        std::io::ErrorKind::InvalidInput, "Invalid fingerprint line",
                    ))?;
                    Self::Fingerprint(fingerprint)
                }
                "hibernating" => {
                    let hibernating = parts.next().ok_or(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput, "Invalid hibernating line",
                    ))?;
                    if hibernating == "true" || hibernating == "1" {
                        Self::Hibernating(true)
                    } else if hibernating == "false" || hibernating == "0" {
                        Self::Hibernating(false)
                    } else {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidInput, "Invalid hibernating line",
                        ));
                    }
                }
                "uptime" => {
                    let uptime = parts.next().ok_or(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput, "Invalid uptime line",
                    ))?;
                    let uptime = uptime.parse::<u64>().map_err(|_| std::io::Error::new(
                        std::io::ErrorKind::InvalidInput, "Invalid uptime line",
                    ))?;
                    Self::Uptime(uptime)
                }
                "onion-key" => {
                    let key = super::read_pem(reader).await.map_err(|_| std::io::Error::new(
                        std::io::ErrorKind::InvalidInput, "Invalid onion key",
                    ))?;
                    Self::OnionKey(key.contents)
                }
                "onion-key-crosscert" => {
                    let cert = super::read_pem(reader).await.map_err(|_| std::io::Error::new(
                        std::io::ErrorKind::InvalidInput, "Invalid onion key crosscert",
                    ))?;
                    Self::OnionKeyCrosscert(cert.contents)
                }
                "ntor-onion-key" => {
                    let key = parts.next().ok_or(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput, "Invalid ntor onion key",
                    ))?;
                    let key = BASE64_STANDARD_NO_PAD.decode(&key).map_err(|_| std::io::Error::new(
                        std::io::ErrorKind::InvalidInput, "Invalid ntor onion key",
                    ))?;
                    Self::NtorOnionKey(key)
                }
                "ntor-onion-key-crosscert" => {
                    let bit = parts.next().ok_or(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput, "Invalid ntor onion key crosscert",
                    ))?;
                    let bit = match bit {
                        "0" => false,
                        "1" => true,
                        _ => return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidInput, "Invalid ntor onion key crosscert",
                        ))
                    };
                    let cert = super::read_pem(reader).await.map_err(|_| std::io::Error::new(
                        std::io::ErrorKind::InvalidInput, "Invalid ntor onion key crosscert",
                    ))?;
                    Self::NtorOnionKeyCrosscert((cert.contents, bit))
                }
                "signing-key" => {
                    let key = super::read_pem(reader).await.map_err(|_| std::io::Error::new(
                        std::io::ErrorKind::InvalidInput, "Invalid signing key",
                    ))?;
                    Self::SigningKey(key.contents)
                }
                "accept" => Self::Accept(ExitPattern::parse(&mut parts)?),
                "reject" => Self::Reject(ExitPattern::parse(&mut parts)?),
                "ipv6-policy" => Self::Ipv6Policy(super::consensus::RouterPortPolicy::parse(&mut parts)?),
                "overload-general" => {
                    let version = parts.next().ok_or(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput, "Invalid overload-general line",
                    ))?;
                    if version != "1" {
                        continue;
                    }

                    let date = parts.next().ok_or(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput, "Invalid overload-general line",
                    ))?;
                    let time = parts.next().ok_or(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput, "Invalid overload-general line",
                    ))?;
                    let date_time = chrono::NaiveDateTime::parse_from_str(&format!("{} {}", date, time), "%Y-%m-%d %H:%M:%S").map_err(|_| std::io::Error::new(
                        std::io::ErrorKind::InvalidInput, "Invalid overload-general line",
                    ))?;
                    Self::Overload(chrono::DateTime::from_utc(date_time, chrono::Utc))
                }
                "contact" => {
                    Self::Contact(parts.collect::<Vec<_>>().join(" "))
                }
                "family" => {
                    Self::Family(parts.map(|s| s.to_string()).collect::<Vec<_>>())
                }
                "caches-extra-info" => {
                    Self::CachesExtraInfo(())
                }
                "extra-info-digest" => Self::ExtraInfoDigest(ExtraInfoDigest::parse(&mut parts)?),
                "hidden-service-dir" => {
                    Self::HiddenServiceDir(())
                }
                "or-address" => {
                    let address = parts.next().ok_or(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput, "Invalid or-address line",
                    ))?;
                    let address = address.parse::<std::net::SocketAddr>().map_err(|_| std::io::Error::new(
                        std::io::ErrorKind::InvalidInput, "Invalid or-address line",
                    ))?;
                    Self::OrAddress(address)
                }
                "tunnelled-dir-server" => {
                    Self::TunnelledDirServer(())
                }
                "proto" => Self::Protocols(super::consensus::Entries::parse(&mut parts)?),
                _ => continue
            }));
        }
    }
}

#[derive(Debug)]
pub(crate) struct Bandwidth {
    average: u64,
    burst: u64,
    observed: u64,
}

impl Bandwidth {
    fn parse(parts: &mut std::str::Split<'_, &str>) -> std::io::Result<Self> {
        let average = parts.next().ok_or(std::io::Error::new(
            std::io::ErrorKind::InvalidInput, "Invalid bandwidth line",
        ))?;
        let average = average.parse::<u64>().map_err(|_| std::io::Error::new(
            std::io::ErrorKind::InvalidInput, "Invalid bandwidth line",
        ))?;
        let burst = parts.next().ok_or(std::io::Error::new(
            std::io::ErrorKind::InvalidInput, "Invalid bandwidth line",
        ))?;
        let burst = burst.parse::<u64>().map_err(|_| std::io::Error::new(
            std::io::ErrorKind::InvalidInput, "Invalid bandwidth line",
        ))?;
        let observed = parts.next().ok_or(std::io::Error::new(
            std::io::ErrorKind::InvalidInput, "Invalid bandwidth line",
        ))?;
        let observed = observed.parse::<u64>().map_err(|_| std::io::Error::new(
            std::io::ErrorKind::InvalidInput, "Invalid bandwidth line",
        ))?;
        Ok(Self {
            average,
            burst,
            observed,
        })
    }
}

#[derive(Debug, Clone)]
pub(crate) struct ExitPattern {
    pub(crate) addr: Option<std::net::IpAddr>,
    pub(crate) mask: u8,
    pub(crate) ports: std::ops::RangeInclusive<u16>,
}

impl ExitPattern {
    pub fn matches(&self, addr: std::net::IpAddr, port: u16) -> bool {
        if let Some(o_addr) = self.addr {
            match (addr, o_addr) {
                (std::net::IpAddr::V4(addr), std::net::IpAddr::V4(o_addr)) => {
                    let addr = u32::from(addr) >> (32 - self.mask);
                    let o_addr = u32::from(o_addr) >> (32 - self.mask);
                    if addr != o_addr {
                        return false;
                    }
                }
                (std::net::IpAddr::V6(addr), std::net::IpAddr::V6(o_addr)) => {
                    let addr = u128::from(addr) >> (128 - self.mask);
                    let o_addr = u128::from(o_addr) >> (128 - self.mask);
                    if addr != o_addr {
                        return false;
                    }
                }
                _ => return false
            }
        }

        if !self.ports.contains(&port) {
            return false;
        }

        true
    }

    fn parse(line: &mut std::str::Split<&str>) -> std::io::Result<Self> {
        let exit_pattern = line.next().ok_or(std::io::Error::new(
            std::io::ErrorKind::InvalidInput, "Invalid exit pattern line",
        ))?;
        let (addr, ports) = exit_pattern.rsplit_once(':').ok_or(std::io::Error::new(
            std::io::ErrorKind::InvalidInput, "Invalid exit pattern line",
        ))?;
        let ports = if ports == "*" {
            0..=65535
        } else {
            match ports.split_once('-') {
                Some((start, end)) => {
                    let start = start.parse::<u16>().map_err(|_| std::io::Error::new(
                        std::io::ErrorKind::InvalidInput, "Invalid exit pattern line",
                    ))?;
                    let end = end.parse::<u16>().map_err(|_| std::io::Error::new(
                        std::io::ErrorKind::InvalidInput, "Invalid exit pattern line",
                    ))?;
                    start..=end
                }
                None => {
                    let port = ports.parse::<u16>().map_err(|_| std::io::Error::new(
                        std::io::ErrorKind::InvalidInput, "Invalid exit pattern line",
                    ))?;
                    port..=port
                }
            }
        };
        let (addr, mask) = if addr == "*" {
            (None, 0)
        } else {
            match addr.rsplit_once('/') {
                Some((addr, mask)) => {
                    let addr = addr.parse::<std::net::IpAddr>().map_err(|_| std::io::Error::new(
                        std::io::ErrorKind::InvalidInput, "Invalid exit pattern line",
                    ))?;
                    let mask = match addr {
                        std::net::IpAddr::V4(_) => {
                            let mask = match mask.parse::<std::net::Ipv4Addr>() {
                                Ok(m) => (!u32::from(m)).leading_zeros() as u8,
                                Err(_) => mask.parse::<u8>().map_err(|_| std::io::Error::new(
                                    std::io::ErrorKind::InvalidInput, "Invalid exit pattern line",
                                ))?
                            };
                            if mask > 32 {
                                return Err(std::io::Error::new(
                                    std::io::ErrorKind::InvalidInput, "Invalid exit pattern line",
                                ));
                            }
                            mask
                        }
                        std::net::IpAddr::V6(_) => {
                            let mask = mask.parse::<u8>().map_err(|_| std::io::Error::new(
                                std::io::ErrorKind::InvalidInput, "Invalid exit pattern line",
                            ))?;
                            if mask > 128 {
                                return Err(std::io::Error::new(
                                    std::io::ErrorKind::InvalidInput, "Invalid exit pattern line",
                                ));
                            }
                            mask
                        }
                    };
                    (Some(addr), mask)
                }
                None => {
                    let addr = addr.parse::<std::net::IpAddr>().map_err(|_| std::io::Error::new(
                        std::io::ErrorKind::InvalidInput, "Invalid exit pattern line",
                    ))?;
                    let mask = match addr {
                        std::net::IpAddr::V4(_) => 32,
                        std::net::IpAddr::V6(_) => 128
                    };
                    (Some(addr), mask)
                }
            }
        };
        Ok(Self {
            addr,
            mask,
            ports,
        })
    }
}

#[derive(Debug)]
pub(crate) struct ExtraInfoDigest {
    pub(crate) sha1: [u8; 20],
    pub(crate) sha256: Option<[u8; 32]>,
}

impl ExtraInfoDigest {
    pub fn parse(line: &mut std::str::Split<&str>) -> std::io::Result<Self> {
        let sha1 = line.next().ok_or(std::io::Error::new(
            std::io::ErrorKind::InvalidInput, "Invalid extra-info-digest line",
        ))?;
        let sha1 = hex::decode(sha1).map_err(|_| std::io::Error::new(
            std::io::ErrorKind::InvalidInput, "Invalid extra-info-digest line",
        ))?;
        let sha1 = TryInto::<[u8; 20]>::try_into(sha1).map_err(|_| std::io::Error::new(
            std::io::ErrorKind::InvalidInput, "Invalid extra-info-digest line",
        ))?;
        let sha256 = line.next().map(|s| -> Result<_, std::io::Error> {
            let sha256 = BASE64_STANDARD_NO_PAD.decode(s).map_err(|_| std::io::Error::new(
                std::io::ErrorKind::InvalidInput, "Invalid extra-info-digest line",
            ))?;
            let sha256 = TryInto::<[u8; 32]>::try_into(sha256).map_err(|_| std::io::Error::new(
                std::io::ErrorKind::InvalidInput, "Invalid extra-info-digest line",
            ))?;
            Ok(sha256)
        }).transpose()?;

        Ok(Self {
            sha1,
            sha256,
        })
    }
}

struct Ed25519Signature {
    pub signature: Vec<u8>,
}

impl Ed25519Signature {
    async fn parse(reader: &mut super::LineReaderIter<'_>) -> std::io::Result<Self> {
        let line = match reader.next().await {
            Some(l) => l?,
            None => return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof, "Unexpected EOF",
            ))
        };

        let mut parts = line.trim().split(" ");
        let def = parts.next().ok_or(std::io::Error::new(
            std::io::ErrorKind::InvalidInput, "Invalid router-sig-ed25519 line",
        ))?;
        if def != "router-sig-ed25519" {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput, "Invalid router-sig-ed25519 line",
            ));
        }
        let signature = parts.next().ok_or(std::io::Error::new(
            std::io::ErrorKind::InvalidInput, "Invalid router-sig-ed25519 line",
        ))?;
        let signature = BASE64_STANDARD_NO_PAD.decode(signature).map_err(|_| std::io::Error::new(
            std::io::ErrorKind::InvalidInput, "Invalid router-sig-ed25519 line",
        ))?;

        Ok(Self {
            signature
        })
    }
}

struct RsaSignature {
    pub signature: Vec<u8>,
}

impl RsaSignature {
    async fn parse(reader: &mut super::LineReaderIter<'_>) -> std::io::Result<Self> {
        let line = match reader.next().await {
            Some(l) => l?,
            None => return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof, "Unexpected EOF",
            ))
        };

        let mut parts = line.trim().split(" ");
        let def = parts.next().ok_or(std::io::Error::new(
            std::io::ErrorKind::InvalidInput, "Invalid router-signature line",
        ))?;
        if def != "router-signature" {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput, "Invalid router-signature line",
            ));
        }

        reader.stop_digesting_one(0);

        let signature = match super::read_pem(reader).await {
            Ok(s) => s.contents,
            Err(e) => return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput, "Invalid router-signature line",
            ))
        };

        Ok(Self {
            signature
        })
    }
}