use rand::prelude::*;
use crate::{cell, cert};

fn is_v3_handshake<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(
    connection: &async_native_tls::TlsStream<S>
) -> bool {
    let cert = match connection.peer_certificate() {
        Ok(Some(cert)) => cert,
        _ => return false,
    };

    let cert_der = match cert.to_der() {
        Ok(der) => der,
        Err(_) => return false,
    };
    let cert = match x509_parser::parse_x509_certificate(&cert_der) {
        Ok((_, cert)) => cert,
        Err(_) => return false,
    };

    // The certificate is self-signed
    match cert::verify_x509_signature(&cert, None) {
        Ok(()) => return true,
        _ => {}
    }

    // Some component other than "commonName" is set in the subject or issuer DN of the certificate.
    if cert.issuer().iter_attributes()
        .any(|entry| entry.attr_type() != &oid_registry::OID_X509_COMMON_NAME) ||
        cert.issuer().iter_attributes()
            .any(|entry| entry.attr_type() != &oid_registry::OID_X509_COMMON_NAME) {
        return true;
    }

    // The commonName of the subject or issuer of the certificate ends with a suffix other than ".net".
    if let Some(issuer_cn) = cert.issuer().iter_common_name().next() {
        let issuer_cn = match issuer_cn.as_str() {
            Ok(cn) => cn,
            Err(_) => return false
        };
        if !issuer_cn.ends_with(".net") {
            return true;
        }
    }
    if let Some(subject_cn) = cert.subject().iter_common_name().next() {
        let subject_cn = match subject_cn.as_str() {
            Ok(cn) => cn,
            Err(_) => return false
        };
        if !subject_cn.ends_with(".net") {
            return true;
        }
    }

    // The certificate's public key modulus is longer than 1024 bits.
    let pubkey = match cert.public_key().parsed() {
        Ok(pubkey) => pubkey,
        Err(_) => return false,
    };
    if pubkey.key_size() > 1024 {
        return true;
    }

    false
}

struct InnerConnection {
    identity: crate::RsaIdentity,
    protocol_version: u16,
    stream: async_native_tls::TlsStream<tokio::net::TcpStream>,
    local_addr: std::net::SocketAddr,
    peer_addr: std::net::SocketAddr,
}

impl InnerConnection {
    async fn negotiate_connection(&mut self) -> std::io::Result<u16> {
        let version_cell = cell::Cell {
            circuit_id: 0,
            command: cell::Command::Versions(cell::Versions {
                versions: crate::VERSIONS.to_vec()
            })
        };
        self.write_cell(&version_cell).await?;

        let cell = self.read_next_cell().await?;
        if cell.circuit_id != 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other, "unexpected circuit ID in negotiation"
            ));
        }
        let cp_versions = match cell.command {
            cell::Command::Versions(v) => v,
            o => return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("unexpected command in negotiation {:?}", o)
            )),
        };
        self.protocol_version = cp_versions.upgrade_protocol_version();
        if self.protocol_version == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("{}: no common protocol versions", self.identity)
            ));
        }
        debug!("{}: using protocol version {}", self.identity, self.protocol_version);

        let cell = self.read_next_cell().await?;
        if cell.circuit_id != 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other, "unexpected circuit ID in negotiation",
            ));
        }
        let certs = match cell.command {
            cell::Command::Certs(c) => c,
            o => return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("unexpected command in negotiation {:?}", o)
            )),
        };
        self.validate_certs(&certs)?;
        let id_cert = match x509_parser::parse_x509_certificate(certs.identity_cert.as_ref().unwrap() ) {
            Ok((_, cert)) => cert,
            Err(e) => return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData, format!("invalid identity cert: {}", e)
            ))
        };
        let peer_identity = crate::RsaIdentity::from_asn1(
            id_cert.public_key().subject_public_key.as_ref()
        )?;
        if peer_identity != self.identity {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("{}: peer identity mismatch", self.identity)
            ));
        }
        debug!("{}: validated identity certificate", self.identity);

        let cell = self.read_next_cell().await?;
        if cell.circuit_id != 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other, "unexpected circuit ID in negotiation",
            ));
        }
        let auth_challenge = match cell.command {
            cell::Command::AuthChollenge(c) => c,
            o => return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("unexpected command in negotiation {:?}", o)
            )),
        };
        debug!("{}: received auth challenge {:?}", self.identity, auth_challenge);

        // Here is where authentication would go, if we where to implement it.

        let cell = self.read_next_cell().await?;
        if cell.circuit_id != 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other, "unexpected circuit ID in negotiation",
            ));
        }
        let peer_netinfo = match cell.command {
            cell::Command::Netinfo(c) => c,
            o => return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("unexpected command in negotiation {:?}", o)
            )),
        };
        trace!("{}: received netinfo {:?}", self.identity, peer_netinfo);

        if peer_netinfo.timestamp > chrono::Utc::now() + chrono::Duration::seconds(60) {
            warn!("{}: netinfo timestamp is in the future", self.identity);
        }
        if peer_netinfo.timestamp < chrono::Utc::now() - chrono::Duration::seconds(60) {
            warn!("{}: netinfo timestamp is in the past", self.identity);
        }

        if !peer_netinfo.my_addresses.contains(&self.peer_addr.ip()) {
            warn!("{}: not connected on canonical address", self.identity);
        }

        let own_netinfo_cell = cell::Cell {
            circuit_id: 0,
            command: cell::Command::Netinfo(cell::Netinfo {
                timestamp: chrono::DateTime::default(),
                other_address: self.peer_addr.ip(),
                my_addresses: vec![]
            })
        };
        self.write_cell(&own_netinfo_cell).await?;

        Ok(self.protocol_version)
    }

    fn validate_certs(&self, certs: &cell::Certs) -> std::io::Result<()> {
        let now = chrono::Utc::now();
        let asn1_now = x509_parser::time::ASN1Time::from_timestamp(now.timestamp()).unwrap();

        match (&certs.identity_cert, &certs.ed25519_identity_cert) {
            (Some(rsa_id), Some(ed25519_id)) => {
                let rsa_id = match x509_parser::parse_x509_certificate(rsa_id) {
                    Ok((_, cert)) => cert,
                    Err(e) => return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData, format!("invalid identity cert: {}", e)
                    ))
                };

                // The CERTS cell contains exactly one CertType 4 Ed25519 "Id->Signing" cert.
                let ed25519_signing_key = match &certs.ed25519_signing_key {
                    Some(k) => k,
                    None => return Err(std::io::Error::new(
                        std::io::ErrorKind::Other, "no Ed25519 signing key",
                    ))
                };
                let ed25519_signing_pkey = match &ed25519_signing_key.key_type {
                    cert::KeyType::Ed25519(k) => k,
                    _ => return Err(std::io::Error::new(
                        std::io::ErrorKind::Other, "Ed25519 signing key not an Ed25519 key",
                    ))
                };
                // The CERTS cell contains exactly one CertType 5 Ed25519 "Signing->link" certificate.
                let tls_link_cert = match &certs.tls_link_cert {
                    Some(k) => k,
                    None => return Err(std::io::Error::new(
                        std::io::ErrorKind::Other, "no TLS link certificate",
                    ))
                };

                // All X.509 certificates above have validAfter and validUntil dates;
                // no X.509 or Ed25519 certificates are expired.
                if rsa_id.validity.not_before > asn1_now || rsa_id.validity.not_after < asn1_now {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::Other, "identity certificate expired"
                    ));
                }
                if ed25519_signing_key.expiration < now {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::Other, "Ed25519 signing key expired"
                    ));
                }
                if tls_link_cert.expiration < now {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::Other, "TLS link certificate expired",
                    ));
                }
                if ed25519_id.expiration < now {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::Other, "Ed25519 identity certificate expired",
                    ));
                }

                let rsa_pubkey = match rsa_id.public_key().parsed() {
                    Ok(k) => k,
                    Err(_) => return Err(std::io::Error::new(
                        std::io::ErrorKind::Other, "identity certificate has invalid key",
                    ))
                };

                // The certified key in the ID certificate is a 1024-bit RSA key.
                if rsa_pubkey.key_size() != 1024 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::Other, "identity certificate has wrong key size",
                    ));
                }

                // The RSA ID certificate is correctly self-signed.
                if cert::verify_x509_signature(&rsa_id, None).is_err() {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::Other, "identity certificate incorrectly signed"
                    ));
                }

                // The RSA->Ed25519 cross-certificate certifies the Ed25519 identity,
                // and is signed with the RSA identity listed in the "ID" certificate.
                ed25519_id.verify_signature(&rsa_id.public_key().raw)?;

                // The Signing->Link cert was signed with the Signing key listed in the ID->Signing cert.
                tls_link_cert.verify_signature_ed25519(&ed25519_signing_pkey)?;

                // The identity key listed in the ID->Signing cert was used to sign the ID->Signing Cert.
                ed25519_signing_key.verify_signature_ed25519(&ed25519_id.ed25519_key)?;

                // The certified key in the Signing->Link certificate matches the SHA256 digest of
                // the certificate that was used to authenticate the TLS connection.
                let conn_cert = self.stream.peer_certificate().ok().and_then(|c| c).ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::Other,
                        "no certificate used to authenticate TLS connection",
                    )
                })?;
                let conn_cert_der = conn_cert.to_der().map_err(|e| {
                    std::io::Error::new(
                        std::io::ErrorKind::Other,
                        format!("failed to DER encode TLS connection certificate: {}", e),
                    )
                })?;
                let conn_cert_digest = ring::digest::digest(&ring::digest::SHA256, &conn_cert_der);
                match &tls_link_cert.key_type {
                    cert::KeyType::X509Sha256(key_digest) => {
                        if ring::constant_time::verify_slices_are_equal(conn_cert_digest.as_ref(), key_digest).is_err() {
                            return Err(std::io::Error::new(
                                std::io::ErrorKind::Other,
                                "TLS link certificate is not over certificate used to authenticate TLS connection"
                            ));
                        }
                    },
                    _ => return Err(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        "TLS link certificate is not an X509Sha256 key"
                    ))
                }
            },
            (Some(rsa_id), None) => {
                let rsa_id = match x509_parser::parse_x509_certificate(rsa_id) {
                    Ok((_, cert)) => cert,
                    Err(e) => return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData, format!("Invalid identity cert: {}", e)
                    ))
                };

                // The CERTS cell contains exactly one CertType 1 "Link" certificate.
                let link_cert = match &certs.link_key_cert {
                    Some(k) => match x509_parser::parse_x509_certificate(k) {
                        Ok((_, cert)) => cert,
                        Err(e) => return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData, format!("invalid link cert: {}", e)
                        ))
                    },
                    None => return Err(std::io::Error::new(
                        std::io::ErrorKind::Other, "no link certificate",
                    ))
                };

                // Both certificates have validAfter and validUntil dates that are not expired.
                if rsa_id.validity.not_before > asn1_now || rsa_id.validity.not_after < asn1_now  {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::Other, "identity certificate expired"
                    ));
                }
                if link_cert.validity.not_before > asn1_now || link_cert.validity.not_after < asn1_now  {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::Other, "link certificate expired"
                    ));
                }

                // The certified key in the Link certificate matches the link key that was used to
                // negotiate the TLS connection.
                let conn_cert = self.stream.peer_certificate().ok().and_then(|c| c).ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::Other,
                        "no certificate used to authenticate TLS connection",
                    )
                })?;
                let conn_cert_der = conn_cert.to_der().map_err(|e| {
                    std::io::Error::new(
                        std::io::ErrorKind::Other,
                        format!("failed to DER encode TLS connection certificate: {}", e),
                    )
                })?;
                let conn_cert = match x509_parser::parse_x509_certificate(&conn_cert_der) {
                    Ok((_, cert)) => cert,
                    Err(_) => return Err(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        "could not parse certificate used to authenticate TLS connection"
                    ))
                };
                if conn_cert.public_key() != link_cert.public_key() {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        "link certificate is not over certificate used to authenticate TLS connection"
                    ));
                }

                let rsa_pubkey = match rsa_id.public_key().parsed() {
                    Ok(k) => k,
                    Err(_) => return Err(std::io::Error::new(
                        std::io::ErrorKind::Other, "identity certificate has invalid key",
                    ))
                };

                // The certified key in the ID certificate is a 1024-bit RSA key.
                if rsa_pubkey.key_size() != 1024 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::Other, "identity certificate has wrong key size",
                    ));
                }

                // The link certificate is correctly signed with the key in the ID certificate
                if cert::verify_x509_signature(&link_cert, Some(rsa_id.public_key())).is_err() {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::Other, "link certificate incorrectly signed"
                    ));
                }

                // The RSA ID certificate is correctly self-signed.
                if cert::verify_x509_signature(&rsa_id, None).is_err() {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::Other, "identity certificate incorrectly signed"
                    ));
                }

            },
            _ => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other, "no identity certificates",
                ));
            }
        }
        Ok(())
    }

    async fn write_cell(&mut self, cell: &cell::Cell) -> std::io::Result<()> {
        cell.write(self.protocol_version, &mut self.stream).await
    }

    async fn read_next_cell_impl<R: tokio::io::AsyncRead + Unpin>(
        protocol_version: u16, identity: crate::RsaIdentity, reader: &mut R
    ) -> std::io::Result<cell::Cell> {
        loop {
            let cell = match cell::Cell::read(protocol_version, reader).await? {
                Some(cell) => cell,
                None => {
                    warn!("{}: unrecognised cell", identity);
                    continue;
                }
            };
            match &cell.command {
                cell::Command::Padding => {
                    continue;
                },
                _ => return Ok(cell)
            }
        }
    }

    async fn read_next_cell(&mut self) -> std::io::Result<cell::Cell> {
        Self::read_next_cell_impl(self.protocol_version, self.identity, &mut self.stream).await
    }

    fn run(self) -> (tokio::sync::mpsc::Receiver<cell::Cell>, tokio::sync::mpsc::Sender<cell::Cell>) {
        let (cell_in_tx, cell_in_rx) = tokio::sync::mpsc::channel::<cell::Cell>(10);
        let (cell_out_tx, mut cell_out_rx) = tokio::sync::mpsc::channel::<cell::Cell>(10);
        let (read_half, mut write_half) = tokio::io::split(self.stream);
        let mut reader = tokio::io::BufReader::new(read_half);

        tokio::task::spawn(async move {
            loop {
                match Self::read_next_cell_impl(self.protocol_version, self.identity, &mut reader).await {
                    Ok(cell) => {
                        match cell_in_tx.send(cell).await {
                            Ok(_) => {},
                            Err(_) => {
                                trace!("{}: cell_in_tx closed", self.identity);
                                return
                            },
                        }
                    },
                    Err(e) => {
                        warn!("{}: failed to read cell: {:?}", self.identity, e);
                        return;
                    }
                }
            }
        });
        tokio::task::spawn(async move {
            loop {
                match cell_out_rx.recv().await {
                    Some(cell) => {
                        match cell.write(self.protocol_version, &mut write_half).await {
                            Ok(_) => {},
                            Err(e) => {
                                warn!("{}: failed to write cell: {}", self.identity, e);
                                return;
                            }
                        }
                    },
                    None => {
                        trace!("{}: cell_out_rx closed", self.identity);
                        return
                    },
                }
            }
        });
        (cell_in_rx, cell_out_tx)
    }
}

#[derive(Debug)]
struct ConnectionRouter {
    identity: crate::RsaIdentity,
    initiated: bool,
    protocol_version: u16,
    cell_tx: tokio::sync::mpsc::Sender<cell::Cell>,
    circuit_tx: tokio::sync::mpsc::Sender<CircuitManagement>,
    circuits: std::collections::HashSet<u32>
}

enum CircuitManagement {
    Create(u32, tokio::sync::mpsc::Sender<cell::Command>),
    Destroy(u32),
}

impl ConnectionRouter {
    fn new(
        identity: crate::RsaIdentity,
        initiated: bool, protocol_version: u16,
        cell_tx: tokio::sync::mpsc::Sender<cell::Cell>,
        cell_rx: tokio::sync::mpsc::Receiver<cell::Cell>
    ) -> Self {
        let (circuit_tx, circuit_rx) = tokio::sync::mpsc::channel(10);
        Self::run(cell_rx, circuit_rx);
        ConnectionRouter {
            identity,
            initiated,
            cell_tx,
            protocol_version,
            circuit_tx,
            circuits: std::collections::HashSet::new(),
        }
    }

    fn run(
        mut cell_rx: tokio::sync::mpsc::Receiver<cell::Cell>,
        mut circuit_rx: tokio::sync::mpsc::Receiver<CircuitManagement>,
    ) {
        let mut circuits = std::collections::HashMap::<u32, tokio::sync::mpsc::Sender<cell::Command>>::new();

        tokio::task::spawn(async move {
            loop {
                tokio::select! {
                    ic = cell_rx.recv() => {
                        match ic {
                            Some(cell) => {
                                if cell.circuit_id == 0 {
                                    println!("got control command {:?}", cell.command);
                                } else {
                                    if let Some(circuit) = circuits.get(&cell.circuit_id) {
                                        let _ = circuit.send(cell.command).await;
                                    } else {
                                        warn!("got command for unknown circuit {} ({:?})", cell.circuit_id, cell.command);
                                    }
                                }
                            },
                            None => return
                        }
                    }
                    cc = circuit_rx.recv() => {
                        match cc {
                            Some(command) => match command {
                                CircuitManagement::Create(circuit_id, command_tx) => {
                                    circuits.insert(circuit_id, command_tx);
                                },
                                CircuitManagement::Destroy(circuit_id) => {
                                    circuits.remove(&circuit_id);
                                },
                            },
                            None => return
                        }
                    }
                }
            }
        });
    }

    fn select_circuit_id(&mut self) -> u32 {
        let mut rng = thread_rng();
        loop {
            let circuit_id = if self.protocol_version >= 4 {
                let r = rng.gen_range(1, u32::MAX >> 1);
                if self.initiated {
                    r | 1 << 31
                } else {
                    r
                }
            } else {
                rng.gen_range(1, u16::MAX as u32)
            };
            if !self.circuits.contains(&circuit_id) {
                self.circuits.insert(circuit_id);
                return circuit_id;
            }
        }
    }

    async fn new_circuit(&mut self) -> std::io::Result<crate::circuit::Circuit> {
        let (command_in_tx, command_in_rx) = tokio::sync::mpsc::channel::<cell::Command>(10);
        let (command_out_tx, mut command_out_rx) = tokio::sync::mpsc::channel::<cell::Command>(10);

        let circuit_id = self.select_circuit_id();
        match self.circuit_tx.send(CircuitManagement::Create(circuit_id, command_in_tx.clone())).await {
            Ok(_) => {},
            Err(_) => return Err(std::io::Error::new(std::io::ErrorKind::Other, "failed to create circuit")),
        }

        let circ_control_tx = self.circuit_tx.clone();
        let circ_cell_tx = self.cell_tx.clone();
        tokio::task::spawn(async move {
            loop {
                match command_out_rx.recv().await {
                    Some(command) => {
                        match circ_cell_tx.send(cell::Cell {
                            circuit_id,
                            command
                        }).await {
                            Ok(_) => {},
                            Err(_) => break,
                        }
                    },
                    None => break,
                }
            }
            if let Err(_) = circ_control_tx.send(CircuitManagement::Destroy(circuit_id)).await {
                warn!("failed to destroy circuit {}", circuit_id);
            }
        });

        Ok(crate::circuit::Circuit::new(
            self.identity, circuit_id,
            command_out_tx, command_in_rx
        ))
    }

    fn purge_circuit(&mut self, circuit_id: u32) {
        self.circuits.remove(&circuit_id);
        let _ = self.circuit_tx.send(CircuitManagement::Destroy(circuit_id));
    }
}

#[derive(Debug)]
pub struct Connection {
    identity: crate::RsaIdentity,
    router: ConnectionRouter,
}

pub(crate) struct NtorClientState {
    identity: crate::RsaIdentity,
    ntor_onion_key: [u8; 32],
    my_sk: x25519_dalek::StaticSecret
}

impl Connection {
    pub async fn connect(tcp_stream: tokio::net::TcpStream, identity: crate::RsaIdentity) -> std::io::Result<Connection> {
        let local_addr = tcp_stream.local_addr()?;
        let peer_addr = tcp_stream.peer_addr()?;

        let tls_stream = match async_native_tls::TlsConnector::new()
            .use_sni(false)
            .danger_accept_invalid_certs(true)
            .danger_accept_invalid_hostnames(true)
            .connect("", tcp_stream).await {
            Ok(s) => s,
            Err(e) => return Err(std::io::Error::new(std::io::ErrorKind::Other, format!("TLS error: {}", e))),
        };
        // let tls_connector = tokio_rustls::TlsConnector::from(crate::TLS_CLIENT_CONFIG.clone());
        // let tls_stream = tls_connector.connect(rustls::client::ServerName::try_from("example.com").unwrap(), tcp_stream).await?;
        debug!("TLS connection to {} established", identity);
        if !is_v3_handshake(&tls_stream) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other, "did not present a v3 handshake",
            ));
        }
        let mut inner = InnerConnection {
            identity,
            protocol_version: 3,
            stream: tls_stream,
            local_addr,
            peer_addr,
        };
        let protocol_version = inner.negotiate_connection().await?;
        debug!("{}: connection established", identity);
        let (cell_rx, cell_tx) = inner.run();

        let connection = Self {
            identity,
            router: ConnectionRouter::new(identity, true, protocol_version, cell_tx, cell_rx)
        };
        Ok(connection)
    }

    pub(super) fn ntor_client_1(identity: crate::RsaIdentity, ntor_onion_key: [u8; 32]) -> (Vec<u8>, NtorClientState) {
        let my_sk = x25519_dalek::StaticSecret::new(&mut thread_rng());
        let my_pk = x25519_dalek::PublicKey::from(&my_sk);

        let mut data = vec![];
        data.append(&mut identity.to_vec());
        data.append(&mut ntor_onion_key.to_vec());
        data.append(&mut my_pk.to_bytes().to_vec());

        (data, NtorClientState {
            my_sk,
            identity,
            ntor_onion_key,
        })
    }

    pub(super) fn ntor_client_2(resp: &[u8], state: NtorClientState) -> std::io::Result<([u8; 20], [u8; 20], [u8; 16], [u8; 16])> {
        if resp.len() != 64 {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid server data"));
        }

        let server_pk = TryInto::<[u8; 32]>::try_into(&resp[0..32]).unwrap();
        let auth_s = TryInto::<[u8; 32]>::try_into(&resp[32..64]).unwrap();

        let xy = state.my_sk.diffie_hellman(&x25519_dalek::PublicKey::from(server_pk));
        let xb = state.my_sk.diffie_hellman(&x25519_dalek::PublicKey::from(state.ntor_onion_key));
        let my_pk = x25519_dalek::PublicKey::from(&state.my_sk);

        let mut secret_input = vec![];
        secret_input.extend(xy.as_bytes());
        secret_input.extend(xb.as_bytes());
        secret_input.extend(&state.identity.to_vec());
        secret_input.extend(&state.ntor_onion_key);
        secret_input.extend(&my_pk.to_bytes());
        secret_input.extend(&server_pk);
        secret_input.extend(b"ntor-curve25519-sha256-1");

        let t_mac = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, b"ntor-curve25519-sha256-1:mac");
        let t_verify = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, b"ntor-curve25519-sha256-1:verify");

        let verify = ring::hmac::sign(&t_verify, &secret_input);
        let mut auth_input = vec![];
        auth_input.extend(verify.as_ref());
        auth_input.extend(&state.identity.to_vec());
        auth_input.extend(&state.ntor_onion_key);
        auth_input.extend(&server_pk);
        auth_input.extend(&my_pk.to_bytes());
        auth_input.extend(b"ntor-curve25519-sha256-1");
        auth_input.extend(b"Server");
        let auth = ring::hmac::sign(&t_mac, &auth_input);

        if ring::constant_time::verify_slices_are_equal(auth.as_ref(), &auth_s).is_err() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other, "KDF mismatch",
            ));
        }

        let hk = hkdf::Hkdf::<sha2::Sha256>::new(Some(b"ntor-curve25519-sha256-1:key_extract"), &secret_input);
        let mut k = [0u8; 256];
        hk.expand(b"ntor-curve25519-sha256-1:key_expand", &mut k).unwrap();

        let df = k[0..20].try_into().unwrap();
        let db = k[20..40].try_into().unwrap();
        let kf = k[40..56].try_into().unwrap();
        let kb = k[56..72].try_into().unwrap();

        Ok((df, db, kf, kb))
    }

    pub async fn create_circuit(&mut self, ntor_onion_key: [u8; 32]) -> std::io::Result<crate::circuit::Circuit> {
        let circuit = self.router.new_circuit().await?;

        let (data, state) = Self::ntor_client_1(self.identity, ntor_onion_key);

        match circuit.inner.lock().await.command_tx.send(cell::Command::Create2(cell::Create2 {
            client_handshake_type: 2,
            client_handshake: data,
        })).await {
            Ok(_) => {}
            Err(_) => return Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionReset,
                format!("connection dropped"),
            ))
        }
        let reply_command = match circuit.recv_control_command().await {
            Ok(command) => command,
            Err(e) => {
                self.router.purge_circuit(circuit.get_circuit_id());
                return Err(e);
            }
        };

        let resp = match reply_command {
            cell::Command::Destroy(d) => {
                self.router.purge_circuit(circuit.get_circuit_id());
                return Err(std::io::Error::new(
                    std::io::ErrorKind::ConnectionRefused,
                    format!("circuit refused {:?}", d.reason),
                ));
            },
            cell::Command::Created2(c) => c.server_data,
            _ => {
                self.router.purge_circuit(circuit.get_circuit_id());
                return Err(std::io::Error::new(
                    std::io::ErrorKind::ConnectionReset, "unexpected reply",
                ));
            }
        };

        let (df, db, kf, kb) = match Self::ntor_client_2(&resp, state) {
            Ok(x) => x,
            Err(e) => {
                self.router.purge_circuit(circuit.get_circuit_id());
                return Err(e);
            }
        };

        circuit.insert_node(df, db, kf, kb).await;
        debug!("{}: circuit {} created", self.identity, circuit.get_circuit_id());
        Ok(circuit)
    }

    pub async fn create_circuit_fast(&mut self) -> std::io::Result<crate::circuit::Circuit> {
        let circuit = self.router.new_circuit().await?;

        let x = {
            let mut x = [0u8; 20];
            let mut rng = thread_rng();
            rng.fill_bytes(&mut x);
            x
        };

        match circuit.inner.lock().await.command_tx.send(cell::Command::CreateFast(cell::CreateFast {
            x
        })).await {
            Ok(_) => {}
            Err(_) => return Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionReset,
                format!("connection dropped"),
            ))
        }
        let reply_command = match circuit.recv_control_command().await {
            Ok(command) => command,
            Err(e) => {
                self.router.purge_circuit(circuit.get_circuit_id());
                return Err(e);
            }
        };

        let created = match reply_command {
            cell::Command::Destroy(d) => {
                self.router.purge_circuit(circuit.get_circuit_id());
                return Err(std::io::Error::new(
                    std::io::ErrorKind::ConnectionRefused,
                    format!("circuit refused {:?}", d.reason),
                ));
            },
            cell::Command::CreatedFast(c) => c,
            _ => {
                self.router.purge_circuit(circuit.get_circuit_id());
                return Err(std::io::Error::new(
                    std::io::ErrorKind::ConnectionReset, "unexpected reply",
                ));
            }
        };
        let mut k0 = x.to_vec();
        k0.append(&mut created.y.to_vec());
        let target_len = 20 * 5;
        let mut k = Vec::<u8>::with_capacity(target_len);
        let mut i = 0;
        while k.len() < target_len {
            let mut ctx = ring::digest::Context::new(&ring::digest::SHA1_FOR_LEGACY_USE_ONLY);
            ctx.update(&k0);
            ctx.update(&[i]);
            k.extend(ctx.finish().as_ref());
            i += 1;
        }
        let kh = <[u8; 20]>::try_from(&k[0..20]).unwrap();
        let df = <[u8; 20]>::try_from(&k[20..40]).unwrap();
        let db = <[u8; 20]>::try_from(&k[40..60]).unwrap();
        let kf = <[u8; 16]>::try_from(&k[60..76]).unwrap();
        let kb = <[u8; 16]>::try_from(&k[76..92]).unwrap();

        if kh != created.derivate_key_data {
            self.router.purge_circuit(circuit.get_circuit_id());
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other, "KDF mismatch",
            ));
        }

        circuit.insert_node(df, db, kf, kb).await;
        debug!("{}: circuit {} created", self.identity, circuit.get_circuit_id());
        Ok(circuit)
    }
}