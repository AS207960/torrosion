use crate::cell;
use rand::prelude::*;
use aes::cipher::{KeyIvInit, StreamCipher};

struct RelayCommand {
    stream_id: u16,
    early: bool,
    command: crate::stream::StreamCommand,
}

#[derive(Debug)]
pub struct InnerCircuit {
    identity: crate::RsaIdentity,
    circuit_id: u32,
    pub(crate) command_tx: tokio::sync::mpsc::Sender<cell::Command>,
    control_rx: tokio::sync::mpsc::Receiver<cell::Command>,
    stream_tx: tokio::sync::mpsc::Sender<StreamManagement>,
    streams: std::collections::HashSet<u16>,
    nodes: std::sync::Arc<tokio::sync::Mutex<Vec<CircuitNode>>>,
    relay_tx: tokio::sync::mpsc::Sender<RelayCommand>,
    relay_control_rx: tokio::sync::mpsc::Receiver<super::stream::StreamCommand>
}

#[derive(Clone, Debug)]
pub struct Circuit {
    identity: crate::RsaIdentity,
    circuit_id: u32,
    #[allow(dead_code)]
    stream_tx: tokio::sync::mpsc::Sender<StreamManagement>,
    relay_tx: tokio::sync::mpsc::Sender<RelayCommand>,
    pub(crate) inner: std::sync::Arc<tokio::sync::Mutex<InnerCircuit>>,
}

trait Digest: Send + Sync {
    fn save(&mut self);
    fn revert(&mut self);

    fn update(&mut self, data: &[u8]);
    fn output(&mut self) -> Vec<u8>;
}

struct Sha1 {
    hasher: sha1::Sha1,
    saved_hasher: Option<sha1::Sha1>
}

impl Sha1 {
    fn new() -> Self {
        use sha1::Digest;
        Self {
            hasher: sha1::Sha1::new(),
            saved_hasher: None
        }
    }
}

impl Digest for Sha1 {
    fn save(&mut self) {
        self.saved_hasher = Some(self.hasher.clone());
    }

    fn revert(&mut self) {
        if let Some(hasher) = self.saved_hasher.take() {
            self.hasher = hasher;
        }
    }
    
    fn update(&mut self, data: &[u8]) {
        use sha1::Digest;
        self.hasher.update(data);
    }

    fn output(&mut self) -> Vec<u8> {
        use sha1::Digest;
        self.hasher.clone().finalize().to_vec()
    }
}

struct Sha3_256 {
    hasher: sha3::Sha3_256,
    saved_hasher: Option<sha3::Sha3_256>
}

impl Sha3_256 {
    fn new() -> Self {
        use sha3::Digest;
        Self {
            hasher: sha3::Sha3_256::new(),
            saved_hasher: None
        }
    }
}

impl Digest for Sha3_256 {
    fn save(&mut self) {
        self.saved_hasher = Some(self.hasher.clone());
    }

    fn revert(&mut self) {
        if let Some(hasher) = self.saved_hasher.take() {
            self.hasher = hasher;
        }
    }

    fn update(&mut self, data: &[u8]) {
        use sha3::Digest;
        self.hasher.update(data);
    }

    fn output(&mut self) -> Vec<u8> {
        use sha3::Digest;
        self.hasher.clone().finalize().to_vec()
    }
}

trait Crypter: Send + Sync {
    fn apply_keystream(&mut self, data: &mut [u8]);
}

struct Aes128 {
    crypter: crate::Aes128,
}

impl Aes128 {
    fn new(key: &[u8], iv: &[u8]) -> Self {
        Self {
            crypter: crate::Aes128::new(key.into(), iv.into())
        }
    }
}

impl Crypter for Aes128 {
    fn apply_keystream(&mut self, data: &mut [u8]) {
        self.crypter.apply_keystream(data);
    }
}

struct Aes256 {
    crypter: crate::Aes256,
}

impl Aes256 {
    fn new(key: &[u8], iv: &[u8]) -> Self {
        Self {
            crypter: crate::Aes256::new(key.into(), iv.into())
        }
    }
}

impl Crypter for Aes256 {
    fn apply_keystream(&mut self, data: &mut [u8]) {
        self.crypter.apply_keystream(data);
    }
}

struct CircuitNode {
    forward_hasher: Box<dyn Digest>,
    backward_hasher: Box<dyn Digest>,
    forward_crypter: Box<dyn Crypter>,
    backward_crypter: Box<dyn Crypter>,
    package_window: isize,
    deliver_window: isize,
}

impl std::fmt::Debug for CircuitNode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CircuitNode")
            .field("package_window", &self.package_window)
            .field("deliver_window", &self.deliver_window)
            .finish_non_exhaustive()
    }
}

#[allow(dead_code)]
enum StreamManagement {
    Create(u16, tokio::sync::mpsc::Sender<crate::stream::StreamCommand>),
    Destroy(u16),
    Close,
}
impl InnerCircuit {
    fn run(
        identity: crate::RsaIdentity,
        circuit_id: u32,
        nodes: std::sync::Arc<tokio::sync::Mutex<Vec<CircuitNode>>>,
        mut stream_rx: tokio::sync::mpsc::Receiver<StreamManagement>,

        mut command_in_rx: tokio::sync::mpsc::Receiver<cell::Command>,
        control_in_tx: tokio::sync::mpsc::Sender<cell::Command>,

        mut relay_out_rx: tokio::sync::mpsc::Receiver<RelayCommand>,
        command_out_tx: tokio::sync::mpsc::Sender<cell::Command>,

        relay_control_out_tx: tokio::sync::mpsc::Sender<super::stream::StreamCommand>,
    ) {
        let mut streams = std::collections::HashMap::<u16,  tokio::sync::mpsc::Sender<crate::stream::StreamCommand>>::new();

        tokio::task::spawn(async move {
            macro_rules! process_command {
                ($ic:expr) => {
                    match $ic {
                        Some(cell::Command::Relay(relay)) => {
                            let mut nodes_guard = nodes.lock().await;
                            let (origin, cell) = match Self::decrypt_backward(&mut nodes_guard, &relay.data) {
                                Ok(payload) => payload,
                                Err(e) => {
                                    warn!("Failed to process incoming relay: {:?}", e);
                                    continue;
                                },
                            };
                            if let Some(cell) = cell {
                                if cell.stream_id == 0 {
                                    match cell.command {
                                        cell::RelayCommand::SendMe(_) => {
                                            // TODO: verify digest
                                            nodes_guard[origin].package_window += crate::CIRCUIT_WINDOW_INCREMENT;
                                        },
                                        _ => {
                                            match relay_control_out_tx.send(super::stream::StreamCommand {
                                                node: origin,
                                                command: cell.command
                                            }).await {
                                                Ok(_) => {},
                                                Err(_) => return,
                                            }
                                        }
                                    }
                                } else {
                                    if matches!(cell.command, cell::RelayCommand::Data(_)) {
                                        nodes_guard[origin].deliver_window -= 1;

                                        if nodes_guard[origin].deliver_window <= (
                                            crate::CIRCUIT_WINDOW_INITIAL - crate::CIRCUIT_WINDOW_INCREMENT) {
                                            nodes_guard[origin].deliver_window += crate::CIRCUIT_WINDOW_INCREMENT;

                                            let digest = nodes_guard[origin].backward_hasher.output();

                                            let command = cell::RelayCommand::SendMe(cell::RelaySendMe {
                                                version: 1,
                                                data: Some(digest),
                                            });
                                            trace!("Write relay cell (dest {}) {} {:?}", origin, 0, command);
                                            let payload = match Self::process_stream_command(0, crate::stream::StreamCommand {
                                                node: origin,
                                                command: command
                                            }, &mut nodes_guard) {
                                                Ok(payload) => payload,
                                                Err(_) => return,
                                            };
                                            match command_out_tx.send(cell::Command::Relay(cell::Relay {
                                                data: payload
                                            })).await {
                                                Ok(_) => {},
                                                Err(_) => return,
                                            }
                                        }
                                    }

                                    if let Some(command_tx) = streams.get(&cell.stream_id) {
                                        match command_tx.send(crate::stream::StreamCommand {
                                            node: origin,
                                            command: cell.command
                                        }).await {
                                            Ok(_) => {},
                                            Err(_) => {
                                                streams.remove(&cell.stream_id);
                                            }
                                        }
                                    } else {
                                        warn!("Received relay for unknown stream {} from node {}", cell.stream_id, origin);
                                    }
                                }
                            }
                        },
                        Some(command) => {
                            match command {
                                cell::Command::Destroy(d) => {
                                    info!("{}: circuit {} destroyed ({:?})", identity, circuit_id, d.reason);
                                    return;
                                }
                                _ => match control_in_tx.send(command).await {
                                    Ok(_) => {},
                                    Err(_) => return,
                                }
                            }
                        },
                        None => {
                            trace!("{}: circuit {} command_in_rx closed", identity, circuit_id);
                            return
                        },
                    }
                }
            }

            macro_rules! process_stream {
                ($sc:expr) => {
                    match $sc {
                        Some(command) => match command {
                            StreamManagement::Create(stream_id, command_tx) => {
                                streams.insert(stream_id, command_tx);
                            },
                            StreamManagement::Destroy(stream_id) => {
                                streams.remove(&stream_id);
                            },
                            StreamManagement::Close => {
                                return;
                            }
                        },
                        None => {
                            trace!("{}: circuit {} stream_rx closed", identity, circuit_id);
                            return
                        },
                    }
                }
            }

            macro_rules! process_relay {
                ($or:expr) => {
                    match $or {
                        Some(relay) => {
                            trace!(
                                "Write relay cell (dest {}, early {}) {} {:?}",
                                relay.command.node, relay.early, relay.stream_id, relay.command.command
                            );
                            let is_data = matches!(relay.command.command, cell::RelayCommand::Data(_));
                            let node_id = relay.command.node;
                            let payload = match Self::process_stream_command(relay.stream_id, relay.command, &mut nodes.lock().await) {
                                Ok(payload) => payload,
                                Err(e) => {
                                    warn!("Failed to process stream command: {:?}", e);
                                    continue;
                                },
                            };

                            match command_out_tx.send(if relay.early {
                                cell::Command::RelayEarly(cell::RelayEarly {
                                    data: payload
                                })
                            } else {
                                cell::Command::Relay(cell::Relay {
                                    data: payload
                                })
                            }).await {
                                Ok(_) => {},
                                Err(_) => return,
                            }
                            if is_data {
                                nodes.lock().await[node_id].package_window -= 1;
                            }
                        },
                        None => {
                            trace!("{}: circuit {} relay_out_rx closed", identity, circuit_id);
                            return
                        }
                    }
                }
            }

            loop {
                // This stops processing ALL relay cells if ANY node has a package window of 0.
                // This is not ideal. We should only stop processing relay cells for specific node
                // that has a package window of 0. Additionally we should process relay cells other
                // than data cells even if the package window is 0. However for now this is probably
                // adequate.
                let min_package_window = nodes.lock().await.iter().map(|n| n.package_window)
                    .min().unwrap_or(crate::CIRCUIT_WINDOW_INITIAL);

                if min_package_window > 0 {
                    tokio::select! {
                        ic = command_in_rx.recv() => {
                            process_command!(ic);
                        }
                        sc = stream_rx.recv() => {
                            process_stream!(sc);
                        }
                        or = relay_out_rx.recv() => {
                            process_relay!(or);
                        }
                    }
                } else {
                    tokio::select! {
                        ic = command_in_rx.recv() => {
                            process_command!(ic);
                        }
                        sc = stream_rx.recv() => {
                            process_stream!(sc);
                        }
                    }
                }
            }
        });
    }

    fn select_stream_id(&mut self) -> u16 {
        let mut rng = thread_rng();
        loop {
            let stream_id = rng.gen_range(1, u16::MAX);
            if !self.streams.contains(&stream_id) {
                self.streams.insert(stream_id);
                return stream_id;
            }
        }
    }

    fn encrypt_forward(nodes: &mut tokio::sync::MutexGuard<Vec<CircuitNode>>, dest: usize, payload: &[u8]) -> std::io::Result<Vec<u8>> {
        let mut cur = payload.to_vec();
        for i in (0..dest+1).rev() {
            let n = &mut nodes[i];
            n.forward_crypter.apply_keystream(&mut cur);
        }
        Ok(cur)
    }

    fn decrypt_backward(
        nodes: &mut tokio::sync::MutexGuard<Vec<CircuitNode>>, payload: &[u8]
    ) -> std::io::Result<(usize, Option<cell::RelayCell>)> {
        let mut cur = payload.to_vec();
        for i in 0..nodes.len() {
            let n = &mut nodes[i];
            n.backward_crypter.apply_keystream(&mut cur);

            let mut relay_cell = cell::RelayCellRaw::from_bytes(&cur)?;
            if relay_cell.recognized == 0 {
                n.backward_hasher.save();
                let old_digest = relay_cell.digest;
                relay_cell.digest = [0; 4];
                let hashed_bytes = relay_cell.to_bytes()?;
                n.backward_hasher.update(&hashed_bytes);
                let payload_digest = n.backward_hasher.output();
                if old_digest == payload_digest[0..4] {
                    trace!("Read relay cell (origin {}) {} {}", i, relay_cell.stream_id, relay_cell.command_id);
                    let relay_cell = cell::RelayCell::from_raw(relay_cell)?;
                    return Ok((i, relay_cell));
                }
                n.backward_hasher.revert();
            }
        }
        Err(std::io::Error::new(std::io::ErrorKind::Other, "unrecognized cell at last node"))
    }

    fn process_stream_command(
        stream_id: u16, command: crate::stream::StreamCommand, nodes: &mut tokio::sync::MutexGuard<Vec<CircuitNode>>
    ) -> std::io::Result<Vec<u8>> {
        if command.node >= nodes.len() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::AddrNotAvailable,
                format!(
                    "invalid destination; circuit only has {} nodes, requested {}",
                    nodes.len(), command.node
                )
            ));
        }
        let dest_node = &mut nodes[command.node];
        let mut cell = cell::RelayCell {
            stream_id,
            command: command.command,
            digest: [0; 4],
            recognized: 0,
        };

        let mut payload_bytes_no_digest = cell.to_bytes()?;
        let padding_len = crate::PAYLOAD_LEN - payload_bytes_no_digest.len();
        let mut padding = Vec::with_capacity(padding_len);
        for _ in 0..std::cmp::min(padding_len, 4) {
            padding.push(0);
        }
        if padding_len > 4 {
            let mut rng = thread_rng();
            for _ in 0..(padding_len - 4) {
                padding.push(rng.gen());
            }
        }
        payload_bytes_no_digest.extend(&padding);

        dest_node.forward_hasher.update(&payload_bytes_no_digest);
        let payload_digest = dest_node.forward_hasher.output();
        cell.digest = payload_digest[0..4].try_into().unwrap();

        let mut payload_bytes = cell.to_bytes()?;
        payload_bytes.extend(&padding);

        Self::encrypt_forward(nodes, command.node, &payload_bytes)
    }

    async fn new_stream(&mut self) -> std::io::Result<crate::stream::Stream> {
        let (command_in_tx, command_in_rx) = tokio::sync::mpsc::channel(10);
        let (command_out_tx, mut command_out_rx) = tokio::sync::mpsc::channel::<crate::stream::StreamCommand>(10);

        let stream_id = self.select_stream_id();
        match self.stream_tx.send(StreamManagement::Create(stream_id, command_in_tx.clone())).await {
            Ok(_) => {},
            Err(_) => return Err(std::io::Error::new(std::io::ErrorKind::Other, "failed to create stream")),
        }

        let control_tx = self.stream_tx.clone();
        let relay_tx = self.relay_tx.clone();
        tokio::task::spawn(async move{
            loop {
                match command_out_rx.recv().await {
                    Some(command) => {
                        match relay_tx.send(RelayCommand {
                            stream_id,
                            early: false,
                            command
                        }).await {
                            Ok(_) => {},
                            Err(_) => break,
                        }
                    },
                    None => break,
                }
            }
            if let Err(_) = control_tx.send(StreamManagement::Destroy(stream_id)).await {
                warn!("failed to destroy stream {}", stream_id);
            }
        });

        Ok(crate::stream::Stream::new(
            self.identity, stream_id, self.circuit_id, command_out_tx, command_in_rx
        ))
    }

    fn purge_stream(&mut self, stream_id: u16) {
        self.streams.remove(&stream_id);
        let _ = self.stream_tx.send(StreamManagement::Destroy(stream_id));
    }

    async fn circuit_len(&self) -> usize {
        self.nodes.lock().await.len()
    }
}

impl Circuit {
    pub(crate) fn new(
        identity: crate::RsaIdentity, circuit_id: u32,
        command_tx: tokio::sync::mpsc::Sender<cell::Command>,
        command_rx: tokio::sync::mpsc::Receiver<cell::Command>
    ) -> Self {
        let nodes = std::sync::Arc::new(tokio::sync::Mutex::new(Vec::new()));
        let (stream_tx, stream_rx) = tokio::sync::mpsc::channel(10);
        let (control_tx, control_rx) = tokio::sync::mpsc::channel(10);
        let (relay_tx, relay_rx) = tokio::sync::mpsc::channel(10);
        let (relay_control_tx, relay_control_rx) = tokio::sync::mpsc::channel(10);

        InnerCircuit::run(
            identity, circuit_id,
            nodes.clone(), stream_rx,
            command_rx, control_tx,
            relay_rx, command_tx.clone(),
            relay_control_tx,
        );

        Circuit {
            identity,
            circuit_id,
            relay_tx: relay_tx.clone(),
            stream_tx: stream_tx.clone(),
            inner: std::sync::Arc::new(tokio::sync::Mutex::new(InnerCircuit {
                identity,
                circuit_id,
                command_tx,
                stream_tx,
                control_rx,
                nodes,
                relay_tx,
                relay_control_rx,
                streams: std::collections::HashSet::new(),
            })),
        }
    }

    pub fn get_circuit_id(&self) -> u32 {
        self.circuit_id
    }

    pub(crate) async fn insert_node(&self, df: [u8; 20], db: [u8; 20], kf: [u8; 16], kb: [u8; 16]) {
        let mut hf = Sha1::new();
        let mut hb = Sha1::new();
        hf.update(&df);
        hb.update(&db);

        let iv = [0u8; 16];
        let fc = Aes128::new(&kf, &iv);
        let bc = Aes128::new(&kb, &iv);

        self.inner.lock().await.nodes.lock().await.push(CircuitNode {
            forward_hasher: Box::new(hf),
            backward_hasher: Box::new(hb),
            forward_crypter: Box::new(fc),
            backward_crypter: Box::new(bc),
            package_window: crate::CIRCUIT_WINDOW_INITIAL,
            deliver_window: crate::CIRCUIT_WINDOW_INITIAL,
        });
    }

    pub(crate) async fn insert_node_hs_v3(&self, df: [u8; 32], db: [u8; 32], kf: [u8; 32], kb: [u8; 32]) {
        let mut hf = Sha3_256::new();
        let mut hb = Sha3_256::new();
        hf.update(&df);
        hb.update(&db);

        let iv = [0u8; 16];
        let fc = Aes256::new(&kf, &iv);
        let bc = Aes256::new(&kb, &iv);

        self.inner.lock().await.nodes.lock().await.push(CircuitNode {
            forward_hasher: Box::new(hf),
            backward_hasher: Box::new(hb),
            forward_crypter: Box::new(fc),
            backward_crypter: Box::new(bc),
            package_window: crate::CIRCUIT_WINDOW_INITIAL,
            deliver_window: crate::CIRCUIT_WINDOW_INITIAL,
        });
    }

    pub(crate) async fn recv_control_command(&self) -> Result<cell::Command, std::io::Error> {
        match self.inner.lock().await.control_rx.recv().await {
            Some(command) => Ok(command),
            None => Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionReset, "circuit closed",
            )),
        }
    }

    pub(crate) async fn recv_relay_control_command(&self) -> Result<super::stream::StreamCommand, std::io::Error> {
        match self.inner.lock().await.relay_control_rx.recv().await {
            Some(command) => Ok(command),
            None => Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionReset, "circuit closed",
            )),
        }
    }

    pub(crate) async fn extend_circuit_raw(
        &self, link_specifiers: Vec<crate::cell::LinkSpecifier>, identity: crate::RsaIdentity,
        ntor_onion_key: [u8; 32],
    ) -> std::io::Result<()> {
        let dest = self.inner.lock().await.circuit_len().await - 1;
        debug!("{}: extending circuit {} to {}", self.identity, self.get_circuit_id(), identity);
        let (data, state) = super::connection::Connection::ntor_client_1(identity, ntor_onion_key);

        match self.relay_tx.send(RelayCommand {
            stream_id: 0,
            early: true,
            command: crate::stream::StreamCommand {
                node: dest,
                command: cell::RelayCommand::Extend2(cell::RelayExtend2 {
                    link_specifiers,
                    client_handshake_type: 2,
                    client_handshake: data,
                }),
            }
        }).await {
            Ok(_) => {},
            Err(_) => return Err(std::io::Error::new(std::io::ErrorKind::ConnectionReset, "circuit closed")),
        }

        let reply_command = self.recv_relay_control_command().await?;
        let resp = match reply_command.command {
            cell::RelayCommand::Extended2(e) => {
                if e.server_data.len() != 64 {
                    return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid server data"));
                }
                e.server_data
            },
            _ => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::ConnectionReset, "unexpected reply",
                ));
            }
        };

        let (df, db, kf, kb) = super::connection::Connection::ntor_client_2(&resp, state)?;
        self.insert_node(df, db, kf, kb).await;
        debug!("{}: circuit {} extended", self.identity, self.get_circuit_id());

        Ok(())
    }

    pub(crate) async fn extend_circuit(&self, descriptor: &crate::net_status::descriptor::Descriptor) -> std::io::Result<()> {
        self.extend_circuit_raw(descriptor.to_link_specifiers(), descriptor.identity, descriptor.ntor_onion_key).await
    }

    pub(crate) async fn establish_rendezvous(&self, cookie: [u8; 20]) -> std::io::Result<()> {
        let dest = self.inner.lock().await.circuit_len().await - 1;

        match self.relay_tx.send(RelayCommand {
            stream_id: 0,
            early: false,
            command: crate::stream::StreamCommand {
                node: dest,
                command: cell::RelayCommand::EstablishRendezvous(cell::RelayEstablishRendezvous {
                    cookie,
                }),
            }
        }).await {
            Ok(_) => {},
            Err(_) => return Err(std::io::Error::new(std::io::ErrorKind::ConnectionReset, "circuit closed")),
        }

        let reply_command = self.recv_relay_control_command().await?;
        match reply_command.command {
            cell::RelayCommand::RendezvousEstablished => {},
            _ => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::ConnectionReset, "unexpected reply",
                ));
            }
        };

        debug!("{}: circuit {} now a rendezvous point", self.identity, self.get_circuit_id());

        Ok(())
    }

    pub(crate) async fn recv_rendezvous(&self) -> std::io::Result<cell::RelayRendezvous2> {
        let reply_command = self.recv_relay_control_command().await?;
        let resp = match reply_command.command {
            cell::RelayCommand::Rendezvous2(r) => r,
            _ => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::ConnectionReset, "unexpected reply",
                ));
            }
        };

        Ok(resp)
    }

    pub(crate) async fn send_introduction(&self, intro: cell::RelayIntroduce1) -> std::io::Result<cell::RelayIntroduceAck> {
        let dest = self.inner.lock().await.circuit_len().await - 1;

        match self.relay_tx.send(RelayCommand {
            stream_id: 0,
            early: false,
            command: crate::stream::StreamCommand {
                node: dest,
                command: cell::RelayCommand::Introduce1(intro),
            }
        }).await {
            Ok(_) => {},
            Err(_) => return Err(std::io::Error::new(std::io::ErrorKind::ConnectionReset, "circuit closed")),
        }

        let reply_command = self.recv_relay_control_command().await?;
        let resp = match reply_command.command {
            cell::RelayCommand::IntroduceAck(a) => a,
            _ => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::ConnectionReset, "unexpected reply",
                ));
            }
        };

        debug!("{}: circuit {} sent introduction", self.identity, self.get_circuit_id());

        Ok(resp)
    }

    pub async fn is_open(&self) -> bool {
        !self.inner.lock().await.relay_tx.is_closed()
    }

    pub async fn relay_begin(&self, to: &str, dest: Option<usize>) -> std::io::Result<crate::stream::Stream> {
        let dest = dest.unwrap_or(self.inner.lock().await.circuit_len().await - 1);
        let mut stream = self.inner.lock().await.new_stream().await?;
        stream.circuit_end.store(dest, std::sync::atomic::Ordering::Relaxed);

        match stream.command_tx.get_ref().unwrap().send(crate::stream::StreamCommand {
            node: dest,
            command: cell::RelayCommand::Begin(cell::RelayBegin {
                addr_port: to.to_string(),
                ipv6_ok: true,
                ipv4_not_ok: false,
                ipv6_preferred: true
            }),
        }).await {
            Ok(_) => {},
            Err(_) => {
                self.inner.lock().await.purge_stream(stream.get_stream_id());
                return Err(std::io::Error::new(std::io::ErrorKind::ConnectionReset, "circuit closed"))
            },
        }
        let reply_command = match stream.recv_command().await {
            Ok(command) => command,
            Err(e) => {
                self.inner.lock().await.purge_stream(stream.get_stream_id());
                return Err(e);
            }
        };

        match reply_command.command {
            cell::RelayCommand::End(e) => {
                self.inner.lock().await.purge_stream(stream.get_stream_id());
                return Err(e.reason.to_io_error());
            },
            cell::RelayCommand::Connected(_) => {},
            _ => {
                self.inner.lock().await.purge_stream(stream.get_stream_id());
                return Err(std::io::Error::new(
                    std::io::ErrorKind::ConnectionReset, "unexpected reply",
                ));
            }
        };

        debug!("{}: circuit {}; created stream {} to node {}", self.identity, self.circuit_id, stream.get_stream_id(), dest);

        Ok(stream)
    }

    pub async fn relay_begin_dir(&self, dest: Option<usize>) -> std::io::Result<crate::stream::Stream> {
        let dest = dest.unwrap_or(self.inner.lock().await.circuit_len().await - 1);
        let mut stream = self.inner.lock().await.new_stream().await?;
        stream.circuit_end.store(dest, std::sync::atomic::Ordering::Relaxed);

        match stream.command_tx.get_ref().unwrap().send(crate::stream::StreamCommand {
            node: dest,
            command: cell::RelayCommand::BeginDir,
        }).await {
            Ok(_) => {},
            Err(_) => {
                self.inner.lock().await.purge_stream(stream.get_stream_id());
                return Err(std::io::Error::new(std::io::ErrorKind::ConnectionReset, "circuit closed"))
            },
        }
        let reply_command = match stream.recv_command().await {
            Ok(command) => command,
            Err(e) => {
                self.inner.lock().await.purge_stream(stream.get_stream_id());
                return Err(e);
            }
        };

        match reply_command.command {
            cell::RelayCommand::End(e) => {
                self.inner.lock().await.purge_stream(stream.get_stream_id());
                return Err(e.reason.to_io_error());
            },
            cell::RelayCommand::Connected(_) => {},
            _ => {
                self.inner.lock().await.purge_stream(stream.get_stream_id());
                return Err(std::io::Error::new(
                    std::io::ErrorKind::ConnectionReset, "unexpected reply",
                ));
            }
        };

        debug!("{}: circuit {}; created directory stream {} to node {}", self.identity, self.circuit_id, stream.get_stream_id(), dest);

        Ok(stream)
    }
}