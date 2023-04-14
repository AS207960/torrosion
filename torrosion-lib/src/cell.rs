use std::io::{Read, Write};
use tokio::io::{AsyncWriteExt, AsyncReadExt};
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use chrono::prelude::*;

#[derive(Debug)]
pub struct Cell {
    pub circuit_id: u32,
    pub command: Command
}

impl Cell {
    pub async fn write<W: tokio::io::AsyncWrite + Unpin>(&self, version: u16, out: &mut W) -> std::io::Result<()> {
        let command_id = self.command.command_id();
        let command_data = self.command.data();
        let is_variable = Self::is_variable(command_id, version);

        trace!("Write cell: {:?} {:?}", self.circuit_id, command_id);

        if version >= 4 {
            out.write_u32(self.circuit_id).await?;
        } else {
            out.write_u16(self.circuit_id as u16).await?;
        }
        out.write_u8(command_id).await?;

        if is_variable {
            out.write_u16(command_data.len() as u16).await?;
            out.write_all(&command_data).await?;
        } else {
            let padding = vec![0; crate::PAYLOAD_LEN - command_data.len()];
            out.write_all(&command_data).await?;
            out.write_all(&padding).await?;
        }
        Ok(())
    }

    pub async fn read<R: tokio::io::AsyncRead + Unpin>(version: u16, read: &mut R) -> std::io::Result<Option<Cell>> {
        let circuit_id = if version >= 4 {
            read.read_u32().await?
        } else {
            read.read_u16().await? as u32
        };

        let command_id = read.read_u8().await?;
        let is_variable = Self::is_variable(command_id, version);
        let buf = if is_variable {
            let len = read.read_u16().await? as usize;
            let mut buf = vec![0; len];
            read.read_exact(& mut buf).await?;
            buf
        } else {
            let mut buf = vec![0; crate::PAYLOAD_LEN];
            read.read_exact(& mut buf).await?;
            buf
        };
        trace!("Read cell: {:?} {:?}", circuit_id, command_id);

        Ok(Some(Cell {
            circuit_id,
            command: match Command::from_data(command_id, buf)? {
                Some(c) => c,
                None => {
                    warn!("Unknown command id: {}", command_id);
                    return Ok(None)
                }
            }
        }))
    }

    fn is_variable(command_id: u8, version: u16) -> bool {
        if version == 2 {
            command_id == 7
        } else if version >= 3 {
            command_id == 7 || command_id >= 128
        } else {
            false
        }
    }
}

#[derive(Debug)]
pub enum Command {
    Padding,
    VPadding,

    Create(Create),
    Created(Created),
    Relay(Relay),
    Destroy(Destroy),
    CreateFast(CreateFast),
    CreatedFast(CreatedFast),
    Netinfo(Netinfo),
    RelayEarly(RelayEarly),
    Create2(Create2),
    Created2(Created2),
    PaddingNegotiate(PaddingNegotiate),
    Versions(Versions),
    Certs(Certs),
    AuthChollenge(AuthChallenge),
    Authenticate(Authenticate),
    Authorize(Authorize),
}

impl Command {
    fn command_id(&self) -> u8 {
        match self {
            Command::Padding => 0,
            Command::VPadding => 128,

            Command::Create(_) => 1,
            Command::Created(_) => 2,
            Command::Relay(_) => 3,
            Command::Destroy(_) => 4,
            Command::CreateFast(_) => 5,
            Command::CreatedFast(_) => 6,
            Command::Versions(_) => 7,
            Command::Netinfo(_) => 8,
            Command::RelayEarly(_) => 9,
            Command::Create2(_) => 10,
            Command::Created2(_) => 11,
            Command::PaddingNegotiate(_) => 12,
            Command::Certs(_) => 129,
            Command::AuthChollenge(_) => 130,
            Command::Authenticate(_) => 131,
            Command::Authorize(_) => 132,
        }
    }

    fn data(&self) -> Vec<u8> {
        match self {
            Command::Padding => vec![],
            Command::VPadding => vec![],

            Command::Create(v) => v.data(),
            Command::Created(v) => v.data(),
            Command::Relay(v) => v.data(),
            Command::Destroy(v) => v.data(),
            Command::CreateFast(v) => v.data(),
            Command::CreatedFast(v) => v.data(),
            Command::Versions(v) => v.data(),
            Command::Netinfo(v) => v.data(),
            Command::RelayEarly(v) => v.data(),
            Command::Create2(v) => v.data(),
            Command::Created2(v) => v.data(),
            Command::PaddingNegotiate(v) => v.data(),
            Command::Certs(v) => v.data(),
            Command::AuthChollenge(v) => v.data(),
            Command::Authenticate(v) => v.data(),
            Command::Authorize(v) => v.data(),
        }
    }

    fn from_data(command_id: u8, data: Vec<u8>) -> std::io::Result<Option<Command>> {
        match command_id {
            0 => Ok(Some(Command::Padding)),
            128 => Ok(Some(Command::VPadding)),

            1 => Ok(Some(Command::Create(Create::from_data(data)?))),
            2 => Ok(Some(Command::Created(Created::from_data(data)?))),
            3 => Ok(Some(Command::Relay(Relay::from_data(data)?))),
            4 => Ok(Some(Command::Destroy(Destroy::from_data(data)?))),
            5 => Ok(Some(Command::CreateFast(CreateFast::from_data(data)?))),
            6 => Ok(Some(Command::CreatedFast(CreatedFast::from_data(data)?))),
            7 => Ok(Some(Command::Versions(Versions::from_data(data)?))),
            8 => Ok(Some(Command::Netinfo(Netinfo::from_data(data)?))),
            9 => Ok(Some(Command::RelayEarly(RelayEarly::from_data(data)?))),
            10 => Ok(Some(Command::Create2(Create2::from_data(data)?))),
            11 => Ok(Some(Command::Created2(Created2::from_data(data)?))),
            12 => Ok(Some(Command::PaddingNegotiate(PaddingNegotiate::from_data(data)?))),
            129 => Ok(Some(Command::Certs(Certs::from_data(data)?))),
            130 => Ok(Some(Command::AuthChollenge(AuthChallenge::from_data(data)?))),
            131 => Ok(Some(Command::Authenticate(Authenticate::from_data(data)?))),
            132 => Ok(Some(Command::Authorize(Authorize::from_data(data)?))),
            _ => Ok(None)
        }
    }
}

#[derive(Debug)]
pub struct Create {
}

impl Create {
    fn data(&self) -> Vec<u8> {
        vec![]
    }

    fn from_data(_data: Vec<u8>) -> std::io::Result<Self> {
        Err(std::io::Error::new(std::io::ErrorKind::Other, "Unimplemented"))
    }
}

#[derive(Debug)]
pub struct Created {
}

impl Created {
    fn data(&self) -> Vec<u8> {
        vec![]
    }

    fn from_data(_data: Vec<u8>) -> std::io::Result<Self> {
        Err(std::io::Error::new(std::io::ErrorKind::Other, "Unimplemented"))
    }
}

#[derive(Debug)]
pub struct Relay {
    pub data: Vec<u8>
}

impl Relay {
    fn data(&self) -> Vec<u8> {
        self.data.clone()
    }

    fn from_data(data: Vec<u8>) -> std::io::Result<Self> {
        Ok(Relay { data })
    }
}

#[derive(Debug)]
pub struct Destroy {
    pub reason: DestroyReason
}

#[derive(Debug, Copy, Clone)]
#[repr(u8)]
pub enum DestroyReason {
    None = 0,
    Protocol = 1,
    Internal = 2,
    Requested = 3,
    Hibernating = 4,
    ResourceLimit = 5,
    ConnectFailed = 6,
    OrIdentity = 7,
    ChannelClosed = 8,
    Finished = 9,
    Timeout = 10,
    Destroyed = 11,
    NoSuchService = 12,
}

impl Destroy {
    fn data(&self) -> Vec<u8> {
        vec![self.reason as u8]
    }

    fn from_data(data: Vec<u8>) -> std::io::Result<Self> {
        if data.len() < 1 {
            return Err(std::io::Error::new(std::io::ErrorKind::Other, "Invalid data length"));
        }
        let reason = match data[0] {
            0 => DestroyReason::None,
            1 => DestroyReason::Protocol,
            2 => DestroyReason::Internal,
            3 => DestroyReason::Requested,
            4 => DestroyReason::Hibernating,
            5 => DestroyReason::ResourceLimit,
            6 => DestroyReason::ConnectFailed,
            7 => DestroyReason::OrIdentity,
            8 => DestroyReason::ChannelClosed,
            9 => DestroyReason::Finished,
            10 => DestroyReason::Timeout,
            11 => DestroyReason::Destroyed,
            12 => DestroyReason::NoSuchService,
            _ => return Err(std::io::Error::new(std::io::ErrorKind::Other, "Invalid reason")),
        };
        Ok(Destroy { reason })
    }
}

#[derive(Debug)]
pub struct CreateFast {
    pub x: [u8; 20]
}

impl CreateFast {
    fn data(&self) -> Vec<u8> {
        self.x.to_vec()
    }

    fn from_data(_data: Vec<u8>) -> std::io::Result<Self> {
        Err(std::io::Error::new(std::io::ErrorKind::Other, "Unimplemented"))
    }
}

#[derive(Debug)]
pub struct CreatedFast {
    pub y: [u8; 20],
    pub derivate_key_data: [u8; 20]
}

impl CreatedFast {
    fn data(&self) -> Vec<u8> {
        unimplemented!()
    }

    fn from_data(data: Vec<u8>) -> std::io::Result<Self> {
        let mut cursor = std::io::Cursor::new(data);
        let mut y = [0; 20];
        let mut derivate_key_data = [0; 20];
        std::io::Read::read_exact(&mut cursor,&mut y)?;
        std::io::Read::read_exact(&mut cursor,&mut derivate_key_data)?;
        Ok(CreatedFast { y, derivate_key_data })
    }
}

#[derive(Debug)]
pub struct Versions {
    pub versions: Vec<u16>
}

impl Versions {
    fn data(&self) -> Vec<u8> {
        self.versions.iter().map(|v| v.to_be_bytes().to_vec()).flatten().collect()
    }

    fn from_data(data: Vec<u8>) -> std::io::Result<Self> {
        if data.len() % 2 != 0 {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "Invalid versions length"))
        }
        let mut versions = Vec::new();
        for i in 0..data.len()/2 {
            let mut buf = [0; 2];
            buf.copy_from_slice(&data[i*2..i*2+2]);
            versions.push(u16::from_be_bytes(buf));
        }
        Ok(Versions { versions })
    }

    pub fn upgrade_protocol_version(&self) -> u16 {
        let mut version = 0;
        for own_version in crate::VERSIONS {
            if self.versions.contains(&own_version) && own_version > version {
                version = own_version;
            }
        }
        version
    }
}

#[derive(Debug)]
pub struct Netinfo {
    pub timestamp: DateTime<Utc>,
    pub other_address: std::net::IpAddr,
    pub my_addresses: Vec<std::net::IpAddr>
}

impl Netinfo {
    fn encode_addr(addr: &std::net::IpAddr) -> Vec<u8> {
        let mut data = Vec::new();
        data.push(match addr {
            std::net::IpAddr::V4(_) => 0x04,
            std::net::IpAddr::V6(_) => 0x06
        });
        data.push(match addr {
            std::net::IpAddr::V4(_) => 4,
            std::net::IpAddr::V6(_) => 16
        });
        match addr {
            std::net::IpAddr::V4(a) => data.extend_from_slice(&a.octets()),
            std::net::IpAddr::V6(a) => data.extend_from_slice(&a.octets()),
        }
        data
    }

    fn data(&self) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&(self.timestamp.timestamp() as u32).to_be_bytes());
        data.append(&mut Self::encode_addr(&self.other_address));
        for address in &self.my_addresses {
            data.append(&mut Self::encode_addr(address));
        }
        data
    }

    fn read_addr(cursor: &mut std::io::Cursor<Vec<u8>>) -> std::io::Result<std::net::IpAddr> {
        let address_type = ReadBytesExt::read_u8(cursor)?;
        let address_len = ReadBytesExt::read_u8(cursor)?;
        let address = match address_type {
            0x04 => {
                if address_len != 4 {
                    return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "Invalid IPv4 address length"))
                }
                let mut buf = [0; 4];
                std::io::Read::read_exact(cursor, &mut buf)?;
                std::net::IpAddr::V4(std::net::Ipv4Addr::from(buf))
            }
            0x06 => {
                if address_len != 16 {
                    return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "Invalid IPv6 address length"))
                }
                let mut buf = [0; 16];
                std::io::Read::read_exact(cursor, &mut buf)?;
                std::net::IpAddr::V6(std::net::Ipv6Addr::from(buf))
            }
            _ => return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "Invalid address type"))
        };
        Ok(address)
    }

    fn from_data(data: Vec<u8>) -> std::io::Result<Self> {
        let mut cursor = std::io::Cursor::new(data);
        let timestamp = match Utc.timestamp_opt(ReadBytesExt::read_u32::<BigEndian>(&mut cursor)? as i64, 0) {
            chrono::offset::LocalResult::Single(t) => t,
            _ => return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "Invalid timestamp"))
        };

        let other_address = Self::read_addr(&mut cursor)?;

        let num_my_addresses = ReadBytesExt::read_u8(&mut cursor)?;
        let mut my_addresses = Vec::new();
        for _ in 0..num_my_addresses {
            my_addresses.push(Self::read_addr(&mut cursor)?);
        }

        Ok(Netinfo {
            timestamp,
            other_address,
            my_addresses
        })
    }
}

#[derive(Debug)]
pub struct RelayEarly {
    pub data: Vec<u8>
}

impl RelayEarly {
    fn data(&self) -> Vec<u8> {
        self.data.clone()
    }

    fn from_data(data: Vec<u8>) -> std::io::Result<Self> {
        Ok(RelayEarly { data })
    }
}

#[derive(Debug)]
pub struct Create2 {
    pub client_handshake_type: u16,
    pub client_handshake: Vec<u8>,
}

impl Create2 {
    fn data(&self) -> Vec<u8> {
        let mut cursor = std::io::Cursor::new(Vec::new());

        WriteBytesExt::write_u16::<BigEndian>(&mut cursor, self.client_handshake_type).unwrap();
        WriteBytesExt::write_u16::<BigEndian>(&mut cursor, self.client_handshake.len() as u16).unwrap();
        Write::write_all(&mut cursor, &self.client_handshake).unwrap();

        cursor.into_inner()
    }

    fn from_data(_data: Vec<u8>) -> std::io::Result<Self> {
        Err(std::io::Error::new(std::io::ErrorKind::Other, "Unimplemented"))
    }
}

#[derive(Debug)]
pub struct Created2 {
    pub server_data: Vec<u8>,
}

impl Created2 {
    fn data(&self) -> Vec<u8> {
        unimplemented!()
    }

    fn from_data(data: Vec<u8>) -> std::io::Result<Self> {
        let mut cursor = std::io::Cursor::new(data);
        let len = ReadBytesExt::read_u16::<BigEndian>(&mut cursor)?;
        let mut server_data = vec![0; len as usize];
        std::io::Read::read_exact(&mut cursor,&mut server_data)?;
        Ok(Created2 {
            server_data
        })
    }
}

#[derive(Debug)]
pub struct PaddingNegotiate {
}

impl PaddingNegotiate {
    fn data(&self) -> Vec<u8> {
        vec![]
    }

    fn from_data(_data: Vec<u8>) -> std::io::Result<Self> {
        Err(std::io::Error::new(std::io::ErrorKind::Other, "Unimplemented"))
    }
}

#[derive(Debug)]
pub struct Certs {
    pub link_key_cert: Option<Vec<u8>>,
    pub identity_cert: Option<Vec<u8>>,
    pub authenticate_cell_link_cert: Option<Vec<u8>>,
    pub ed25519_signing_key: Option<crate::cert::Cert>,
    pub tls_link_cert: Option<crate::cert::Cert>,
    pub ed25519_authenticate_cell_link_cert: Option<crate::cert::Cert>,
    pub ed25519_identity_cert: Option<crate::cert::RsaEd25519CrossCert>,
}

impl Default for Certs {
    fn default() -> Self {
        Certs {
            link_key_cert: None,
            identity_cert: None,
            authenticate_cell_link_cert: None,
            ed25519_signing_key: None,
            tls_link_cert: None,
            ed25519_authenticate_cell_link_cert: None,
            ed25519_identity_cert: None,
        }
    }
}

impl Certs {
    fn data(&self) -> Vec<u8> {
        unimplemented!();
    }

    fn from_data(data: Vec<u8>) -> std::io::Result<Self> {
        let mut cursor = std::io::Cursor::new(data);
        let num_certs = ReadBytesExt::read_u8(&mut cursor)?;
        let mut c = Vec::new();
        for _ in 0..num_certs {
            let cert_tye = ReadBytesExt::read_u8(&mut cursor)?;
            let cert_len = ReadBytesExt::read_u16::<BigEndian>(&mut cursor)?;
            let mut cert = vec![0u8; cert_len as usize];
            std::io::Read::read_exact(&mut cursor, &mut cert)?;
            c.push((cert_tye, cert));
        }
        let mut certs = Certs::default();
        for cert in c {
            match cert.0 {
                1 => {
                    if certs.link_key_cert.is_some() {
                        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "Duplicate link key cert"))
                    }
                    certs.link_key_cert = Some(cert.1);
                },
                2 => {
                    if certs.identity_cert.is_some() {
                        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "Duplicate identity cert"))
                    }
                    certs.identity_cert = Some(cert.1);
                },
                3 => {
                    if certs.authenticate_cell_link_cert.is_some() {
                        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "Duplicate authenticate cell link cert"))
                    }
                    certs.authenticate_cell_link_cert = Some(cert.1);
                },
                4 => {
                    if certs.ed25519_signing_key.is_some() {
                        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "Duplicate Ed25519 signing key"))
                    }
                    certs.ed25519_signing_key = Some(crate::cert::Cert::from_bytes(cert.1)?);
                },
                5 => {
                    if certs.tls_link_cert.is_some() {
                        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "Duplicate TLS link cert"))
                    }
                    certs.tls_link_cert = Some(crate::cert::Cert::from_bytes(cert.1)?);
                },
                6 => {
                    if certs.ed25519_authenticate_cell_link_cert.is_some() {
                        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "Duplicate Ed25519 authenticate cell link cert"))
                    }
                    certs.ed25519_authenticate_cell_link_cert = Some(crate::cert::Cert::from_bytes(cert.1)?);
                },
                7 => {
                    if certs.ed25519_identity_cert.is_some() {
                        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "Duplicate Ed25519 identity cert"))
                    }
                    certs.ed25519_identity_cert = Some(crate::cert::RsaEd25519CrossCert::from_bytes(cert.1)?);
                },
                t => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData, format!("Invalid cert type {}", t)
                    ))
                }
            }
        }
        Ok(certs)
    }
}

#[derive(Debug)]
#[repr(u16)]
pub enum AuthMethod {
    RsaSha256TlsSecret = 1,
    Ed25519Sha256Rfc5705 = 3,
}

#[derive(Debug)]
pub struct AuthChallenge {
    pub challenge: [u8; 32],
    pub methods: Vec<AuthMethod>,
}

impl AuthChallenge {
    fn data(&self) -> Vec<u8> {
        unimplemented!();
    }

    fn from_data(data: Vec<u8>) -> std::io::Result<Self> {
        let mut cursor = std::io::Cursor::new(data);
        let mut challenge = [0u8; 32];
        std::io::Read::read_exact(&mut cursor,&mut challenge)?;
        let num_methods = ReadBytesExt::read_u16::<BigEndian>(&mut cursor)?;
        let mut methods = vec![];
        for _ in 0..num_methods {
            let method = ReadBytesExt::read_u16::<BigEndian>(&mut cursor)?;
            match method {
                1 => methods.push(AuthMethod::RsaSha256TlsSecret),
                3 => methods.push(AuthMethod::Ed25519Sha256Rfc5705),
                _ => {}
            }
        }
        Ok(AuthChallenge {
            challenge,
            methods
        })
    }
}

#[derive(Debug)]
pub struct Authenticate {
}

impl Authenticate {
    fn data(&self) -> Vec<u8> {
        vec![]
    }

    fn from_data(_data: Vec<u8>) -> std::io::Result<Self> {
        Err(std::io::Error::new(std::io::ErrorKind::Other, "Unimplemented"))
    }
}

#[derive(Debug)]
pub struct Authorize {
}

impl Authorize {
    fn data(&self) -> Vec<u8> {
        vec![]
    }

    fn from_data(_data: Vec<u8>) -> std::io::Result<Self> {
        Err(std::io::Error::new(std::io::ErrorKind::Other, "Unimplemented"))
    }
}

#[allow(dead_code)]
#[derive(Debug)]
pub enum ClientHandshake {
    Tap(TapClientHandshake),
    Ntor(NtorClientHandshake)
}

#[derive(Debug)]
pub enum ServerHandshake {
}

#[derive(Debug)]
pub struct TapClientHandshake {
    pub server_id: crate::RsaIdentity,
    pub key_id: Vec<u8>,
    pub client_kp: Vec<u8>
}

#[derive(Debug)]
pub struct NtorClientHandshake {
    pub server_id: crate::RsaIdentity,
    pub key_id: Vec<u8>,
    pub client_kp: Vec<u8>
}

#[derive(Debug)]
pub struct RelayCell {
    pub command: RelayCommand,
    pub recognized: u16,
    pub stream_id: u16,
    pub digest: [u8; 4],
}

#[derive(Debug)]
pub struct RelayCellRaw {
    pub command_id: u8,
    pub recognized: u16,
    pub stream_id: u16,
    pub digest: [u8; 4],
    pub data_len: u16,
    pub data: Vec<u8>,
}

#[allow(dead_code)]
#[derive(Debug)]
pub enum RelayCommand {
    Begin(RelayBegin),
    Data(Vec<u8>),
    End(RelayEnd),
    Connected(RelayConnected),
    SendMe(RelaySendMe),
    Extend,
    Extended,
    Truncate,
    Truncated,
    Drop,
    Resolve,
    Resolved,
    BeginDir,
    Extend2(RelayExtend2),
    Extended2(RelayExtended2),
    Xon,
    Xoff,
    EstablishInto,
    EstablishRendezvous(RelayEstablishRendezvous),
    Introduce1(RelayIntroduce1),
    Introduce2,
    Rendezvous1,
    Rendezvous2(RelayRendezvous2),
    IntroEstablished,
    RendezvousEstablished,
    IntroduceAck(RelayIntroduceAck),
}

impl RelayCell {
    pub fn to_bytes(&self) -> std::io::Result<Vec<u8>> {
        let mut out = std::io::Cursor::new(vec![]);
        let command_id = self.command.command_id();
        let command_data = self.command.data()?;

        WriteBytesExt::write_u8(&mut out, command_id)?;
        WriteBytesExt::write_u16::<BigEndian>(&mut out, self.recognized)?;
        WriteBytesExt::write_u16::<BigEndian>(&mut out, self.stream_id)?;
        Write::write_all(&mut out,&self.digest)?;
        WriteBytesExt::write_u16::<BigEndian>(&mut out, command_data.len() as u16)?;
        Write::write_all(&mut out, &command_data)?;

        Ok(out.into_inner())
    }

    pub fn from_raw(mut raw: RelayCellRaw) -> std::io::Result<Option<RelayCell>> {
        raw.data.truncate(raw.data_len as usize);
        Ok(Some(RelayCell {
            recognized: raw.recognized,
            stream_id: raw.stream_id,
            digest: raw.digest,
            command: match RelayCommand::from_data(raw.command_id, raw.data)? {
                Some(c) => c,
                None => {
                    warn!("Unknown relay command id: {}", raw.command_id);
                    return Ok(None)
                }
            }
        }))
    }
}

impl RelayCellRaw {
    pub fn from_bytes(bytes: &[u8]) -> std::io::Result<RelayCellRaw> {
        let mut cursor = std::io::Cursor::new(bytes);
        let command_id = ReadBytesExt::read_u8(&mut cursor)?;
        let recognized = ReadBytesExt::read_u16::<BigEndian>(&mut cursor)?;
        let stream_id = ReadBytesExt::read_u16::<BigEndian>(&mut cursor)?;
        let mut digest = [0u8; 4];
        Read::read_exact(&mut cursor,&mut digest)?;
        let data_len = ReadBytesExt::read_u16::<BigEndian>(&mut cursor)?;
        let mut data = vec![0; crate::MAX_RELAY_DATA_LEN];
        Read::read_exact(&mut cursor,&mut data)?;

        Ok(RelayCellRaw {
            command_id,
            recognized,
            stream_id,
            digest,
            data_len,
            data,
        })
    }

    pub fn to_bytes(&self) -> std::io::Result<Vec<u8>> {
        let mut out = std::io::Cursor::new(vec![]);

        WriteBytesExt::write_u8(&mut out, self.command_id)?;
        WriteBytesExt::write_u16::<BigEndian>(&mut out, self.recognized)?;
        WriteBytesExt::write_u16::<BigEndian>(&mut out, self.stream_id)?;
        Write::write_all(&mut out,&self.digest)?;
        WriteBytesExt::write_u16::<BigEndian>(&mut out, self.data_len)?;
        Write::write_all(&mut out,&self.data)?;

        Ok(out.into_inner())
    }
}

impl RelayCommand {
    fn command_id(&self) -> u8 {
        match self {
            RelayCommand::Begin(_) => 1,
            RelayCommand::Data(_) => 2,
            RelayCommand::End(_) => 3,
            RelayCommand::Connected(_) => 4,
            RelayCommand::SendMe(_) => 5,
            RelayCommand::Extend => 6,
            RelayCommand::Extended => 7,
            RelayCommand::Truncate => 8,
            RelayCommand::Truncated => 9,
            RelayCommand::Drop => 10,
            RelayCommand::Resolve => 11,
            RelayCommand::Resolved => 12,
            RelayCommand::BeginDir => 13,
            RelayCommand::Extend2(_) => 14,
            RelayCommand::Extended2(_) => 15,
            RelayCommand::Xon => 43,
            RelayCommand::Xoff => 44,

            RelayCommand::EstablishInto => 32,
            RelayCommand::EstablishRendezvous(_) => 33,
            RelayCommand::Introduce1(_) => 34,
            RelayCommand::Introduce2 => 35,
            RelayCommand::Rendezvous1 => 36,
            RelayCommand::Rendezvous2(_) => 37,
            RelayCommand::IntroEstablished => 38,
            RelayCommand::RendezvousEstablished => 39,
            RelayCommand::IntroduceAck(_) => 40,
        }
    }

    fn data(&self) -> std::io::Result<Vec<u8>> {
        Ok(match self {
            RelayCommand::Begin(b) => b.data(),
            RelayCommand::Data(d) => {
                let mut d = d.clone();
                d.truncate(crate::MAX_RELAY_DATA_LEN);
                d
            },
            RelayCommand::End(e) => e.data(),
            RelayCommand::Connected(c) => c.data(),
            RelayCommand::SendMe(c) => c.data()?,
            RelayCommand::Drop => vec![],
            RelayCommand::BeginDir => vec![],
            RelayCommand::Extend2(c) => c.data()?,
            RelayCommand::Extended2(c) => c.data()?,

            RelayCommand::EstablishRendezvous(c) => c.data()?,
            RelayCommand::Introduce1(c) => c.data()?,
            RelayCommand::Rendezvous2(c) => c.data()?,
            RelayCommand::RendezvousEstablished => vec![],
            RelayCommand::IntroduceAck(c) => c.data()?,
            _ => unimplemented!()
        })
    }

    fn from_data(command_id: u8, data: Vec<u8>) -> std::io::Result<Option<RelayCommand>> {
        match command_id {
            1 => Ok(Some(RelayCommand::Begin(RelayBegin::from_data(data)?))),
            2 => Ok(Some(RelayCommand::Data(data))),
            3 => Ok(Some(RelayCommand::End(RelayEnd::from_data(data)?))),
            4 => Ok(Some(RelayCommand::Connected(RelayConnected::from_data(data)?))),
            5 => Ok(Some(RelayCommand::SendMe(RelaySendMe::from_data(data)?))),
            10 => Ok(Some(RelayCommand::Drop)),
            13 => Ok(Some(RelayCommand::BeginDir)),
            14 => Ok(Some(RelayCommand::Extend2(RelayExtend2::from_data(data)?))),
            15 => Ok(Some(RelayCommand::Extended2(RelayExtended2::from_data(data)?))),

            33 => Ok(Some(RelayCommand::EstablishRendezvous(RelayEstablishRendezvous::from_data(data)?))),
            34 => Ok(Some(RelayCommand::Introduce1(RelayIntroduce1::from_data(data)?))),
            37 => Ok(Some(RelayCommand::Rendezvous2(RelayRendezvous2::from_data(data)?))),
            39 => Ok(Some(RelayCommand::RendezvousEstablished)),
            40 => Ok(Some(RelayCommand::IntroduceAck(RelayIntroduceAck::from_data(data)?))),
            _ => Ok(None)
        }
    }
}

#[derive(Debug)]
pub struct RelayBegin {
    pub addr_port: String,
    pub ipv6_ok: bool,
    pub ipv4_not_ok: bool,
    pub ipv6_preferred: bool,
}

impl RelayBegin {
    fn data(&self) -> Vec<u8> {
        let mut cursor = std::io::Cursor::new(vec![]);

        Write::write_all(&mut cursor, self.addr_port.as_bytes()).unwrap();
        WriteBytesExt::write_u8(&mut cursor, 0).unwrap();

        let mut flags = 0u32;

        if self.ipv6_ok {
            flags |= 1;
        }
        if self.ipv4_not_ok {
            flags |= 2;
        }
        if self.ipv6_preferred {
            flags |= 4;
        }

        WriteBytesExt::write_u32::<BigEndian>(&mut cursor, flags).unwrap();

        cursor.into_inner()
    }

    fn from_data(_data: Vec<u8>) -> std::io::Result<Self> {
        unimplemented!()
    }
}

#[derive(Debug)]
pub struct RelayConnected {
    pub address: Option<std::net::IpAddr>,
    pub ttl: u32,
}

impl RelayConnected {
    fn data(&self) -> Vec<u8> {
        unimplemented!();
    }

    fn from_data(data: Vec<u8>) -> std::io::Result<Self> {
        if data.len() == 0 {
            return Ok(RelayConnected {
                address: None,
                ttl: 0
            });
        }

        let mut cursor = std::io::Cursor::new(data);
        let mut address = [0u8; 4];
        Read::read_exact(&mut cursor, &mut address)?;

        if address == [0, 0, 0, 0] {
            let addr_type = ReadBytesExt::read_u8(&mut cursor)?;
            match addr_type {
                6 => {
                    let mut address = [0u8; 16];
                    Read::read_exact(&mut cursor, &mut address)?;
                    let address = std::net::Ipv6Addr::from(address);
                    let ttl = ReadBytesExt::read_u32::<BigEndian>(&mut cursor)?;
                    Ok(RelayConnected {
                        address: Some(std::net::IpAddr::V6(address)),
                        ttl
                    })
                },
                _ => Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "Invalid address type"))
            }
        } else {
            let address = std::net::Ipv4Addr::from(address);
            let ttl = ReadBytesExt::read_u32::<BigEndian>(&mut cursor)?;
            Ok(RelayConnected {
                address: Some(std::net::IpAddr::V4(address)),
                ttl
            })
        }
    }
}

#[derive(Debug)]
pub struct RelayEnd {
    pub reason: EndReason,
    pub addr: Option<std::net::IpAddr>,
    pub ttl: Option<u32>,
}

#[derive(Debug, Copy, Clone)]
#[repr(u8)]
pub enum EndReason {
    Misc = 1,
    ResolveFailed = 2,
    ConnectRefused = 3,
    ExitPolicy = 4,
    Destroy = 5,
    Done = 6,
    Timeout = 7,
    NoRoute = 8,
    Hibernating = 9,
    Internal = 10,
    ResourceLimit = 11,
    ConnReset = 12,
    TorProtocol = 13,
    NotDirectory = 14,
}

impl EndReason {
    pub fn to_io_error(&self) -> std::io::Error {
        match self {
            EndReason::Misc => std::io::Error::new(std::io::ErrorKind::Other, "Misc"),
            EndReason::ResolveFailed => std::io::Error::new(std::io::ErrorKind::NotFound, "Resolve failed"),
            EndReason::ConnectRefused => std::io::Error::new(std::io::ErrorKind::ConnectionRefused, "Connection refused"),
            EndReason::ExitPolicy => std::io::Error::new(std::io::ErrorKind::PermissionDenied, "Exit policy"),
            EndReason::Destroy => std::io::Error::new(std::io::ErrorKind::ConnectionAborted, "Circuit destroyed"),
            EndReason::Done => std::io::Error::new(std::io::ErrorKind::ConnectionAborted, "Connection aborted"),
            EndReason::Timeout => std::io::Error::new(std::io::ErrorKind::TimedOut, "Connection timed out"),
            EndReason::NoRoute => std::io::Error::new(std::io::ErrorKind::AddrNotAvailable, "No route"),
            EndReason::Hibernating => std::io::Error::new(std::io::ErrorKind::ConnectionAborted, "OR hibernating"),
            EndReason::Internal => std::io::Error::new(std::io::ErrorKind::Other, "Internal error"),
            EndReason::ResourceLimit => std::io::Error::new(std::io::ErrorKind::Other, "Resource limit reached"),
            EndReason::ConnReset => std::io::Error::new(std::io::ErrorKind::ConnectionReset, "Connection reset"),
            EndReason::TorProtocol => std::io::Error::new(std::io::ErrorKind::Other, "Tor protocol error"),
            EndReason::NotDirectory => std::io::Error::new(std::io::ErrorKind::ConnectionRefused, "Not a directory"),
        }
    }
}

impl RelayEnd {
    fn data(&self) -> Vec<u8> {
        vec![self.reason as u8]
    }

    fn from_data(data: Vec<u8>) -> std::io::Result<Self> {
        if data.len() == 0 {
            return Ok(RelayEnd {
                reason: EndReason::Misc,
                addr: None,
                ttl: None
            });
        }

        let mut cursor = std::io::Cursor::new(data);
        let reason = ReadBytesExt::read_u8(&mut cursor)?;

        match reason {
            1 => Ok(RelayEnd {
                reason: EndReason::Misc,
                addr: None,
                ttl: None
            }),
            2 => Ok(RelayEnd {
                reason: EndReason::ResolveFailed,
                addr: None,
                ttl: None
            }),
            3 => Ok(RelayEnd {
                reason: EndReason::ConnectRefused,
                addr: None,
                ttl: None
            }),
            4 => Ok(RelayEnd {
                reason: EndReason::ExitPolicy,
                addr: None,
                ttl: None
            }),
            5 => Ok(RelayEnd {
                reason: EndReason::Destroy,
                addr: None,
                ttl: None
            }),
            6 => Ok(RelayEnd {
                reason: EndReason::Done,
                addr: None,
                ttl: None
            }),
            7 => Ok(RelayEnd {
                reason: EndReason::Timeout,
                addr: None,
                ttl: None
            }),
            8 => Ok(RelayEnd {
                reason: EndReason::NoRoute,
                addr: None,
                ttl: None
            }),
            9 => Ok(RelayEnd {
                reason: EndReason::Hibernating,
                addr: None,
                ttl: None
            }),
            10 => Ok(RelayEnd {
                reason: EndReason::Internal,
                addr: None,
                ttl: None
            }),
            11 => Ok(RelayEnd {
                reason: EndReason::ResourceLimit,
                addr: None,
                ttl: None
            }),
            12 => Ok(RelayEnd {
                reason: EndReason::ConnReset,
                addr: None,
                ttl: None
            }),
            13 => Ok(RelayEnd {
                reason: EndReason::TorProtocol,
                addr: None,
                ttl: None
            }),
            14 => Ok(RelayEnd {
                reason: EndReason::NotDirectory,
                addr: None,
                ttl: None
            }),
            _ => Ok(RelayEnd {
                reason: EndReason::Misc,
                addr: None,
                ttl: None
            })
        }
    }
}

#[derive(Debug)]
pub struct RelaySendMe {
    pub version: u8,
    pub data: Option<Vec<u8>>
}

impl RelaySendMe {
    fn data(&self) -> std::io::Result<Vec<u8>> {
        let mut cursor = std::io::Cursor::new(Vec::new());
        WriteBytesExt::write_u8(&mut cursor, self.version)?;
        if let Some(data) = &self.data {
            WriteBytesExt::write_u16::<BigEndian>(&mut cursor, data.len() as u16)?;
            Write::write_all(&mut cursor,data)?;
        }
        Ok(cursor.into_inner())
    }

    fn from_data(data: Vec<u8>) -> std::io::Result<Self> {
        if data.len() == 0 {
            return Ok(RelaySendMe {
                version: 0,
                data: None
            });
        }

        let mut cursor = std::io::Cursor::new(data);
        let version = ReadBytesExt::read_u8(&mut cursor)?;
        if version == 1 {
            let len = ReadBytesExt::read_u16::<BigEndian>(&mut cursor)?;
            let mut data = vec![0; len as usize];
            std::io::Read::read_exact(&mut cursor,&mut data)?;
            return Ok(RelaySendMe {
                version,
                data: Some(data)
            });
        }

        Ok(RelaySendMe {
            version,
            data: None
        })
    }
}

#[derive(Debug)]
pub struct RelayExtend2 {
    pub link_specifiers: Vec<LinkSpecifier>,
    pub client_handshake_type: u16,
    pub client_handshake: Vec<u8>,
}

#[derive(Debug, Clone)]
pub enum LinkSpecifier {
    IPv4Address(std::net::SocketAddrV4),
    IPv6Address(std::net::SocketAddrV6),
    LegacyIdentity(crate::RsaIdentity),
    Ed25519Identity([u8; 32]),
    Unrecognized(u8, Vec<u8>)
}

impl RelayExtend2 {
    fn data(&self) -> std::io::Result<Vec<u8>> {
        let mut cursor = std::io::Cursor::new(Vec::new());

        WriteBytesExt::write_u8(&mut cursor, self.link_specifiers.len() as u8)?;
        for link_spec in &self.link_specifiers {
            let type_id = link_spec.type_id();
            let data = link_spec.data();
            WriteBytesExt::write_u8(&mut cursor, type_id)?;
            WriteBytesExt::write_u8(&mut cursor, data.len() as u8)?;
            Write::write_all(&mut cursor, &data)?;
        }

        WriteBytesExt::write_u16::<BigEndian>(&mut cursor, self.client_handshake_type)?;
        WriteBytesExt::write_u16::<BigEndian>(&mut cursor, self.client_handshake.len() as u16)?;
        Write::write_all(&mut cursor, &self.client_handshake)?;

        Ok(cursor.into_inner())
    }

    fn from_data(_data: Vec<u8>) -> std::io::Result<Self> {
        unimplemented!()
    }
}

impl LinkSpecifier {
    pub(crate) fn type_id(&self) -> u8 {
        match self {
            LinkSpecifier::IPv4Address(_) => 0,
            LinkSpecifier::IPv6Address(_) => 1,
            LinkSpecifier::LegacyIdentity(_) => 2,
            LinkSpecifier::Ed25519Identity(_) => 3,
            LinkSpecifier::Unrecognized(id, _) => *id,
        }
    }

    pub(crate) fn data(&self) -> Vec<u8> {
        match self {
            LinkSpecifier::IPv4Address(addr) => {
                let mut d = addr.ip().octets().to_vec();
                d.append(&mut addr.port().to_be_bytes().to_vec());
                d
            }
            LinkSpecifier::IPv6Address(addr) => {
                let mut d = addr.ip().octets().to_vec();
                d.append(&mut addr.port().to_be_bytes().to_vec());
                d
            }
            LinkSpecifier::LegacyIdentity(id) => id.to_vec(),
            LinkSpecifier::Ed25519Identity(id) => id.to_vec(),
            LinkSpecifier::Unrecognized(_, data) => data.clone(),
        }
    }

    pub(crate) fn from_data(id: u8, data: Vec<u8>) -> std::io::Result<Self> {
        let mut cursor = std::io::Cursor::new(data);

        match id {
            0 => {
                let mut ip = [0; 4];
                std::io::Read::read_exact(&mut cursor, &mut ip)?;
                let port = ReadBytesExt::read_u16::<BigEndian>(&mut cursor)?;
                Ok(LinkSpecifier::IPv4Address(std::net::SocketAddrV4::new(ip.into(), port)))
            }
            1 => {
                let mut ip = [0; 16];
                std::io::Read::read_exact(&mut cursor, &mut ip)?;
                let port = ReadBytesExt::read_u16::<BigEndian>(&mut cursor)?;
                Ok(LinkSpecifier::IPv6Address(std::net::SocketAddrV6::new(ip.into(), port, 0, 0)))
            }
            2 => {
                let mut key = [0; 20];
                std::io::Read::read_exact(&mut cursor, &mut key)?;
                Ok(LinkSpecifier::LegacyIdentity(crate::RsaIdentity::from_bytes(&key)?))
            }
            3 => {
                let mut key = [0; 32];
                std::io::Read::read_exact(&mut cursor, &mut key)?;
                Ok(LinkSpecifier::Ed25519Identity(key))
            }
            id => Ok(LinkSpecifier::Unrecognized(id, cursor.into_inner()))
        }
    }
}

#[derive(Debug)]
pub struct RelayExtended2 {
    pub server_data: Vec<u8>,
}

impl RelayExtended2 {
    fn data(&self) -> std::io::Result<Vec<u8>> {
        unimplemented!()
    }

    fn from_data(data: Vec<u8>) -> std::io::Result<Self> {
        let mut cursor = std::io::Cursor::new(data);
        let len = ReadBytesExt::read_u16::<BigEndian>(&mut cursor)?;
        let mut server_data = vec![0; len as usize];
        std::io::Read::read_exact(&mut cursor,&mut server_data)?;
        Ok(RelayExtended2 {
            server_data
        })
    }
}

#[derive(Debug)]
pub struct RelayEstablishRendezvous {
    pub cookie: [u8; 20],
}

impl RelayEstablishRendezvous {
    fn data(&self) -> std::io::Result<Vec<u8>> {
        Ok(self.cookie.to_vec())
    }

    fn from_data(_data: Vec<u8>) -> std::io::Result<Self> {
       unimplemented!()
    }
}

#[derive(Debug)]
pub struct RelayIntroduce1 {
    pub auth_key: RelayIntroduce1AuthKey,
    pub extensions: Vec<RelayIntroduce1Extension>,
    pub client_pk: [u8; 32],
    pub encrypted_data: Vec<u8>,
    pub mac: [u8; 32],
}

#[allow(dead_code)]
#[derive(Debug)]
pub enum RelayIntroduce1AuthKey {
    Ed25519([u8; 32]),
    Unrecognized(u8, Vec<u8>)
}

#[allow(dead_code)]
#[derive(Debug)]
pub enum RelayIntroduce1Extension {
    Unrecognized(u8, Vec<u8>)
}

impl RelayIntroduce1 {
    pub(crate) fn data(&self) -> std::io::Result<Vec<u8>> {
        let mut cursor = std::io::Cursor::new(Vec::new());

        Write::write_all(&mut cursor,&[0u8; 20])?;

        match &self.auth_key {
            RelayIntroduce1AuthKey::Ed25519(key) => {
                WriteBytesExt::write_u8(&mut cursor, 2)?;
                WriteBytesExt::write_u16::<BigEndian>(&mut cursor, 32)?;
                Write::write_all(&mut cursor, key)?;
            }
            RelayIntroduce1AuthKey::Unrecognized(id, data) => {
                WriteBytesExt::write_u8(&mut cursor, *id)?;
                WriteBytesExt::write_u16::<BigEndian>(&mut cursor, data.len() as u16)?;
                Write::write_all(&mut cursor, data)?;
            }
        }

        WriteBytesExt::write_u8(&mut cursor, self.extensions.len() as u8)?;
        for ext in &self.extensions {
            match ext {
                RelayIntroduce1Extension::Unrecognized(id, data) => {
                    WriteBytesExt::write_u8(&mut cursor, *id)?;
                    WriteBytesExt::write_u8(&mut cursor, data.len() as u8)?;
                    Write::write_all(&mut cursor, data)?;
                }
            }
        }

        Write::write_all(&mut cursor, &self.client_pk)?;
        Write::write_all(&mut cursor, &self.encrypted_data)?;
        Write::write_all(&mut cursor, &self.mac)?;

        Ok(cursor.into_inner())
    }

    fn from_data(_data: Vec<u8>) -> std::io::Result<Self> {
        unimplemented!()
    }
}

#[derive(Debug)]
pub struct RelayRendezvous2 {
    pub data: Vec<u8>
}

impl RelayRendezvous2 {
    pub(crate) fn data(&self) -> std::io::Result<Vec<u8>> {
        unimplemented!()
    }

    fn from_data(data: Vec<u8>) -> std::io::Result<Self> {
        Ok(Self {
            data,
        })
    }
}

#[derive(Debug)]
pub struct RelayIntroduceAck {
    pub status: RelayIntroduceAckStatus,
    pub extensions: Vec<RelayIntroduceAckExtension>,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum RelayIntroduceAckStatus {
    Success,
    ServiceIDNotRecognized,
    BadMessageFormat,
    CantRelayCellToService,
    Unrecognized(u16)
}

#[derive(Debug)]
pub enum RelayIntroduceAckExtension {
    Unrecognized(u8, Vec<u8>)
}

impl RelayIntroduceAck {
    fn data(&self) -> std::io::Result<Vec<u8>> {
        unimplemented!()
    }

    fn from_data(data: Vec<u8>) -> std::io::Result<Self> {
        let mut cursor = std::io::Cursor::new(data);

        let status = match ReadBytesExt::read_u16::<BigEndian>(&mut cursor)? {
            0 => RelayIntroduceAckStatus::Success,
            1 => RelayIntroduceAckStatus::ServiceIDNotRecognized,
            2 => RelayIntroduceAckStatus::BadMessageFormat,
            3 => RelayIntroduceAckStatus::CantRelayCellToService,
            id => RelayIntroduceAckStatus::Unrecognized(id)
        };

        let mut extensions = Vec::new();
        let n_extensions = ReadBytesExt::read_u8(&mut cursor)?;
        for _ in 0..n_extensions {
            let ext_type = ReadBytesExt::read_u8(&mut cursor)?;
            let ext_len = ReadBytesExt::read_u8(&mut cursor)?;
            let mut data = vec![0; ext_len as usize];
            std::io::Read::read_exact(&mut cursor, &mut data)?;

            match ext_type {
                _ => extensions.push(RelayIntroduceAckExtension::Unrecognized(ext_type, data))
            }
        }

        Ok(Self {
            status,
            extensions
        })
    }
}