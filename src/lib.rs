#[macro_use]
extern crate log;

mod fallback;

use rand::prelude::*;
use std::io::{Read, Write};

static PAYLOAD_LEN: usize = 509;

pub struct RsaIdentity([u8; 20]);

impl RsaIdentity {
    fn new(id: &str) -> RsaIdentity {
        let mut key = [0; 20];
        hex::decode_to_slice(id, &mut key).unwrap();
        RsaIdentity(key)
    }
}

impl std::fmt::Display for RsaIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "${}", hex::encode(&self.0.as_ref()))
    }
}

impl std::fmt::Debug for RsaIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "RsaIdentity {{ {} }}", self)
    }
}

struct Authority {
    name: String,
    id: RsaIdentity,
}

impl Authority {
    fn new(name: &str, id: &str) -> Authority {
        Authority {
            name: name.to_string(),
            id: RsaIdentity::new(id),
        }
    }
}

fn default_authorities() -> Vec<Authority> {
    vec![
        Authority::new("bastet", "27102BC123E7AF1D4741AE047E160C91ADC76B21"),
        Authority::new("dannenberg", "0232AF901C31A04EE9848595AF9BB7620D4C5B2E"),
        Authority::new("dizum", "E8A9C45EDE6D711294FADF8E7951F4DE6CA56B58"),
        Authority::new("gabelmoo", "ED03BB616EB2F60BEC80151114BB25CEF515B226"),
        Authority::new("longclaw", "23D15D965BC35114467363C165C4F724B64B4F66"),
        Authority::new("maatuska", "49015F787433103580E3B66A1707A00E60F2D15B"),
        Authority::new("moria1", "F533C81CEF0BC0267857C99B2F471ADF249FA232"),
        Authority::new("tor26", "14C131DFC5C6F93646BE72FA1401C02A8DF2E8B4"),
    ]
}

#[derive(Debug)]
struct Cell {
    circuit_id: u32,
    command: Command
}

impl Cell {
    fn write<W: Write>(&self, version: u16, out: &mut W) -> std::io::Result<()> {
        let command_id = self.command.command_id();
        let command_data = self.command.data();
        let is_variable = Self::is_variable(command_id, version);

        if version >= 4 {
            out.write_all(&self.circuit_id.to_be_bytes())?;
        } else {
            out.write_all(&(self.circuit_id as u16).to_be_bytes())?;
        }
        out.write_all(&command_id.to_be_bytes())?;

        if is_variable {
            out.write_all(&(command_data.len() as u16).to_be_bytes())?;
            out.write_all(&command_data)?;
        } else {
            let padding = vec![0; PAYLOAD_LEN - command_data.len()];
            out.write_all(&command_data)?;
            out.write_all(&padding)?;
        }
        Ok(())
    }

    fn read<R: Read>(version: u16, read: &mut R) -> std::io::Result<Option<Cell>> {
        let circuit_id = if version >= 4 {
            let mut buf = [0; 4];
            read.read_exact(& mut buf)?;
            u32::from_be_bytes(buf)
        } else {
            let mut buf = [0; 2];
            read.read_exact(& mut buf)?;
            u16::from_be_bytes(buf) as u32
        };

        let mut buf = [0; 1];
        read.read_exact(& mut buf)?;
        let command_id = u8::from_be_bytes(buf);
        let is_variable = Self::is_variable(command_id, version);
        let buf = if is_variable {
            let mut buf = [0; 2];
            read.read_exact(& mut buf)?;
            let len = u16::from_be_bytes(buf) as usize;
            let mut buf = vec![0; len];
            read.read_exact(& mut buf)?;
            buf
        } else {
            let mut buf = vec![0; PAYLOAD_LEN];
            read.read_exact(& mut buf)?;
            buf
        };

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
enum Command {
    Padding,
    Versions(Vec<u16>)
}

impl Command {
    fn command_id(&self) -> u8 {
        match self {
            Command::Padding => 0,
            Command::Versions(_) => 7,
        }
    }

    fn data(&self) -> Vec<u8> {
        match self {
            Command::Padding => vec![],
            Command::Versions(v) => v.iter().map(|v| v.to_be_bytes().to_vec()).flatten().collect(),
        }
    }

    fn from_data(command_id: u8, data: Vec<u8>) -> std::io::Result<Option<Command>> {
        match command_id {
            0 => Ok(Some(Command::Padding)),
            7 => {
                if data.len() % 2 != 0 {
                    return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "Invalid versions length"))
                }
                let mut versions = Vec::new();
                for i in 0..data.len()/2 {
                    let mut buf = [0; 2];
                    buf.copy_from_slice(&data[i*2..i*2+2]);
                    versions.push(u16::from_be_bytes(buf));
                }
                Ok(Some(Command::Versions(versions)))
            },
            _ => Ok(None)
        }
    }
}

fn connect_to_fallback(fallback: &fallback::FallbackDir) -> Result<std::net::TcpStream, std::io::Error> {
    if let Some(v6) = fallback.v6 {
        debug!("Connecting to fallback {} on v6", fallback.id);
        match std::net::TcpStream::connect(v6) {
            Ok(stream) => {
                info!("TCP connection to fallback {} established", fallback.id);
                return Ok(stream)
            },
            Err(e) => warn!("Failed to connect to fallback {} on v6: {}", fallback.id, e),
        }
    }
    debug!("Connecting to fallback {} on v4", fallback.id);
    match std::net::TcpStream::connect(fallback.v4) {
        Ok(stream) => {
            info!("TCP connection to fallback {} established", fallback.id);
            return Ok(stream)
        },
        Err(e) => {
            warn!("Failed to connect to fallback {} on v4: {}", fallback.id, e);
            Err(e)
        },
    }
}

fn is_v3_handshake(ssl: &openssl::ssl::SslRef) -> bool {
    let cert = match ssl.peer_certificate() {
        Some(cert) => cert,
        None => return false,
    };

    // The certificate is self-signed
    let pubkey = match cert.public_key() {
        Ok(pubkey) => pubkey,
        Err(_) => return false,
    };
    match cert.verify(&pubkey) {
        Ok(true) => return true,
        _ => {}
    }

    // Some component other than "commonName" is set in the subject or issuer DN of the certificate.
    if cert.issuer_name().entries()
        .any(|entry| entry.object().nid() != openssl::nid::Nid::COMMONNAME) ||
        cert.subject_name().entries()
        .any(|entry| entry.object().nid() != openssl::nid::Nid::COMMONNAME) {
        return true;
    }

    // The commonName of the subject or issuer of the certificate ends with a suffix other than ".net".
    if let Some(issuer_cn) = cert.issuer_name().entries_by_nid(openssl::nid::Nid::COMMONNAME).next() {
        if !issuer_cn.data().as_slice().ends_with(b".net") {
            return true;
        }
    }
    if let Some(subject_cn) = cert.subject_name().entries_by_nid(openssl::nid::Nid::COMMONNAME).next() {
        if !subject_cn.data().as_slice().ends_with(b".net") {
            return true;
        }
    }

    // The certificate's public key modulus is longer than 1024 bits.
    if pubkey.bits() > 1024 {
        return true;
    }

    false
}

pub fn fetch_consensus() {
    let mut rng = thread_rng();

    info!("Fetching consensus");
    let fallback_dirs = fallback::FallbackDirs::new();
    let fallback = fallback_dirs.fallbacks.choose(&mut rng).unwrap();
    info!("Using fallback {}", fallback.id);
    let mut tcp_stream = connect_to_fallback(fallback).unwrap();

    let mut ssl_context_builder = openssl::ssl::SslContext::builder(
        openssl::ssl::SslMethod::tls()
    ).unwrap();
    ssl_context_builder.set_options(openssl::ssl::SslOptions::NO_SSLV2);
    ssl_context_builder.set_options(openssl::ssl::SslOptions::NO_SSLV3);
    ssl_context_builder.set_options(openssl::ssl::SslOptions::NO_TICKET);
    ssl_context_builder.set_options(openssl::ssl::SslOptions::SINGLE_DH_USE);
    ssl_context_builder.set_options(openssl::ssl::SslOptions::SINGLE_ECDH_USE);
    ssl_context_builder.set_options(openssl::ssl::SslOptions::NO_SESSION_RESUMPTION_ON_RENEGOTIATION);
    ssl_context_builder.set_options(openssl::ssl::SslOptions::NO_COMPRESSION);
    ssl_context_builder.set_verify(openssl::ssl::SslVerifyMode::NONE);
    let ssl_context = ssl_context_builder.build();

    let mut tls_stream = openssl::ssl::SslStream::new(
        openssl::ssl::Ssl::new(&ssl_context).unwrap(), tcp_stream
    ).unwrap();
    tls_stream.connect().unwrap();
    info!("TLS connection to fallback {} established", fallback.id);
    if !is_v3_handshake(tls_stream.ssl()) {
        panic!("Fallback {} did not present a v3 handshake", fallback.id);
    }

    let mut protocol_version: u16 = 3;
    let version_cell = Cell {
        circuit_id: 0,
        command: Command::Versions(vec![3, 4, 5])
    };
    version_cell.write(protocol_version, &mut tls_stream).unwrap();

    let cell = Cell::read(protocol_version, &mut tls_stream).unwrap();
    println!("{:?}", cell);
}