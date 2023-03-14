use base64::prelude::*;
use byteorder::ReadBytesExt;
use crate::net_status::{get_all, get_at_most_once, get_exactly_once};
use std::io::Read;

#[derive(Debug)]
pub struct Descriptor {
    pub create2_formats: Vec<u16>,
    pub intro_auth_required: Option<Vec<String>>,
    pub single_onion_service: bool,
    pub intro_points: Vec<IntroductionPoint>,
}

impl Descriptor {
    pub(crate) async fn parse<R: tokio::io::AsyncRead + Unpin + Send>(reader: &mut R) -> std::io::Result<Self> {
        let mut lines = crate::net_status::LineReader::new(reader).iter_digest_none();

        let mut line = vec![];
        while let Some(p) = Line::parse(&mut lines).await? {
            line.push(p);
        }

        let mut intro_points = vec![];
        while let Some(p) = IntroductionPoint::parse(&mut lines).await? {
            intro_points.push(p);
        }

        Ok(Self {
            create2_formats: get_exactly_once!(line, Line::Create2Formats),
            intro_auth_required: get_at_most_once!(line, Line::IntroAuthRequired),
            single_onion_service: get_at_most_once!(line, Line::SingleOnionService).is_some(),
            intro_points,
        })
    }
}

#[derive(Debug)]
enum Line {
    Create2Formats(Vec<u16>),
    IntroAuthRequired(Vec<String>),
    SingleOnionService(()),
}

impl Line {
    async fn parse(reader: &mut crate::net_status::LineReaderIter<'_>) -> std::io::Result<Option<Self>> {
        loop {
            let line = match reader.next_if(|l| match l {
                Ok(l) => !l.starts_with("introduction-point"),
                Err(_) => true
            }).await {
                Some(l) => l?,
                None => return Ok(None)
            };

            let mut parts = line.trim().split(" ");
            let def = parts.next().ok_or(std::io::Error::new(
                std::io::ErrorKind::InvalidInput, "Invalid second layer descriptor",
            ))?;
            return Ok(Some(match def {
                "create2-formats" => {
                    let fmts = parts.map(|p| p.parse().map_err(|_| std::io::Error::new(
                        std::io::ErrorKind::InvalidInput, "Invalid second layer descriptor",
                    ))).collect::<Result<Vec<_>, _>>()?;
                    Self::Create2Formats(fmts)
                }
                "intro-auth-required" => {
                    Self::IntroAuthRequired(parts.map(|p| p.to_string()).collect())
                },
                "single-onion-service" => {
                    Self::SingleOnionService(())
                }
                _ => continue
            }))
        }
    }
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct IntroductionPoint {
    pub(crate) link_specifiers: Vec<crate::cell::LinkSpecifier>,
    pub(crate) ntor_onion_key: [u8; 32],
    pub(crate) ntor_enc_key: [u8; 32],
    pub(crate) auth_key: crate::cert::Cert,
    pub(crate) enc_key_cert: crate::cert::Cert,
}

impl IntroductionPoint {
    async fn parse(reader: &mut crate::net_status::LineReaderIter<'_>) -> std::io::Result<Option<Self>> {
        let line = match reader.next().await {
            Some(l) => l?,
            None => return Ok(None)
        };

        let mut parts = line.trim().split(" ");
        let def = parts.next().ok_or(std::io::Error::new(
            std::io::ErrorKind::InvalidInput, "Invalid introduction point",
        ))?;

        if def != "introduction-point" {
            return Ok(None)
        }

        let link_spec = parts.next().ok_or(std::io::Error::new(
            std::io::ErrorKind::InvalidInput, "Invalid introduction point",
        ))?;
        let link_spec = BASE64_STANDARD.decode(link_spec).map_err(|_| std::io::Error::new(
            std::io::ErrorKind::InvalidInput, "Invalid introduction point",
        ))?;

        let mut link_spec = std::io::Cursor::new(link_spec);
        let mut link_specifiers = vec![];
        let nspec = link_spec.read_u8()?;
        for _ in 0..nspec {
            let lstype = link_spec.read_u8()?;
            let lslen = link_spec.read_u8()?;
            let mut lspec = vec![0; lslen as usize];
            link_spec.read_exact(&mut lspec)?;
            link_specifiers.push(crate::cell::LinkSpecifier::from_data(lstype, lspec)?);
        }

        let mut line = vec![];
        while let Some(p) = IntroductionPointLine::parse(reader).await? {
            line.push(p);
        }

        let onion_keys = get_all!(line, IntroductionPointLine::OnionKey);
        let enc_keys = get_all!(line, IntroductionPointLine::EncryptionKey);

        let ntor_onion_key = TryInto::<[u8; 32]>::try_into(onion_keys.iter().find(|(k, _)| k == "ntor").ok_or(std::io::Error::new(
            std::io::ErrorKind::InvalidInput, "Invalid introduction point",
        ))?.1.as_ref()).map_err(|_| std::io::Error::new(
            std::io::ErrorKind::InvalidInput, "Invalid introduction point",
        ))?;
        let ntor_enc_key = TryInto::<[u8; 32]>::try_into(enc_keys.iter().find(|(k, _)| k == "ntor").ok_or(std::io::Error::new(
            std::io::ErrorKind::InvalidInput, "Invalid introduction point",
        ))?.1.as_ref()).map_err(|_| std::io::Error::new(
            std::io::ErrorKind::InvalidInput, "Invalid introduction point",
        ))?;

        let auth_key = get_exactly_once!(line, IntroductionPointLine::AuthKey);
        let auth_key = crate::cert::Cert::from_bytes(auth_key)?;

        let enc_key_cert = get_exactly_once!(line, IntroductionPointLine::EncryptionKeyCert);
        let enc_key_cert = crate::cert::Cert::from_bytes(enc_key_cert)?;

        Ok(Some(Self {
            link_specifiers,
            ntor_onion_key,
            ntor_enc_key,
            auth_key,
            enc_key_cert,
        }))
    }
}

enum IntroductionPointLine {
    OnionKey((String, Vec<u8>)),
    AuthKey(Vec<u8>),
    EncryptionKey((String, Vec<u8>)),
    EncryptionKeyCert(Vec<u8>),
}

impl IntroductionPointLine {
    async fn parse(reader: &mut crate::net_status::LineReaderIter<'_>) -> std::io::Result<Option<Self>> {
        loop {
            let line = match reader.next_if(|l| match l {
                Ok(l) => !l.starts_with("introduction-point"),
                Err(_) => true
            }).await {
                Some(l) => l?,
                None => return Ok(None)
            };

            let mut parts = line.trim().split(" ");
            let def = parts.next().ok_or(std::io::Error::new(
                std::io::ErrorKind::InvalidInput, "Invalid introduction point",
            ))?;
            return Ok(Some(match def {
                "onion-key" => {
                    let key_type = parts.next().ok_or(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput, "Invalid introduction point",
                    ))?;
                    let key = parts.next().ok_or(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput, "Invalid introduction point",
                    ))?;
                    let key = BASE64_STANDARD.decode(key).map_err(|_| std::io::Error::new(
                        std::io::ErrorKind::InvalidInput, "Invalid introduction point",
                    ))?;
                    Self::OnionKey((key_type.to_string(), key))
                }
                "enc-key" => {
                    let key_type = parts.next().ok_or(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput, "Invalid introduction point",
                    ))?;
                    let key = parts.next().ok_or(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput, "Invalid introduction point",
                    ))?;
                    let key = BASE64_STANDARD.decode(key).map_err(|_| std::io::Error::new(
                        std::io::ErrorKind::InvalidInput, "Invalid introduction point",
                    ))?;
                    Self::EncryptionKey((key_type.to_string(), key))
                }
                "auth-key" => {
                    let cert = crate::net_status::read_pem(reader).await.map_err(|_| std::io::Error::new(
                        std::io::ErrorKind::InvalidInput, "Invalid introduction point",
                    ))?;
                    Self::AuthKey(cert.contents)
                },
                "enc-key-cert" => {
                    let cert = crate::net_status::read_pem(reader).await.map_err(|_| std::io::Error::new(
                        std::io::ErrorKind::InvalidInput, "Invalid introduction point",
                    ))?;
                    Self::EncryptionKeyCert(cert.contents)
                },
                _ => continue
            }))
        }
    }
}