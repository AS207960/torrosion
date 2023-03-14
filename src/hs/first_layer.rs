use base64::prelude::*;
use crate::net_status::{get_all, get_exactly_once};

#[allow(dead_code)]
#[derive(Debug)]
pub struct Descriptor {
    pub(crate) ephemeral_key: [u8; 32],
    pub(crate) auth_clients: Vec<AuthClient>,
    pub(crate) encrypted: Vec<u8>,
}

impl Descriptor {
    pub(crate) async fn parse<R: tokio::io::AsyncRead + Unpin + Send>(reader: &mut R) -> std::io::Result<Self> {
        let mut lines = crate::net_status::LineReader::new(reader).iter_digest_none();

        let mut line = vec![];
        while let Some(p) = Line::parse(&mut lines).await? {
            line.push(p);
        }

        let auth_type = get_exactly_once!(line, Line::DescriptorAuthType);
        if auth_type != "x25519" {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput, "Unsupported hidden service descriptor auth"
            ));
        }

        let ephemeral_key = get_exactly_once!(line, Line::DescriptorAuthEphemeralKey);
        let ephemeral_key = TryInto::<[u8; 32]>::try_into(ephemeral_key).map_err(|_| std::io::Error::new(
            std::io::ErrorKind::InvalidInput, "Invalid hidden service descriptor auth ephemeral key"
        ))?;

        Ok(Self {
            ephemeral_key,
            auth_clients: get_all!(line, Line::AuthClient),
            encrypted: get_exactly_once!(line, Line::Encrypted),
        })
    }
}

#[derive(Debug)]
enum Line {
    DescriptorAuthType(String),
    DescriptorAuthEphemeralKey(Vec<u8>),
    AuthClient(AuthClient),
    Encrypted(Vec<u8>),
}

impl Line {
    async fn parse(reader: &mut crate::net_status::LineReaderIter<'_>) -> std::io::Result<Option<Self>> {
        loop {
            let line = match reader.next().await {
                Some(l) => l?,
                None => return Ok(None)
            };

            let mut parts = line.trim().split(" ");
            let def = parts.next().ok_or(std::io::Error::new(
                std::io::ErrorKind::InvalidInput, "Invalid first layer descriptor",
            ))?;
            return Ok(Some(match def {
                "desc-auth-type" => {
                    let auth_type = parts.next().ok_or(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput, "Invalid first layer descriptor",
                    ))?;
                    Self::DescriptorAuthType(auth_type.to_string())
                }
                "desc-auth-ephemeral-key" => {
                    let key = parts.next().ok_or(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput, "Invalid first layer descriptor",
                    ))?;
                    let key = BASE64_STANDARD.decode(key).map_err(|_| std::io::Error::new(
                        std::io::ErrorKind::InvalidInput, "Invalid first layer descriptor",
                    ))?;
                    Self::DescriptorAuthEphemeralKey(key)
                },
                "auth-client" => {
                    let client = AuthClient::parse(&mut parts)?;
                    Self::AuthClient(client)
                }
                "encrypted" => {
                    let encrypted = crate::net_status::read_pem(reader).await.map_err(|_| std::io::Error::new(
                        std::io::ErrorKind::InvalidInput, "Invalid first layer descriptor",
                    ))?;
                    Self::Encrypted(encrypted.contents)
                },
                _ => continue
            }))
        }
    }
}

#[allow(dead_code)]
#[derive(Debug)]
pub(crate) struct AuthClient {
    pub(crate) client_id: [u8; 8],
    pub(crate) iv: [u8; 16],
    pub(crate) encrypted_cookie: Vec<u8>,
}

impl AuthClient {
    fn parse(line: &mut std::str::Split<&str>) -> std::io::Result<Self> {
        let client_id = line.next().ok_or(std::io::Error::new(
            std::io::ErrorKind::InvalidInput, "Invalid first layer descriptor",
        ))?;
        let client_id = BASE64_STANDARD_NO_PAD.decode(client_id).map_err(|_| std::io::Error::new(
            std::io::ErrorKind::InvalidInput, "Invalid first layer descriptor",
        ))?;
        let client_id = client_id.try_into().map_err(|_| std::io::Error::new(
            std::io::ErrorKind::InvalidInput, "Invalid first layer descriptor",
        ))?;
        let iv = line.next().ok_or(std::io::Error::new(
            std::io::ErrorKind::InvalidInput, "Invalid first layer descriptor",
        ))?;
        let iv = BASE64_STANDARD_NO_PAD.decode(iv).map_err(|_| std::io::Error::new(
            std::io::ErrorKind::InvalidInput, "Invalid first layer descriptor",
        ))?;
        let iv = iv.try_into().map_err(|_| std::io::Error::new(
            std::io::ErrorKind::InvalidInput, "Invalid first layer descriptor",
        ))?;
        let encrypted_cookie = line.next().ok_or(std::io::Error::new(
            std::io::ErrorKind::InvalidInput, "Invalid first layer descriptor",
        ))?;
        let encrypted_cookie = BASE64_STANDARD_NO_PAD.decode(encrypted_cookie).map_err(|_| std::io::Error::new(
            std::io::ErrorKind::InvalidInput, "Invalid first layer descriptor",
        ))?;
        Ok(Self {
            client_id,
            iv,
            encrypted_cookie,
        })
    }
}