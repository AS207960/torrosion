use base64::prelude::*;
use crate::net_status::{get_exactly_once};

#[allow(dead_code)]
#[derive(Debug)]
pub struct Descriptor {
    pub(crate) lifetime: usize,
    pub(crate) signing_key_cert: crate::cert::Cert,
    pub(crate) revision_counter: u64,
    pub(crate) superencrypted: Vec<u8>,
    pub(crate) signature: Vec<u8>,
    pub(crate) signed_data: Vec<u8>,
}

impl Descriptor {
    pub(crate) async fn parse<R: tokio::io::AsyncRead + Unpin + Send>(reader: &mut R) -> std::io::Result<Self> {
        let mut lines = crate::net_status::LineReader::new(reader).iter_digest_none();

        let hsdv = HSDescriptorVersion::parse(&mut lines).await?;
        if hsdv.0 != 3 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput, "Unsupported hidden service descriptor version"
            ));
        }

        let mut line = vec![];
        while let Some(p) = Line::parse(&mut lines).await? {
            line.push(p);
        }

        let signature = Signature::parse(&mut lines).await?;

        let signing_key_cert = match crate::cert::Cert::from_bytes(
            get_exactly_once!(line, Line::SigningKeyCert)
        ) {
            Ok(c) => c,
            Err(e) => return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput, format!("Invalid hidden service descriptor: {}", e)
            ))
        };

        let mut signed_data = b"Tor onion service descriptor sig v3".to_vec();
        signed_data.extend(lines.digest_raw());

        Ok(Self {
            lifetime: get_exactly_once!(line, Line::Lifetime),
            signing_key_cert,
            revision_counter: get_exactly_once!(line, Line::RevisionCounter),
            superencrypted: get_exactly_once!(line, Line::Superencrypted),
            signature: signature.signature,
            signed_data,
        })
    }

    pub(crate) fn verify(&self, blinded_public_key: &[u8; 32]) -> bool {
        if self.signing_key_cert.cert_type != crate::cert::CertType::OnionServiceDescriptorKey {
            return false;
        }

        if self.signing_key_cert.verify_signature_ed25519(blinded_public_key).is_err() {
            return false;
        }

        let pkey = ring::signature::UnparsedPublicKey::new(
            &ring::signature::ED25519, match self.signing_key_cert.key_type {
                crate::cert::KeyType::Ed25519(k) => k,
                _ => return false,
            }
        );
        if pkey.verify(&self.signed_data, &self.signature).is_err() {
            return false;
        }

        true
    }
}

struct HSDescriptorVersion(u32);

impl HSDescriptorVersion {
    async fn parse(reader: &mut crate::net_status::LineReaderIter<'_>) -> std::io::Result<Self> {
        let line = match reader.next().await {
            Some(l) => l?,
            None => return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput, "Invalid hidden service descriptor version"
            )),
        };
        let mut parts = line.trim().split(" ");
        let def = parts.next().ok_or(std::io::Error::new(
            std::io::ErrorKind::InvalidInput, "Invalid hidden service descriptor version"
        ))?;
        if def != "hs-descriptor" {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput, "Invalid hidden service descriptor version"
            ));
        }
        let version = parts.next().ok_or(std::io::Error::new(
            std::io::ErrorKind::InvalidInput, "Invalid hidden service descriptor version"
        ))?;
        let version = version.parse::<u32>().map_err(|_| std::io::Error::new(
            std::io::ErrorKind::InvalidInput, "Invalid hidden service descriptor version"
        ))?;
        Ok(Self(version))
    }
}

#[derive(Debug)]
enum Line {
    Lifetime(usize),
    SigningKeyCert(Vec<u8>),
    RevisionCounter(u64),
    Superencrypted(Vec<u8>),
}

impl Line {
    async fn parse(reader: &mut crate::net_status::LineReaderIter<'_>) -> std::io::Result<Option<Self>> {
        loop {
            let line = match reader.next_if(|l| match l {
                Ok(l) => !l.starts_with("signature"),
                Err(_) => true
            }).await {
                Some(l) => l?,
                None => return Ok(None)
            };

            let mut parts = line.trim().split(" ");
            let def = parts.next().ok_or(std::io::Error::new(
                std::io::ErrorKind::InvalidInput, "Invalid HS descriptor",
            ))?;
            return Ok(Some(match def {
                "descriptor-lifetime" => {
                    let lifetime = parts.next().ok_or(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput, "Invalid HS descriptor",
                    ))?;
                    let lifetime = lifetime.parse::<usize>().map_err(|_| std::io::Error::new(
                        std::io::ErrorKind::InvalidInput, "Invalid HS descriptor",
                    ))?;
                    Self::Lifetime(lifetime)
                },
                "descriptor-signing-key-cert" => {
                    let k = crate::net_status::read_pem(reader).await.map_err(|e| std::io::Error::new(
                        std::io::ErrorKind::InvalidInput, format!("Invalid HS descriptor: {}", e)
                    ))?;
                    Self::SigningKeyCert(k.contents)
                },
                "revision-counter" => {
                    let counter = parts.next().ok_or(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput, "Invalid HS descriptor",
                    ))?;
                    let counter = counter.parse::<u64>().map_err(|_| std::io::Error::new(
                        std::io::ErrorKind::InvalidInput, "Invalid HS descriptor",
                    ))?;
                    Self::RevisionCounter(counter)
                },
                "superencrypted" => {
                    let k = crate::net_status::read_pem(reader).await.map_err(|e| std::io::Error::new(
                        std::io::ErrorKind::InvalidInput, format!("Invalid HS descriptor: {}", e)
                    ))?;
                    Self::Superencrypted(k.contents)
                },
                _ => continue
            }))
        }
    }
}

struct Signature {
    pub signature: Vec<u8>,
}

impl Signature {
    async fn parse(reader: &mut crate::net_status::LineReaderIter<'_>) -> std::io::Result<Self> {
        reader.stop_digesting();

        let line = match reader.next().await {
            Some(l) => l?,
            None => return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof, "Unexpected EOF",
            ))
        };

        let mut parts = line.trim().split(" ");
        let def = parts.next().ok_or(std::io::Error::new(
            std::io::ErrorKind::InvalidInput, "Invalid signature line",
        ))?;
        if def != "signature" {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput, "Invalid signature line",
            ));
        }

        let signature = parts.next().ok_or(std::io::Error::new(
            std::io::ErrorKind::InvalidInput, "Invalid router-signature line",
        ))?;
        let signature = BASE64_STANDARD_NO_PAD.decode(signature).map_err(|_| std::io::Error::new(
            std::io::ErrorKind::InvalidInput, "Invalid signature line",
        ))?;

        Ok(Self {
            signature
        })
    }
}