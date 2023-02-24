use rsa::PublicKey;
use x509_parser::prelude::FromDer;

#[derive(Debug)]
pub struct DirectoryKeyCertificate {
    pub directory_address: Option<std::net::SocketAddr>,
    pub fingerprint: crate::RsaIdentity,
    pub identity_key: Vec<u8>,
    pub key_published: chrono::DateTime<chrono::Utc>,
    pub key_expires: chrono::DateTime<chrono::Utc>,
    pub signing_key: Vec<u8>,
    pub cross_cert: Vec<u8>,
    pub certification: Vec<u8>,
    pub digest: ring::digest::Digest,
}

impl DirectoryKeyCertificate {
    pub fn verify(&self) -> bool {
        let now = chrono::Utc::now();

        let identity_key = match x509_parser::public_key::RSAPublicKey::from_der(&self.identity_key) {
            Ok(k) => k.1,
            Err(_) => return false
        };
        if identity_key.key_size() < 1024 {
            return false;
        }

        let signing_key = match x509_parser::public_key::RSAPublicKey::from_der(&self.signing_key) {
            Ok(k) => k.1,
            Err(_) => return false,
        };
        if signing_key.key_size() < 1024 {
            return false;
        }

        let identity = match crate::RsaIdentity::from_asn1(&self.identity_key) {
            Ok(k) => k,
            Err(_) => return false,
        };
        if identity != self.fingerprint {
            return false;
        }

        if self.key_published - chrono::Duration::minutes(15) >= now {
            return false;
        }
        if self.key_expires + chrono::Duration::minutes(15) <= now {
            return false;
        }

        let signing_key = match self.signing_key_rsa() {
            Some(k) => k,
            None => return false,
        };
        let identity_key = match self.identity_key_rsa() {
            Some(k) => k,
            None => return false,
        };

        let hash = ring::digest::digest(&ring::digest::SHA1_FOR_LEGACY_USE_ONLY, &self.identity_key);
        match signing_key.verify(rsa::PaddingScheme::new_pkcs1v15_sign_raw(), hash.as_ref(), &self.cross_cert) {
            Ok(_) => (),
            Err(_) => return false
        }

        match identity_key.verify(rsa::PaddingScheme::new_pkcs1v15_sign_raw(), self.digest.as_ref(), &self.certification) {
            Ok(_) => (),
            Err(_) => return false
        }

        true
    }

    pub fn identity_key_rsa(&self) -> Option<rsa::RsaPublicKey> {
        let key = match x509_parser::public_key::RSAPublicKey::from_der(&self.identity_key) {
            Ok(k) => k.1,
            Err(_) => return None
        };
        match rsa::RsaPublicKey::new(
            rsa::BigUint::from_bytes_be(key.modulus),
            rsa::BigUint::from_bytes_be(key.exponent)
        ) {
            Ok(k) => Some(k),
            Err(_) => None,
        }
    }

    pub fn signing_key_rsa(&self) -> Option<rsa::RsaPublicKey> {
        let key = match x509_parser::public_key::RSAPublicKey::from_der(&self.signing_key) {
            Ok(k) => k.1,
            Err(_) => return None
        };
        match rsa::RsaPublicKey::new(
            rsa::BigUint::from_bytes_be(key.modulus),
            rsa::BigUint::from_bytes_be(key.exponent)
        ) {
            Ok(k) => Some(k),
            Err(_) => None,
        }
    }
}

impl DirectoryKeyCertificate {
    pub async fn parse<R: tokio::io::AsyncRead + Unpin + Send>(reader: &mut R) -> std::io::Result<Self> {
        let mut lines = super::LineReader::new(reader).iter(&ring::digest::SHA1_FOR_LEGACY_USE_ONLY);

        let dkcv = DirectoryKeyCertificateVersion::parse(&mut lines).await?;
        if dkcv.0 != 3 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput, "Unsupported directory key certificate version"
            ));
        }

        let mut parts = vec![];
        while let Some(p) = Part::parse(&mut lines).await? {
            parts.push(p);
        }

        Ok(DirectoryKeyCertificate {
            directory_address: super::get_at_most_once!(parts, Part::DirectoryAddress),
            fingerprint: super::get_exactly_once!(parts, Part::Fingerprint),
            identity_key: super::get_exactly_once!(parts, Part::DirectoryIdentityKey),
            key_published: super::get_exactly_once!(parts, Part::DirectoryKeyPublished),
            key_expires: super::get_exactly_once!(parts, Part::DirectoryKeyExpires),
            signing_key: super::get_exactly_once!(parts, Part::DirectorySigningKey),
            cross_cert: super::get_exactly_once!(parts, Part::DirectoryKeyCrosscert),
            certification: super::get_exactly_once!(parts, Part::DirectoryKeyCertification),
            digest: lines.digest(),
        })
    }
}

struct DirectoryKeyCertificateVersion(usize);

impl DirectoryKeyCertificateVersion {
    async fn parse(reader: &mut super::LineReaderIter<'_>) -> std::io::Result<Self> {
        let line = match reader.next().await {
            Some(l) => l?,
            None => return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput, "Invalid directory key certificate version"
            )),
        };
        let mut parts = line.trim().split(" ");
        let def = parts.next().ok_or(std::io::Error::new(
            std::io::ErrorKind::InvalidInput, "Invalid directory key certificate version"
        ))?;
        if def != "dir-key-certificate-version" {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput, "Invalid directory key certificate version"
            ));
        }
        let version = parts.next().ok_or(std::io::Error::new(
            std::io::ErrorKind::InvalidInput, "Invalid directory key certificate version"
        ))?;
        let version = version.parse::<usize>().map_err(|_| std::io::Error::new(
            std::io::ErrorKind::InvalidInput, "Invalid directory key certificate version"
        ))?;
        Ok(Self(version))
    }
}

#[derive(Debug)]
enum Part {
    DirectoryAddress(std::net::SocketAddr),
    Fingerprint(crate::RsaIdentity),
    DirectoryIdentityKey(Vec<u8>),
    DirectoryKeyPublished(chrono::DateTime<chrono::Utc>),
    DirectoryKeyExpires(chrono::DateTime<chrono::Utc>),
    DirectorySigningKey(Vec<u8>),
    DirectoryKeyCrosscert(Vec<u8>),
    DirectoryKeyCertification(Vec<u8>),
}

impl Part {
    async fn parse(reader: &mut super::LineReaderIter<'_>) -> std::io::Result<Option<Self>> {
        loop {
            let line = match reader.next().await {
                Some(l) => l?,
                None => return Ok(None)
            };

            let mut parts = line.trim().split(" ");
            let def = parts.next().ok_or(std::io::Error::new(
                std::io::ErrorKind::InvalidInput, "Invalid directory key certificate"
            ))?;
            return Ok(Some(match def {
                "dir-address" => {
                    let sock_addr = parts.next().ok_or(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput, "Invalid directory key certificate"
                    ))?;
                    let sock_addr = sock_addr.parse::<std::net::SocketAddr>().map_err(|_| std::io::Error::new(
                        std::io::ErrorKind::InvalidInput, "Invalid directory key certificate"
                    ))?;
                    Self::DirectoryAddress(sock_addr)
                }
                "fingerprint" => {
                    let fingerprint = parts.next().ok_or(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput, "Invalid directory key certificate"
                    ))?;
                    let fingerprint = crate::RsaIdentity::from_hex(fingerprint).map_err(|_| std::io::Error::new(
                        std::io::ErrorKind::InvalidInput, "Invalid directory key certificate"
                    ))?;
                    Self::Fingerprint(fingerprint)
                }
                "dir-identity-key" => {
                    let cert = super::read_pem(reader).await.map_err(|_| std::io::Error::new(
                        std::io::ErrorKind::InvalidInput, "Invalid directory key certificate"
                    ))?;
                    Self::DirectoryIdentityKey(cert.contents)
                }
                "dir-key-published" => {
                    let date = parts.next().ok_or(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput, "Invalid directory key certificate"
                    ))?;
                    let time = parts.next().ok_or(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput, "Invalid directory key certificate"
                    ))?;
                    let date_time = chrono::NaiveDateTime::parse_from_str(&format!("{} {}", date, time), "%Y-%m-%d %H:%M:%S").map_err(|_| std::io::Error::new(
                        std::io::ErrorKind::InvalidInput, "Invalid directory key certificate"
                    ))?;
                    Self::DirectoryKeyPublished(chrono::DateTime::from_utc(date_time, chrono::Utc))
                },
                "dir-key-expires" => {
                    let date = parts.next().ok_or(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput, "Invalid directory key certificate"
                    ))?;
                    let time = parts.next().ok_or(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput, "Invalid directory key certificate"
                    ))?;
                    let date_time = chrono::NaiveDateTime::parse_from_str(&format!("{} {}", date, time), "%Y-%m-%d %H:%M:%S").map_err(|_| std::io::Error::new(
                        std::io::ErrorKind::InvalidInput, "Invalid directory key certificate"
                    ))?;
                    Self::DirectoryKeyExpires(chrono::DateTime::from_utc(date_time, chrono::Utc))
                },
                "dir-signing-key" => {
                    let cert = super::read_pem(reader).await.map_err(|_| std::io::Error::new(
                        std::io::ErrorKind::InvalidInput, "Invalid directory key certificate"
                    ))?;
                    Self::DirectorySigningKey(cert.contents)
                },
                "dir-key-crosscert" => {
                    let cert = super::read_pem(reader).await.map_err(|_| std::io::Error::new(
                        std::io::ErrorKind::InvalidInput, "Invalid directory key certificate"
                    ))?;
                    Self::DirectoryKeyCrosscert(cert.contents)
                },
                "dir-key-certification" => {
                    reader.stop_digesting();
                    let cert = super::read_pem(reader).await.map_err(|_| std::io::Error::new(
                        std::io::ErrorKind::InvalidInput, "Invalid directory key certificate"
                    ))?;
                    Self::DirectoryKeyCertification(cert.contents)
                },
                _ => continue
            }));
        }
    }
}