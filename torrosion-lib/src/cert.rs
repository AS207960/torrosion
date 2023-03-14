use std::io::Read;
use byteorder::{BigEndian, ReadBytesExt};
use chrono::prelude::*;

#[derive(Debug, Clone)]
pub struct Cert {
    signed_data: Vec<u8>,
    pub version: u8,
    pub cert_type: CertType,
    pub expiration: DateTime<Utc>,
    pub key_type: KeyType,
    pub extensions: Vec<CertExtension>,
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
#[repr(u8)]
pub enum CertType {
    Ed25519SigningKey = 0x04,
    TlsLinkCert = 0x05,
    Ed25519AuthKey = 0x06,
    OnionServiceDescriptorKey = 0x08,
    OnionServiceIntroductionPointKey = 0x09,
    NtorOnionKey = 0x0A,
    OnionServiceNtorEncryptionKey = 0x0B,
}

#[derive(Debug, Clone, Copy)]
pub enum KeyType {
    Ed25519([u8; 32]),
    RsaSha256([u8; 32]),
    X509Sha256([u8; 32]),
}

impl KeyType {
    pub fn as_bytes(&self) -> [u8; 32] {
        match self {
            KeyType::Ed25519(k) => *k,
            KeyType::RsaSha256(k) => *k,
            KeyType::X509Sha256(k) => *k,
        }
    }
}

#[derive(Debug, Clone)]
pub struct CertExtension {
    pub extension_type: CertExtensionType,
    pub critical: bool,
}

#[derive(Debug, Clone)]
pub enum CertExtensionType {
    SignedWithEd25519Key([u8; 32]),
    Other((u8, Vec<u8>))
}

impl Cert {
    pub fn from_bytes(data: Vec<u8>) -> std::io::Result<Cert> {
        let mut cursor = std::io::Cursor::new(data);
        let version = cursor.read_u8()?;
        let cert_type = match cursor.read_u8()? {
            0x04 => CertType::Ed25519SigningKey,
            0x05 => CertType::TlsLinkCert,
            0x06 => CertType::Ed25519AuthKey,
            0x08 => CertType::OnionServiceDescriptorKey,
            0x09 => CertType::OnionServiceIntroductionPointKey,
            0x0A => CertType::NtorOnionKey,
            0x0B => CertType::OnionServiceNtorEncryptionKey,
            t => return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData, format!("Invalid cert type {}", t)
            )),
        };
        let expiration = (cursor.read_u32::<BigEndian>()? as u64) * 60 * 60;
        let expiration = match Utc.timestamp_opt(expiration as i64, 0) {
            chrono::offset::LocalResult::Single(t) => t,
            _ => return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "Invalid expiration")),
        };
        let key_type = match cursor.read_u8()? {
            0x01 => {
                let mut key = [0; 32];
                cursor.read_exact(&mut key)?;
                KeyType::Ed25519(key)
            },
            0x02 => {
                let mut key = [0; 32];
                cursor.read_exact(&mut key)?;
                KeyType::RsaSha256(key)
            },
            0x03 => {
                let mut key = [0; 32];
                cursor.read_exact(&mut key)?;
                KeyType::X509Sha256(key)
            },
            _ => return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "Invalid key type")),
        };
        let mut extensions = vec![];
        let num_extensions = cursor.read_u8()?;
        for _ in 0..num_extensions {
            let extension_len = cursor.read_u16::<BigEndian>()? as usize;
            let extension_type = cursor.read_u8()?;
            let extension_flags = cursor.read_u8()?;
            let mut extension_data = vec![0u8; extension_len];
            cursor.read_exact(&mut extension_data)?;
            let critical = extension_flags & 0x00 != 0;
            let extension = match extension_type {
                0x04 => {
                    if extension_len != 32 {
                        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "Invalid extension length"));
                    }
                    CertExtensionType::SignedWithEd25519Key(<[u8; 32]>::try_from(extension_data).unwrap())
                },
                o => CertExtensionType::Other((o, extension_data))
            };
            extensions.push(CertExtension {
                extension_type: extension,
                critical,
            });
        }
        let mut signed_data = cursor.into_inner();
        let signature = signed_data.split_off(signed_data.len() - 64);
        Ok(Cert {
            signed_data,
            version,
            cert_type,
            expiration,
            key_type,
            extensions,
            signature,
        })
    }

    pub fn verify_signature_ed25519(&self, pkey: &[u8; 32]) -> std::io::Result<()> {
        if self.expiration < Utc::now() {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "Certificate expired"));
        }

        for ext in &self.extensions {
            match &ext.extension_type {
                CertExtensionType::SignedWithEd25519Key(signed_with_key) => {
                    if ring::constant_time::verify_slices_are_equal(signed_with_key, pkey).is_err() {
                        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "Invalid signature"));
                    }
                },
                CertExtensionType::Other((id, _)) => if ext.critical {
                    return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, format!("Unknown critical extension {}", id)));
                }
            }
        }
        let pkey = ring::signature::UnparsedPublicKey::new(
            &ring::signature::ED25519, pkey
        );
        pkey.verify(
            &self.signed_data, &self.signature
        ).map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "Invalid signature"))
    }
}

#[derive(Debug)]
pub struct RsaEd25519CrossCert {
    pub ed25519_key: [u8; 32],
    pub expiration: DateTime<Utc>,
    signed_data: Vec<u8>,
    signature: Vec<u8>,
}

impl RsaEd25519CrossCert {
    pub fn from_bytes(data: Vec<u8>) -> std::io::Result<RsaEd25519CrossCert> {
        let mut cursor = std::io::Cursor::new(data);
        let mut ed25519_key = [0; 32];
        cursor.read_exact(&mut ed25519_key)?;
        let expiration = cursor.read_u32::<BigEndian>()? * 60 * 60;
        let expiration = match Utc.timestamp_opt(expiration as i64, 0) {
            chrono::offset::LocalResult::Single(t) => t,
            _ => return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "Invalid expiration")),
        };
        let signature_len = cursor.read_u8()? as usize;
        let mut signed_data = b"Tor TLS RSA/Ed25519 cross-certificate".to_vec();
        let mut signed_data_raw = cursor.into_inner();
        let signature = signed_data_raw.split_off(signed_data_raw.len() - signature_len);
        signed_data_raw.remove(signed_data_raw.len() - 1);
        signed_data.append(&mut signed_data_raw);
        Ok(RsaEd25519CrossCert {
            ed25519_key,
            expiration,
            signed_data,
            signature,
        })
    }

    pub fn verify_signature(&self, pkey: &[u8]) -> std::io::Result<()> {
        use rsa::PublicKey;
        use rsa::pkcs8::DecodePublicKey;

        let hash = ring::digest::digest(&ring::digest::SHA256, &self.signed_data);
        let key = match rsa::RsaPublicKey::from_public_key_der(pkey) {
            Ok(key) => key,
            Err(_) => return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid RSA key")),
        };
        key.verify(rsa::PaddingScheme::new_pkcs1v15_sign_raw(), hash.as_ref(), &self.signature)
            .map_err(|_| std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid signature over RSA->Ed25519 cross-cert"
            ))
    }
}

pub fn verify_x509_signature(
    cert: &x509_parser::certificate::X509Certificate,
    public_key: Option<&x509_parser::x509::SubjectPublicKeyInfo>,
) -> Result<(), x509_parser::error::X509Error> {
    fn get_ec_curve_sha(
        pubkey_alg: &x509_parser::x509::AlgorithmIdentifier,
        sha_len: usize,
    ) -> Option<&'static dyn ring::signature::VerificationAlgorithm> {
        let curve_oid = pubkey_alg.parameters.as_ref()?.as_oid().ok()?;
        if curve_oid == oid_registry::OID_EC_P256 {
            match sha_len {
                256 => Some(&ring::signature::ECDSA_P256_SHA256_ASN1),
                384 => Some(&ring::signature::ECDSA_P256_SHA384_ASN1),
                _ => None,
            }
        } else if curve_oid == oid_registry::OID_NIST_EC_P384 {
            match sha_len {
                256 => Some(&ring::signature::ECDSA_P384_SHA256_ASN1),
                384 => Some(&ring::signature::ECDSA_P384_SHA384_ASN1),
                _ => None,
            }
        } else {
            None
        }
    }

    let spki = public_key.unwrap_or_else(|| cert.public_key());
    let signature_alg = &cert.signature_algorithm.algorithm;
    let verification_alg: &dyn ring::signature::VerificationAlgorithm =
    if *signature_alg == oid_registry::OID_PKCS1_SHA1WITHRSA || *signature_alg == oid_registry::OID_SHA1_WITH_RSA {
        &ring::signature::RSA_PKCS1_1024_8192_SHA1_FOR_LEGACY_USE_ONLY
    } else if *signature_alg == oid_registry::OID_PKCS1_SHA256WITHRSA {
        &ring::signature::RSA_PKCS1_1024_8192_SHA256_FOR_LEGACY_USE_ONLY
    } else if *signature_alg == oid_registry::OID_PKCS1_SHA384WITHRSA {
        &ring::signature::RSA_PKCS1_2048_8192_SHA384
    } else if *signature_alg == oid_registry::OID_PKCS1_SHA512WITHRSA {
        &ring::signature::RSA_PKCS1_1024_8192_SHA512_FOR_LEGACY_USE_ONLY
    } else if *signature_alg == oid_registry::OID_SIG_ECDSA_WITH_SHA256 {
        get_ec_curve_sha(&spki.algorithm, 256)
            .ok_or(x509_parser::error::X509Error::SignatureUnsupportedAlgorithm)?
    } else if *signature_alg == oid_registry::OID_SIG_ECDSA_WITH_SHA384 {
        get_ec_curve_sha(&spki.algorithm, 384)
            .ok_or(x509_parser::error::X509Error::SignatureUnsupportedAlgorithm)?
    } else if *signature_alg == oid_registry::OID_SIG_ED25519 {
        &ring::signature::ED25519
    } else {
        return Err(x509_parser::error::X509Error::SignatureUnsupportedAlgorithm);
    };
    let key = ring::signature::UnparsedPublicKey::new(verification_alg, &spki.subject_public_key.data);
    let sig = &cert.signature_value.data;
    key.verify(cert.tbs_certificate.as_ref(), sig)
        .or(Err(x509_parser::error::X509Error::SignatureVerificationError))
}