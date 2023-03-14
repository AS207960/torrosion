#[derive(Copy, Clone, Eq, PartialEq, Hash)]
pub struct RsaIdentity([u8; 20]);

impl RsaIdentity {
    pub fn new(id: &str) -> RsaIdentity {
        let mut key = [0; 20];
        hex::decode_to_slice(id, &mut key).unwrap();
        RsaIdentity(key)
    }

    pub fn from_hex(id: &str) -> Result<RsaIdentity, hex::FromHexError> {
        let mut key = [0; 20];
        hex::decode_to_slice(id, &mut key)?;
        Ok(RsaIdentity(key))
    }

    pub fn from_asn1(raw: &[u8]) -> std::io::Result<RsaIdentity> {
        let hash = ring::digest::digest(&ring::digest::SHA1_FOR_LEGACY_USE_ONLY, raw);
        Ok(RsaIdentity(<[u8; 20]>::try_from(hash.as_ref()).unwrap()))
    }

    pub fn from_bytes(raw: &[u8]) -> std::io::Result<RsaIdentity> {
        Ok(RsaIdentity(match raw.try_into() {
            Ok(v) => v,
            Err(_) => return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "Invalid RSA identity")),
        }))
    }

    pub fn to_hex(&self) -> String {
        hex::encode(&self.0.as_ref())
    }
}

impl std::fmt::Display for RsaIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "${}", self.to_hex())
    }
}

impl std::fmt::Debug for RsaIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "RsaIdentity {{ {} }}", self)
    }
}

impl std::ops::Deref for RsaIdentity {
    type Target = [u8; 20];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

pub(crate) struct Authority {
    pub(crate) name: String,
    pub(crate) id: RsaIdentity,
}

impl Authority {
    fn new(name: &str, id: &str) -> Authority {
        Authority {
            name: name.to_string(),
            id: RsaIdentity::new(id),
        }
    }
}

pub(crate) fn default_authorities() -> Vec<Authority> {
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