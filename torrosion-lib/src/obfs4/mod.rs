mod elligator2;

use crypto_secretbox::aead::AeadMutInPlace;
use crypto_secretbox::AeadInPlace;
use rand::{Rng, RngExt};
use digest::KeyInit;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub struct Obfs4Server {
    node_id: [u8; 20],
    public_key: [u8; 32],
}

pub struct Obfs4Stream<I> {
    inner: tokio::io::BufStream<I>,
    keys: SessionKeys
}

#[derive(Debug, Copy, Clone)]
enum Direction {
    ServerToClient,
    ClientToServer,
}

struct SessionKeys {
    client_to_server_encryption: crypto_secretbox::XSalsa20Poly1305,
    client_to_server_nonce_prefix: [u8; 16],
    client_to_server_nonce_counter: u64,
    client_to_server_siphash: siphasher::sip::SipHasher24,
    client_to_server_siphash_iv: [u8; 8],
    server_to_client_encryption: crypto_secretbox::XSalsa20Poly1305,
    server_to_client_nonce_prefix: [u8; 16],
    server_to_client_nonce_counter: u64,
    server_to_client_siphash: siphasher::sip::SipHasher24,
    server_to_client_siphash_iv: [u8; 8],
}

impl SessionKeys {
    fn from_material(mat: &[u8]) -> Self {
        assert_eq!(mat.len(), 144);
        Self {
            client_to_server_encryption: crypto_secretbox::XSalsa20Poly1305::new((&TryInto::<[u8; 32]>::try_into(&mat[0..32]).unwrap()).into()),
            client_to_server_nonce_prefix: TryInto::<[u8; 16]>::try_into(&mat[32..48]).unwrap(),
            client_to_server_nonce_counter: 1,
            client_to_server_siphash: siphasher::sip::SipHasher24::new_with_key(&TryInto::<[u8; 16]>::try_into(&mat[48..64]).unwrap()),
            client_to_server_siphash_iv: TryInto::<[u8; 8]>::try_into(&mat[64..72]).unwrap(),
            server_to_client_encryption: crypto_secretbox::XSalsa20Poly1305::new((&TryInto::<[u8; 32]>::try_into(&mat[72..104]).unwrap()).into()),
            server_to_client_nonce_prefix: TryInto::<[u8; 16]>::try_into(&mat[104..120]).unwrap(),
            server_to_client_nonce_counter: 1,
            server_to_client_siphash: siphasher::sip::SipHasher24::new_with_key(&TryInto::<[u8; 16]>::try_into(&mat[120..136]).unwrap()),
            server_to_client_siphash_iv: TryInto::<[u8; 8]>::try_into(&mat[136..144]).unwrap(),
        }
    }

    fn mask_length(&mut self, len: u16, dir: Direction) -> u16 {
        let (hasher, iv) = match dir {
            Direction::ServerToClient => (self.server_to_client_siphash, self.server_to_client_siphash_iv),
            Direction::ClientToServer => (self.client_to_server_siphash, self.client_to_server_siphash_iv),
        };
        let new_iv = hasher.hash(&iv).to_le_bytes();
        match dir {
            Direction::ServerToClient => self.server_to_client_siphash_iv = new_iv,
            Direction::ClientToServer => self.client_to_server_siphash_iv = new_iv,
        };
        let mask = u16::from_be_bytes([new_iv[0], new_iv[1]]);
        len ^ mask
    }

    fn make_nonce(&mut self, dir: Direction) -> std::io::Result<crypto_secretbox::Nonce> {
        let (prefix, counter) = match dir {
            Direction::ServerToClient => (self.server_to_client_nonce_prefix, self.server_to_client_nonce_counter),
            Direction::ClientToServer => (self.client_to_server_nonce_prefix, self.client_to_server_nonce_counter),
        };
        if counter == 0 {
            return Err(std::io::Error::other("nonce counter exhausted"));
        }
        let counter_bytes = counter.to_be_bytes();
        let nonce = [
            prefix[0],
            prefix[1],
            prefix[2],
            prefix[3],
            prefix[4],
            prefix[5],
            prefix[6],
            prefix[7],
            prefix[8],
            prefix[9],
            prefix[10],
            prefix[11],
            prefix[12],
            prefix[13],
            prefix[14],
            prefix[15],
            counter_bytes[0],
            counter_bytes[1],
            counter_bytes[2],
            counter_bytes[3],
            counter_bytes[4],
            counter_bytes[5],
            counter_bytes[6],
            counter_bytes[7],
        ];
        let new_counter = counter.wrapping_add(1);
        match dir {
            Direction::ServerToClient => self.server_to_client_nonce_counter = new_counter,
            Direction::ClientToServer => self.client_to_server_nonce_counter = new_counter,
        }
        Ok(nonce.into())
    }

    fn encrypt_packet(&mut self, payload_type: u8, data: &[u8], dir: Direction) -> std::io::Result<Vec<u8>> {
        let nonce = self.make_nonce(dir)?;
        let mut packet = Vec::with_capacity(data.len() + 19);
        packet.push(payload_type);
        packet.extend_from_slice(&(data.len() as u16).to_be_bytes());
        packet.extend_from_slice(data);
        packet.extend_from_slice(&[0u8; 16]);
        let cipher = match dir {
            Direction::ServerToClient => &self.server_to_client_encryption,
            Direction::ClientToServer => &self.client_to_server_encryption,
        };
        cipher.encrypt_in_place(&nonce, &[], &mut packet).unwrap();
        Ok(packet)
    }

    fn decrypt_packet(&mut self, data: &[u8], dir: Direction) -> std::io::Result<(u8, Vec<u8>)> {
        let mut packet = data.to_vec();
        let nonce = self.make_nonce(dir)?;
        let cipher = match dir {
            Direction::ServerToClient => &self.server_to_client_encryption,
            Direction::ClientToServer => &self.client_to_server_encryption,
        };
        cipher.decrypt_in_place(&nonce, &[], &mut packet).map_err(|e| std::io::Error::other(format!("decryption failed: {}", e)))?;
        if packet.len() < 3 {
            return Err(std::io::Error::other("invalid packet format"))
        }
        let payload_type = packet[0];
        let len = u16::from_be_bytes([packet[1], packet[2]]) as usize;
        if len + 3 > packet.len() {
            return Err(std::io::Error::other("invalid packet length"))
        }
        Ok((payload_type, (&packet[3..len+3]).to_vec()))
    }
}

impl<I: tokio::io::AsyncRead + tokio::io::AsyncWrite + std::marker::Unpin> Obfs4Stream<I> {
    async fn open(stream: I, server: &Obfs4Server) -> std::io::Result<Self> {
        let mut stream = tokio::io::BufStream::new(stream);

        let mut rng = rand::rng();
        let own_ephemeral_key = elligator2::EphemeralSecret::ephemeral_from_rng(&mut rng);

        let x_prime = own_ephemeral_key.representative();
        let mut p_c = vec![0; rng.random_range(85..8128)];
        rng.fill_bytes(&mut p_c);

        let mut hmac_key_data = Vec::with_capacity(20 + 32);
        hmac_key_data.extend_from_slice(&server.public_key);
        hmac_key_data.extend_from_slice(&server.node_id);
        let hmac_key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &hmac_key_data);

        let m_c_tag = ring::hmac::sign(&hmac_key, &x_prime);
        let m_c = &m_c_tag.as_ref()[..16];

        let e = (chrono::Utc::now().timestamp() / 3600).to_string().into_bytes();

        let mut mac_c_data = Vec::with_capacity(32 + p_c.len() + 16 + e.len());
        mac_c_data.extend_from_slice(&x_prime);
        mac_c_data.extend_from_slice(&p_c);
        mac_c_data.extend_from_slice(m_c);
        mac_c_data.extend_from_slice(&e);
        let mac_c_tag = ring::hmac::sign(&hmac_key, &mac_c_data);
        let mac_c = &mac_c_tag.as_ref()[..16];

        stream.write(&x_prime).await?;
        stream.write(&p_c).await?;
        stream.write(&m_c).await?;
        stream.write(&mac_c).await?;
        stream.flush().await?;

        let mut y_prime = [0u8; 32];
        stream.read_exact(&mut y_prime).await?;
        let mut auth = [0u8; 32];
        stream.read_exact(&mut auth).await?;

        let mut padding = vec![0u8; 45 + 16];
        stream.read_exact(&mut padding).await?;
        let m_s_tag = ring::hmac::sign(&hmac_key, &y_prime);
        let m_s = &m_s_tag.as_ref()[..16];
        while &padding[padding.len()-16..padding.len()] != m_s && padding.len() < 8096 {
            padding.push(stream.read_u8().await?);
        }

        let mut mac_s = [0; 16];
        stream.read_exact(&mut mac_s).await?;
        let mut mac_s_data = Vec::with_capacity(32 + 32 + padding.len() + e.len());
        mac_s_data.extend_from_slice(&y_prime);
        mac_s_data.extend_from_slice(&auth);
        mac_s_data.extend_from_slice(&padding);
        mac_s_data.extend_from_slice(&e);
        let own_mac_s_tag = ring::hmac::sign(&hmac_key, &mac_s_data);
        if mac_s != own_mac_s_tag.as_ref()[..16] {
            return Err(std::io::Error::other("Invalid MAC"));
        }

        let server_identity_key = x25519_dalek::PublicKey::from(server.public_key);
        let server_ephemeral_key = x25519_dalek::PublicKey::from(elligator2::from_representative(y_prime).to_montgomery().to_bytes());

        let (own_auth, key_material) = ntor_auth(
            &own_ephemeral_key,
            server.node_id,
            &server_identity_key,
            &server_ephemeral_key,
            144
        );

        if !constant_time_eq::constant_time_eq(&auth, &own_auth) {
            return Err(std::io::Error::other("Invalid authentication"));
        }

        println!("okm: {:02x?}", key_material);

        let keys = SessionKeys::from_material(&key_material);

        Ok(Self {
            inner: stream,
            keys
        })
    }
}

fn ntor_auth(
    own_ephemeral_key: &x25519_dalek::StaticSecret,
    server_id: [u8; 20],
    server_identity_key: &x25519_dalek::PublicKey,
    server_ephemeral_key: &x25519_dalek::PublicKey,
    key_length: usize
) -> ([u8; 32], Vec<u8>) {
    const PROTO_ID: &'static str = "ntor-curve25519-sha256-1";

    let xy = own_ephemeral_key.diffie_hellman(&server_ephemeral_key);
    let xb = own_ephemeral_key.diffie_hellman(&server_identity_key);

    let own_pk = x25519_dalek::PublicKey::from(own_ephemeral_key);

    let mut secret_input = Vec::with_capacity(32 + 32 + 20 + 32 + 32 + 32 + PROTO_ID.len());
    secret_input.extend(xy.as_bytes());
    secret_input.extend(xb.as_bytes());
    secret_input.extend(server_identity_key.as_bytes());
    secret_input.extend(server_identity_key.as_bytes());
    secret_input.extend(own_pk.as_bytes());
    secret_input.extend(server_ephemeral_key.as_bytes());
    secret_input.extend(PROTO_ID.as_bytes());
    secret_input.extend(&server_id);

    let t_verify = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, format!("{}:key_verify", PROTO_ID).as_bytes());
    let verify = ring::hmac::sign(&t_verify, &secret_input);
    let mut auth_input = Vec::with_capacity(32 + 20 + 32 + 32 + 32 + PROTO_ID.len() + 6);
    auth_input.extend(verify.as_ref());
    auth_input.extend(server_identity_key.as_bytes());
    auth_input.extend(server_identity_key.as_bytes());
    auth_input.extend(own_pk.as_bytes());
    auth_input.extend(server_ephemeral_key.as_bytes());
    auth_input.extend(PROTO_ID.as_bytes());
    auth_input.extend(&server_id);
    auth_input.extend(b"Server");

    let t_mac = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, format!("{}:mac", PROTO_ID).as_bytes());
    let auth = ring::hmac::sign(&t_mac, &auth_input);
    let auth: [u8; 32] = auth.as_ref().try_into().unwrap();

    let t_extract = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, format!("{}:key_extract", PROTO_ID).as_bytes());
    let extract = ring::hmac::sign(&t_extract, &secret_input);
    let hk = hkdf::Hkdf::<sha2::Sha256>::new(Some(format!("{}:key_extract", PROTO_ID).as_bytes()), extract.as_ref());
    let mut k = vec![0u8; key_length];
    hk.expand(format!("{}:key_expand", PROTO_ID).as_bytes(), &mut k).unwrap();

    (auth, k)
}

// mod test {
//     use base64::Engine;
//     use super::*;
//
//     #[tokio::test]
//     async fn test_obfs4() {
//         let cert = base64::prelude::BASE64_STANDARD.decode("Y1a0KDjLWy+W10eh7ej7Z5vS+IiTRgOgtyZx9A4gICR7639V7xlsKcJsGqksUqqxNnN7EQ==").unwrap();
//
//         let stream = tokio::net::TcpStream::connect("[::1]:9002").await.unwrap();
//         let server = Obfs4Server {
//             node_id: cert[0..20].try_into().unwrap(),
//             public_key: cert[20..52].try_into().unwrap(),
//         };
//         let mut obfs_stream = Obfs4Stream::open(stream, &server).await.unwrap();
//
//         let len = obfs_stream.inner.read_u16().await.unwrap();
//         let len = obfs_stream.keys.mask_length(len, Direction::ServerToClient);
//         let mut data = vec![0u8; len as usize];
//         obfs_stream.inner.read_exact(&mut data).await.unwrap();
//     }
// }
