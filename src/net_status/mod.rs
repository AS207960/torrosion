pub mod consensus;
pub mod dir_key_certificate;
pub mod descriptor;

use std::pin::Pin;
use tokio::io::AsyncBufReadExt;
use futures::StreamExt;
use rand::prelude::SliceRandom;

macro_rules! get_exactly_once {
    ($v:expr, $t:path) => {
        {
            let pos = match $v.iter().position(|p| matches!(p, $t(_))) {
                Some(p) => p,
                None => return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput, "Invalid consensus"
                )),
            };
            let s = $v.swap_remove(pos);
            if $v.iter().position(|p| matches!(p, $t(_))).is_some() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput, "Invalid consensus"
                ));
            }
            match s {
                $t(s) => s,
                _ => unreachable!(),
            }
        }
    }
}

macro_rules! get_at_most_once {
    ($v:expr, $t:path) => {
        {
            match $v.iter().position(|p| matches!(p, $t(_))) {
                Some(pos) => {
                    let s = $v.swap_remove(pos);
                    if $v.iter().position(|p| matches!(p, $t(_))).is_some() {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidInput, "Invalid consensus"
                        ));
                    }
                    match s {
                        $t(s) => Some(s),
                        _ => unreachable!(),
                    }
                },
                None => None,
            }
        }
    }
}

macro_rules! get_all {
    ($v:expr, $t:path) => {
        {
            let mut o = vec![];
            while let Some(pos) = $v.iter().position(|p| matches!(p, $t(_))) {
                let s = $v.swap_remove(pos);
                match s {
                    $t(s) => o.push(s),
                    _ => unreachable!(),
                }
            }
            o
        }
    }
}

pub(crate) use get_exactly_once;
pub(crate) use get_at_most_once;
pub(crate) use get_all;

pub(crate) struct LineReader<'a, R: tokio::io::AsyncRead + Unpin + Send> (
    tokio_stream::wrappers::SplitStream<tokio::io::BufReader<&'a mut R>>
);

impl<'a, R: tokio::io::AsyncRead + Unpin + Send> LineReader<'a, R> {
    pub(crate) fn new(reader: &'a mut R) -> Self {
        Self(tokio_stream::wrappers::SplitStream::new(tokio::io::BufReader::new(reader).split(b'\n')))
    }

    pub(crate) fn iter(self, digest_type: &'static ring::digest::Algorithm) -> LineReaderIter<'a> {
        LineReaderIter {
            iter: StreamExt::peekable(Box::new(self.0)),
            digests: vec![(ring::digest::Context::new(digest_type), true)],
            raw: Vec::new(),
            should_digest_raw: false,
        }
    }

    pub(crate) fn iter_digest_none(self) -> LineReaderIter<'a> {
        LineReaderIter {
            iter: StreamExt::peekable(Box::new(self.0)),
            digests: vec![],
            raw: Vec::new(),
            should_digest_raw: true,
        }
    }

    pub(crate) fn iter_many_digest(self, digest_types: &[&'static ring::digest::Algorithm]) -> LineReaderIter<'a> {
        LineReaderIter {
            iter: StreamExt::peekable(Box::new(self.0)),
            digests: digest_types.iter().map(|d| (ring::digest::Context::new(d), true)).collect(),
            raw: Vec::new(),
            should_digest_raw: false,
        }
    }
}

pub struct LineReaderIter<'a> {
    iter: futures::stream::Peekable<Box<dyn 'a + futures::stream::Stream<Item = Result<Vec<u8>, std::io::Error>> + Unpin + Send>>,
    digests: Vec<(ring::digest::Context, bool)>,
    raw: Vec<u8>,
    should_digest_raw: bool,
}

impl LineReaderIter<'_> {
    pub fn stop_digesting(&mut self) {
        for (_, should_digest) in &mut self.digests {
            *should_digest = false;
        }
        self.should_digest_raw = false;
    }
    pub fn stop_digesting_one(&mut self, i: usize) {
        self.digests[i].1 = false;
    }

    pub fn digest(&self) -> ring::digest::Digest {
        self.digests[0].0.clone().finish()
    }

    pub fn digest_i(&self, i: usize) -> ring::digest::Digest {
        self.digests[i].0.clone().finish()
    }

    pub fn digest_raw(&self) -> &[u8] {
        &self.raw
    }

    pub async fn next(&mut self) -> Option<Result<String, std::io::Error>> {
        let v = match self.iter.next().await? {
            Ok(v) => v,
            Err(e) => return Some(Err(e)),
        };
        for (digest, should_digest) in &mut self.digests {
            if *should_digest {
                digest.update(&v);
                digest.update(b"\n");
            }
        }
        if self.should_digest_raw {
            self.raw.extend_from_slice(&v);
            self.raw.push(b'\n');
        }
        let s = match String::from_utf8(v) {
            Ok(s) => s,
            Err(e) => return Some(Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput, format!("Invalid UTF-8: {}", e)
            ))),
        }.trim().to_string();
        Some(Ok(s))
    }

    pub async fn next_if(&mut self, cond: fn(&Result<String, std::io::Error>) -> bool) -> Option<Result<String, std::io::Error>> {
        let v = match Pin::new(&mut self.iter).next_if(|v| {
            let s = match v {
                Ok(v) => match String::from_utf8(v.clone()) {
                    Ok(s) => Ok(s.trim().to_string()),
                    Err(e) => Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput, format!("Invalid UTF-8: {}", e)
                    )),
                },
                Err(e) => Err(std::io::Error::new(
                    e.kind(), e.to_string()
                ))
            };
            cond(&s)
        }).await? {
            Ok(v) => v,
            Err(e) => return Some(Err(e)),
        };

        for (digest, should_digest) in &mut self.digests {
            if *should_digest {
                digest.update(&v);
                digest.update(b"\n");
            }
        }
        if self.should_digest_raw {
            self.raw.extend_from_slice(&v);
            self.raw.push(b'\n');
        }
        Some(Ok(String::from_utf8(v).unwrap().trim().to_string()))
    }
}

pub async fn read_pem(mut r: &mut LineReaderIter<'_>) -> Result<x509_parser::pem::Pem, x509_parser::error::PEMError> {
    let label = loop {
        let line = match r.next().await {
            Some(Ok(l)) => l,
            Some(Err(e)) => return Err(x509_parser::error::PEMError::IOError(e)),
            None => return Err(x509_parser::error::PEMError::MissingHeader),
        };
        if !line.starts_with("-----BEGIN ") {
            continue;
        }
        let mut iter = line.split_whitespace();
        let label = iter.nth(1).ok_or(x509_parser::error::PEMError::InvalidHeader)?;
        let label = label.split('-').next().ok_or(x509_parser::error::PEMError::InvalidHeader)?.to_string();
        break label;
    };
    let mut s = String::new();
    loop {
        let line = match r.next().await {
            Some(Ok(l)) => l,
            Some(Err(e)) => return Err(x509_parser::error::PEMError::IOError(e)),
            None => return Err(x509_parser::error::PEMError::IncompletePEM),
        };
        if line.starts_with("-----END ") {
            break;
        }
        s.push_str(line.trim_end());
    }

    let contents = base64::decode(&s).or(Err(x509_parser::error::PEMError::Base64DecodeError))?;
    let pem = x509_parser::pem::Pem {
        label,
        contents,
    };
    Ok(pem)
}

pub(crate) fn select_directory_server(consensus: &consensus::Consensus) -> Option<&consensus::Router> {
    let mut rng = rand::thread_rng();
    let mut servers = consensus.routers.iter().filter(|r| {
        r.status.iter().any(|f| f == "V2Dir")
    }).filter(|r| {
        r.status.iter().any(|f| f == "Running")
    }).filter(|r| {
        r.status.iter().any(|f| f == "Valid")
    }).collect::<Vec<_>>();
    servers.shuffle(&mut rng);
    servers.first().map(|r| *r)
}

pub(crate) fn select_node(consensus: &consensus::Consensus) -> Option<&consensus::Router> {
    let mut rng = rand::thread_rng();
    let mut servers = consensus.routers.iter().filter(|r| {
        r.status.iter().any(|f| f == "Running")
    }).filter(|r| {
        r.status.iter().any(|f| f == "Valid")
    }).collect::<Vec<_>>();
    servers.shuffle(&mut rng);
    servers.first().map(|r| *r)
}