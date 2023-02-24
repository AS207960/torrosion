use chrono::prelude::*;
use base64::prelude::*;
use super::{get_exactly_once, get_at_most_once, get_all};

#[derive(Debug, Clone)]
pub struct Consensus {
    pub(crate) valid_after: DateTime<Utc>,
    pub(crate) fresh_until: DateTime<Utc>,
    pub(crate) valid_until: DateTime<Utc>,
    pub(crate) voting_delay: VotingDelay,
    pub(crate) client_versions: Vec<String>,
    pub(crate) server_versions: Vec<String>,
    pub(crate) packages: Vec<Package>,
    pub(crate) known_flags: Vec<String>,
    pub(crate) recommended_client_protocols: Option<Entries>,
    pub(crate) recommended_relay_protocols: Option<Entries>,
    pub(crate) required_client_protocols: Option<Entries>,
    pub(crate) required_relay_protocols: Option<Entries>,
    pub(crate) parameters: std::collections::HashMap<String, i32>,
    pub(crate) previous_shared_random_value: Option<SharedRandomValue>,
    pub(crate) current_shared_random_value: Option<SharedRandomValue>,
    pub(crate) authorities: Vec<Authority>,
    pub(crate) routers: Vec<Router>,
    pub(crate) signatures: Vec<Signature>,
    pub(crate) digest: ring::digest::Digest,
}

impl Consensus {
    pub(crate) async fn parse<R: tokio::io::AsyncRead + Unpin + Send>(reader: &mut R) -> std::io::Result<Self> {
        let mut lines = super::LineReader::new(reader).iter(&ring::digest::SHA1_FOR_LEGACY_USE_ONLY);

        let nsv = NetworkStatusVersion::parse(&mut lines).await?;
        if nsv.0 != 3 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput, "Unsupported network status version"
            ));
        }

        let mut preamble = vec![];
        while let Some(p) = Preamble::parse(&mut lines).await? {
            preamble.push(p);
        }

        let mut authorities = vec![];
        while let Some(a) = Authority::parse(&mut lines).await? {
            authorities.push(a);
        }

        let mut routers = vec![];
        while let Some(r) = Router::parse(&mut lines).await? {
            routers.push(r);
        }

        let line = match lines.next().await {
            Some(l) => l?,
            None => return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput, "Invalid consensus"
            )),
        };
        if line.trim() != "directory-footer" {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput, "Invalid consensus"
            ));
        }

        while let Some(r) = std::pin::Pin::new(&mut lines).next_if(|l| match l {
            Ok(l) => !l.starts_with("directory-signature"),
            Err(_) => true
        }).await {
            r?;
        }

        lines.stop_digesting();
        lines.digests[0].0.update(b"directory-signature ");

        let mut signatures = vec![];
        while let Some(s) = Signature::parse(&mut lines).await? {
            signatures.push(s);
        }

        let vote_status = get_exactly_once!(preamble, Preamble::VoteStatus);
        if vote_status != VoteStatus::Consensus {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput, "Not a consensus"
            ));
        }

        let valid_after = get_exactly_once!(preamble, Preamble::ValidAfter);
        let fresh_until = get_exactly_once!(preamble, Preamble::FreshUntil);
        let valid_until = get_exactly_once!(preamble, Preamble::ValidUntil);
        let voting_delay = get_exactly_once!(preamble, Preamble::VotingDelay);
        let client_versions = get_exactly_once!(preamble, Preamble::ClientVersions);
        let server_versions = get_exactly_once!(preamble, Preamble::ServerVersions);
        let packages = get_all!(preamble, Preamble::Package);
        let known_flags = get_exactly_once!(preamble, Preamble::KnownFlags);
        let recommended_client_protocols = get_at_most_once!(preamble, Preamble::RecommendedClientProtocols);
        let recommended_relay_protocols = get_at_most_once!(preamble, Preamble::RecommendedRelayProtocols);
        let required_client_protocols = get_at_most_once!(preamble, Preamble::RequiredClientProtocols);
        let required_relay_protocols = get_at_most_once!(preamble, Preamble::RequiredRelayProtocols);
        let parameters = get_at_most_once!(preamble, Preamble::Parameters)
            .map(|p| p.0).unwrap_or_else(std::collections::HashMap::new);
        let previous_shared_random_value = get_at_most_once!(preamble, Preamble::SharedRandomPreviousValue);
        let current_shared_random_value = get_at_most_once!(preamble, Preamble::SharedRandomCurrentValue);

        Ok(Self {
            valid_after: valid_after.0,
            fresh_until: fresh_until.0,
            valid_until: valid_until.0,
            voting_delay,
            client_versions: client_versions.0,
            server_versions: server_versions.0,
            packages,
            known_flags: known_flags.0,
            recommended_client_protocols,
            recommended_relay_protocols,
            required_client_protocols,
            required_relay_protocols,
            parameters,
            previous_shared_random_value,
            current_shared_random_value,
            authorities,
            routers,
            signatures,
            digest: lines.digest()
        })
    }
}

struct NetworkStatusVersion(usize);

impl NetworkStatusVersion {
    async fn parse(reader: &mut super::LineReaderIter<'_>) -> std::io::Result<Self> {
        let line = match reader.next().await {
            Some(l) => l?,
            None => return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput, "Invalid network status version"
            )),
        };
        let mut parts = line.trim().split(" ");
        let def = parts.next().ok_or(std::io::Error::new(
            std::io::ErrorKind::InvalidInput, "Invalid network status version"
        ))?;
        if def != "network-status-version" {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput, "Invalid network status version"
            ));
        }
        let version = parts.next().ok_or(std::io::Error::new(
            std::io::ErrorKind::InvalidInput, "Invalid network status version"
        ))?;
        let version = version.parse::<usize>().map_err(|_| std::io::Error::new(
            std::io::ErrorKind::InvalidInput, "Invalid network status version"
        ))?;
        Ok(Self(version))
    }
}

#[derive(Debug)]
enum Preamble {
    VoteStatus(VoteStatus),
    ConsensusMethod(ConsensusMethod),
    ValidAfter(Timestamp),
    FreshUntil(Timestamp),
    ValidUntil(Timestamp),
    VotingDelay(VotingDelay),
    ClientVersions(VersionList),
    ServerVersions(VersionList),
    Package(Package),
    KnownFlags(Flags),
    RecommendedClientProtocols(Entries),
    RecommendedRelayProtocols(Entries),
    RequiredClientProtocols(Entries),
    RequiredRelayProtocols(Entries),
    Parameters(Parameters),
    SharedRandomPreviousValue(SharedRandomValue),
    SharedRandomCurrentValue(SharedRandomValue),
}

impl Preamble {
    async fn parse(reader: &mut super::LineReaderIter<'_>) -> std::io::Result<Option<Self>> {
        let mut r = std::pin::Pin::new(reader);
        loop {
            let line = match r.as_mut().next_if(|l| match l {
                Ok(l) => !l.starts_with("dir-source"),
                Err(_) => true
            }).await {
                Some(l) => l?,
                None => return Ok(None)
            };

            let mut parts = line.trim().split(" ");
            let def = parts.next().ok_or(std::io::Error::new(
                std::io::ErrorKind::InvalidInput, "Invalid consensus preamble"
            ))?;
            return match def {
                "vote-status" => Ok(Some(Self::VoteStatus(VoteStatus::parse(&mut parts)?))),
                "consensus-method" => Ok(Some(Self::ConsensusMethod(ConsensusMethod::parse(&mut parts)?))),
                "valid-after" => Ok(Some(Self::ValidAfter(Timestamp::parse(&mut parts)?))),
                "fresh-until" => Ok(Some(Self::FreshUntil(Timestamp::parse(&mut parts)?))),
                "valid-until" => Ok(Some(Self::ValidUntil(Timestamp::parse(&mut parts)?))),
                "voting-delay" => Ok(Some(Self::VotingDelay(VotingDelay::parse(&mut parts)?))),
                "client-versions" => Ok(Some(Self::ClientVersions(VersionList::parse(&mut parts)?))),
                "server-versions" => Ok(Some(Self::ServerVersions(VersionList::parse(&mut parts)?))),
                "package" => Ok(Some(Self::Package(Package::parse(&mut parts)?))),
                "known-flags" => Ok(Some(Self::KnownFlags(Flags::parse(&mut parts)?))),
                "recommended-client-protocols" => Ok(Some(Self::RecommendedClientProtocols(Entries::parse(&mut parts)?))),
                "recommended-relay-protocols" => Ok(Some(Self::RecommendedRelayProtocols(Entries::parse(&mut parts)?))),
                "required-client-protocols" => Ok(Some(Self::RequiredClientProtocols(Entries::parse(&mut parts)?))),
                "required-relay-protocols" => Ok(Some(Self::RequiredRelayProtocols(Entries::parse(&mut parts)?))),
                "params" => Ok(Some(Self::Parameters(Parameters::parse(&mut parts)?))),
                "shared-rand-previous-value" => Ok(Some(Self::SharedRandomPreviousValue(SharedRandomValue::parse(&mut parts)?))),
                "shared-rand-current-value" => Ok(Some(Self::SharedRandomCurrentValue(SharedRandomValue::parse(&mut parts)?))),
                _ => continue
            };
        }
    }
}

#[derive(Debug, Eq, PartialEq, Clone)]
enum VoteStatus {
    Consensus,
    Vote
}

impl VoteStatus {
    fn parse(line: &mut std::str::Split<&str>) -> std::io::Result<Self> {
        let status = line.next().ok_or(std::io::Error::new(
            std::io::ErrorKind::InvalidInput, "Invalid vote status"
        ))?;
        match status {
            "consensus" => Ok(Self::Consensus),
            "vote" => Ok(Self::Vote),
            _ => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput, "Invalid vote status"
            ))
        }
    }
}

#[derive(Debug)]
struct ConsensusMethod(usize);

impl ConsensusMethod {
    fn parse(line: &mut std::str::Split<&str>) -> std::io::Result<Self> {
        let method = line.next().ok_or(std::io::Error::new(
            std::io::ErrorKind::InvalidInput, "Invalid consensus method"
        ))?;
        let version = method.parse::<usize>().map_err(|_| std::io::Error::new(
            std::io::ErrorKind::InvalidInput, "Invalid consensus method"
        ))?;
        Ok(Self(version))
    }
}

#[derive(Debug)]
struct Timestamp(DateTime<Utc>);

impl Timestamp {
    fn parse(line: &mut std::str::Split<&str>) -> std::io::Result<Self> {
        let date = line.next().ok_or(std::io::Error::new(
            std::io::ErrorKind::InvalidInput, "Invalid timestamp"
        ))?;
        let time = line.next().ok_or(std::io::Error::new(
            std::io::ErrorKind::InvalidInput, "Invalid timestamp"
        ))?;
        let date = NaiveDate::parse_from_str(date, "%Y-%m-%d").map_err(|_| std::io::Error::new(
            std::io::ErrorKind::InvalidInput, "Invalid timestamp"
        ))?;
        let time = NaiveTime::parse_from_str(time, "%H:%M:%S").map_err(|_| std::io::Error::new(
            std::io::ErrorKind::InvalidInput, "Invalid timestamp"
        ))?;
        let datetime = DateTime::from_utc(date.and_time(time), Utc);
        Ok(Self(datetime))
    }
}

#[derive(Debug, Clone)]
pub(crate) struct VotingDelay {
    pub vote_seconds: usize,
    pub dist_seconds: usize,
}

impl VotingDelay {
    fn parse(line: &mut std::str::Split<&str>) -> std::io::Result<Self> {
        let vote_seconds = line.next().ok_or(std::io::Error::new(
            std::io::ErrorKind::InvalidInput, "Invalid voting delay"
        ))?;
        let dist_seconds = line.next().ok_or(std::io::Error::new(
            std::io::ErrorKind::InvalidInput, "Invalid voting delay"
        ))?;
        let vote_seconds = vote_seconds.parse::<usize>().map_err(|_| std::io::Error::new(
            std::io::ErrorKind::InvalidInput, "Invalid voting delay"
        ))?;
        let dist_seconds = dist_seconds.parse::<usize>().map_err(|_| std::io::Error::new(
            std::io::ErrorKind::InvalidInput, "Invalid voting delay"
        ))?;
        Ok(Self {
            vote_seconds,
            dist_seconds,
        })
    }
}

#[derive(Debug)]
struct VersionList(Vec<String>);

impl VersionList {
    fn parse(line: &mut std::str::Split<&str>) -> std::io::Result<Self> {
        let version_list = line.next().ok_or(std::io::Error::new(
            std::io::ErrorKind::InvalidInput, "Invalid version list"
        ))?;
        let versions = version_list.split(",").map(|s| s.to_string()).collect();
        Ok(Self(versions))
    }
}

#[derive(Debug, Clone)]
pub(crate) struct Package {
    pub name: String,
    pub version: String,
    pub url: String,
    pub digests: Vec<(String, String)>
}

impl Package {
    fn parse(line: &mut std::str::Split<&str>) -> std::io::Result<Self> {
        let name = line.next().ok_or(std::io::Error::new(
            std::io::ErrorKind::InvalidInput, "Invalid package"
        ))?;
        let version = line.next().ok_or(std::io::Error::new(
            std::io::ErrorKind::InvalidInput, "Invalid package"
        ))?;
        let url = line.next().ok_or(std::io::Error::new(
            std::io::ErrorKind::InvalidInput, "Invalid package"
        ))?;
        let mut digests = vec![];
        while let Some(digest) = line.next() {
            let digest = digest.split_once("=").ok_or(std::io::Error::new(
                std::io::ErrorKind::InvalidInput, "Invalid package"
            ))?;
            digests.push((digest.0.to_string(), digest.1.to_string()));
        }
        Ok(Self {
            name: name.to_string(),
            version: version.to_string(),
            url: url.to_string(),
            digests,
        })
    }
}

#[derive(Debug)]
struct Flags(Vec<String>);

impl Flags {
    fn parse(line: &mut std::str::Split<&str>) -> std::io::Result<Self> {
        let mut flags = vec![];
        while let Some(flag) = line.next() {
            flags.push(flag.to_string());
        }
        Ok(Self(flags))
    }
}

#[derive(Debug, Clone)]
pub(crate) struct Entries(std::collections::HashMap<String, Vec<std::ops::RangeInclusive<usize>>>);

impl Entries {
    pub(crate) fn supports(&self, entry: &str, version: usize) -> bool {
        self.0.get(entry).map_or(false, |ranges| {
            ranges.iter().any(|range| range.contains(&version))
        })
    }

    pub(super) fn parse(line: &mut std::str::Split<&str>) -> std::io::Result<Self> {
        let mut entries = std::collections::HashMap::new();
        while let Some(entry) = line.next() {
            let (key, values) = entry.split_once("=").ok_or(std::io::Error::new(
                std::io::ErrorKind::InvalidInput, "Invalid entry"
            ))?;
            let values = values.split(",");
            let values = values.map(|v| match v.split_once("-") {
                Some((start, end)) => {
                    let start = start.parse::<usize>().map_err(|_| std::io::Error::new(
                        std::io::ErrorKind::InvalidInput, "Invalid entry"
                    ))?;
                    let end = end.parse::<usize>().map_err(|_| std::io::Error::new(
                        std::io::ErrorKind::InvalidInput, "Invalid entry"
                    ))?;
                    Ok(start..=end)
                }
                None => {
                    let value = v.parse::<usize>().map_err(|_| std::io::Error::new(
                        std::io::ErrorKind::InvalidInput, "Invalid entry"
                    ))?;
                    Ok(value..=value)
                }
            }).collect::<Result<Vec<_>, std::io::Error>>()?;
            entries.insert(key.to_string(), values);
        }
        Ok(Self(entries))
    }
}

#[derive(Debug)]
struct Parameters(std::collections::HashMap<String, i32>);

impl Parameters {
    fn parse(line: &mut std::str::Split<&str>) -> std::io::Result<Self> {
        let mut parameters = std::collections::HashMap::new();
        while let Some(parameter) = line.next() {
            let (key, value) = parameter.split_once("=").ok_or(std::io::Error::new(
                std::io::ErrorKind::InvalidInput, "Invalid parameter"
            ))?;
            let value = value.parse::<i32>().map_err(|_| std::io::Error::new(
                std::io::ErrorKind::InvalidInput, "Invalid parameter"
            ))?;
            parameters.insert(key.to_string(), value);
        }
        Ok(Self(parameters))
    }
}

#[derive(Debug, Clone)]
pub(crate) struct SharedRandomValue {
    pub num_reveals: usize,
    pub value: Vec<u8>
}

impl SharedRandomValue {
    fn parse(line: &mut std::str::Split<&str>) -> std::io::Result<Self> {
        let num_reveals = line.next().ok_or(std::io::Error::new(
            std::io::ErrorKind::InvalidInput, "Invalid shared random value"
        ))?;
        let value = line.next().ok_or(std::io::Error::new(
            std::io::ErrorKind::InvalidInput, "Invalid shared random value"
        ))?;
        let num_reveals = num_reveals.parse::<usize>().map_err(|_| std::io::Error::new(
            std::io::ErrorKind::InvalidInput, "Invalid shared random value"
        ))?;
        let value = BASE64_STANDARD.decode(value).map_err(|_| std::io::Error::new(
            std::io::ErrorKind::InvalidInput, "Invalid shared random value"
        ))?;
        Ok(Self {
            num_reveals,
            value,
        })
    }
}

#[derive(Debug, Clone)]
pub(crate) struct Authority {
    pub name: String,
    pub identity: Vec<u8>,
    pub hostname: String,
    pub address: std::net::SocketAddr,
    pub dir_port: u16,
    pub contact: String,
    pub vote_digest: Vec<u8>
}

impl Authority {
    async fn parse<'a>(r: &mut super::LineReaderIter<'a>) -> std::io::Result<Option<Self>> {
        let line = match r.next_if(|l| match l {
            Ok(l) => !l.starts_with("r"),
            Err(_) => true
        }).await {
            Some(l) => l?,
            None => return Ok(None)
        };

        let mut parts = line.trim().split(" ");
        let def = parts.next().ok_or(std::io::Error::new(
            std::io::ErrorKind::InvalidInput, "Invalid authority"
        ))?;
        if def != "dir-source" {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput, "Invalid authority"
            ));
        }

        let name = parts.next().ok_or(std::io::Error::new(
            std::io::ErrorKind::InvalidInput, "Invalid authority"
        ))?;

        let identity = parts.next().ok_or(std::io::Error::new(
            std::io::ErrorKind::InvalidInput, "Invalid authority"
        ))?;
        let identity = hex::decode(identity).map_err(|_| std::io::Error::new(
            std::io::ErrorKind::InvalidInput, "Invalid authority"
        ))?;

        let address = parts.next().ok_or(std::io::Error::new(
            std::io::ErrorKind::InvalidInput, "Invalid authority"
        ))?;

        let ip = parts.next().ok_or(std::io::Error::new(
            std::io::ErrorKind::InvalidInput, "Invalid authority"
        ))?;
        let ip = ip.parse::<std::net::IpAddr>().map_err(|_| std::io::Error::new(
            std::io::ErrorKind::InvalidInput, "Invalid authority"
        ))?;

        let dir_port = parts.next().ok_or(std::io::Error::new(
            std::io::ErrorKind::InvalidInput, "Invalid authority"
        ))?;
        let dir_port = dir_port.parse::<u16>().map_err(|_| std::io::Error::new(
            std::io::ErrorKind::InvalidInput, "Invalid authority"
        ))?;

        let or_port = parts.next().ok_or(std::io::Error::new(
            std::io::ErrorKind::InvalidInput, "Invalid authority"
        ))?;
        let or_port = or_port.parse::<u16>().map_err(|_| std::io::Error::new(
            std::io::ErrorKind::InvalidInput, "Invalid authority"
        ))?;

        let mut contact = None;
        let mut vote_digest = None;

        while let Some(line) = r.next_if(|l| match l {
            Ok(l) => !(l.starts_with("dir-source") || l.starts_with("r")),
            Err(_) => true
        }).await {
            let l = line?;
            let mut parts = l.trim().split(" ");
            let def = parts.next().ok_or(std::io::Error::new(
                std::io::ErrorKind::InvalidInput, "Invalid authority"
            ))?;
            match def {
                "contact" => {
                    if contact.is_some() {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidInput, "Invalid authority"
                        ));
                    }
                    contact = Some(parts.collect::<Vec<_>>().join(" "));
                },
                "vote-digest" => {
                    let d = parts.next().ok_or(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput, "Invalid authority"
                    ))?;
                    let d = hex::decode(d).map_err(|_| std::io::Error::new(
                        std::io::ErrorKind::InvalidInput, "Invalid authority"
                    ))?;
                    if vote_digest.is_some() {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidInput, "Invalid authority"
                        ));
                    }
                    vote_digest = Some(d);
                },
                _ => return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput, "Invalid authority"
                )),
            }
        }

        Ok(Some(Self {
            name: name.to_string(),
            identity,
            hostname: address.to_string(),
            address: std::net::SocketAddr::new(ip, or_port),
            dir_port,
            contact: match contact {
                Some(c) => c.to_string(),
                None => return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput, "Invalid authority"
                )),
            },
            vote_digest: match vote_digest {
                Some(d) => d,
                None => return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput, "Invalid authority"
                )),
            }
        }))
    }
}

#[derive(Debug, Clone)]
pub(crate) struct Router {
    pub name: String,
    pub identity: crate::RsaIdentity,
    pub digest: Vec<u8>,
    pub addresses: Vec<std::net::SocketAddr>,
    pub dir_port: Option<u16>,
    pub status: Vec<String>,
    pub protocols: Option<Entries>,
    pub version: Option<RouterVersion>,
    pub port_policy: Option<RouterPortPolicy>,
    pub bandwidth: Option<RouterBandwidth>,
}

impl Router {
    async fn parse<'a>(reader: &mut super::LineReaderIter<'a>) -> std::io::Result<Option<Self>> {
        let mut r = std::pin::Pin::new(reader);
        let line = match r.as_mut().next_if(|l| match l {
            Ok(l) => !l.starts_with("directory-footer"),
            Err(_) => true
        }).await {
            Some(l) => l?,
            None => return Ok(None)
        };

        let mut parts = line.trim().split(" ");
        let def = parts.next().ok_or(std::io::Error::new(
            std::io::ErrorKind::InvalidInput, "Invalid router"
        ))?;
        if def != "r" {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput, "Invalid router"
            ));
        }

        let name = parts.next().ok_or(std::io::Error::new(
            std::io::ErrorKind::InvalidInput, "Invalid router"
        ))?.to_string();

        let identity = parts.next().ok_or(std::io::Error::new(
            std::io::ErrorKind::InvalidInput, "Invalid router"
        ))?;
        let identity = BASE64_STANDARD_NO_PAD.decode(identity).map_err(|_| std::io::Error::new(
            std::io::ErrorKind::InvalidInput, "Invalid router"
        ))?;
        let identity = crate::RsaIdentity::from_bytes(&identity).map_err(|_| std::io::Error::new(
            std::io::ErrorKind::InvalidInput, "Invalid router"
        ))?;

        let digest = parts.next().ok_or(std::io::Error::new(
            std::io::ErrorKind::InvalidInput, "Invalid router"
        ))?;
        let digest = BASE64_STANDARD_NO_PAD.decode(digest).map_err(|_| std::io::Error::new(
            std::io::ErrorKind::InvalidInput, "Invalid router"
        ))?;

        // Ignore publication date
        parts.next().ok_or(std::io::Error::new(
            std::io::ErrorKind::InvalidInput, "Invalid router"
        ))?;
        parts.next().ok_or(std::io::Error::new(
            std::io::ErrorKind::InvalidInput, "Invalid router"
        ))?;

        let ip = parts.next().ok_or(std::io::Error::new(
            std::io::ErrorKind::InvalidInput, "Invalid router"
        ))?;
        let ip = ip.parse::<std::net::IpAddr>().map_err(|_| std::io::Error::new(
            std::io::ErrorKind::InvalidInput, "Invalid router"
        ))?;

        let or_port = parts.next().ok_or(std::io::Error::new(
            std::io::ErrorKind::InvalidInput, "Invalid router"
        ))?;
        let or_port = or_port.parse::<u16>().map_err(|_| std::io::Error::new(
            std::io::ErrorKind::InvalidInput, "Invalid router"
        ))?;

        let dir_port = parts.next().ok_or(std::io::Error::new(
            std::io::ErrorKind::InvalidInput, "Invalid router"
        ))?;
        let dir_port = match dir_port {
            "0" => None,
            _ => Some(dir_port.parse::<u16>().map_err(|_| std::io::Error::new(
                std::io::ErrorKind::InvalidInput, "Invalid router"
            ))?),
        };

        let mut items = vec![];
        while let Some(i) = RouterItem::parse(&mut r.as_mut()).await? {
            items.push(i);
        }

        let status = get_at_most_once!(items, RouterItem::Status);
        let protocols = get_at_most_once!(items, RouterItem::Protocols);
        let version = get_at_most_once!(items, RouterItem::Version);
        let port_policy = get_at_most_once!(items, RouterItem::PortPolicy);
        let bandwidth = get_at_most_once!(items, RouterItem::Bandwidth);

        Ok(Some(Router {
            name,
            identity,
            digest,
            addresses: vec![std::net::SocketAddr::new(ip, or_port)],
            dir_port,
            status: status.map(|s| s.0).unwrap_or_default(),
            protocols,
            version,
            port_policy,
            bandwidth,
        }))
    }
}

#[derive(Debug)]
enum RouterItem {
    Address(RouterAddress),
    Status(RouterStatus),
    Flags(Flags),
    Version(RouterVersion),
    Protocols(Entries),
    Bandwidth(RouterBandwidth),
    PortPolicy(RouterPortPolicy),
}

impl RouterItem {
    async fn parse<'a>(reader: &mut super::LineReaderIter<'a>) -> std::io::Result<Option<Self>> {
        let mut r = std::pin::Pin::new(reader);
        loop {
            let line = match r.as_mut().next_if(|l| match l {
                Ok(l) => !(l.starts_with("r") || l.starts_with("directory-footer")),
                Err(_) => true
            }).await {
                Some(l) => l?,
                None => return Ok(None)
            };
            let mut parts = line.trim().split(" ");
            let def = parts.next().ok_or(std::io::Error::new(
                std::io::ErrorKind::InvalidInput, "Invalid router item"
            ))?;
            return match def {
                "a" => Ok(Some(Self::Address(RouterAddress::parse(&mut parts)?))),
                "s" => Ok(Some(Self::Status(RouterStatus::parse(&mut parts)?))),
                "f" => Ok(Some(Self::Flags(Flags::parse(&mut parts)?))),
                "v" => Ok(Some(Self::Version(RouterVersion::parse(&mut parts)?))),
                "pr" => Ok(Some(Self::Protocols(Entries::parse(&mut parts)?))),
                "w" => Ok(Some(Self::Bandwidth(RouterBandwidth::parse(&mut parts)?))),
                "p" => Ok(Some(Self::PortPolicy(RouterPortPolicy::parse(&mut parts)?))),
                _ => continue
            };
        }
    }
}

#[derive(Debug)]
struct RouterAddress(std::net::SocketAddr);

impl RouterAddress {
    fn parse(line: &mut std::str::Split<&str>) -> std::io::Result<Self> {
        let addr = line.next().ok_or(std::io::Error::new(
            std::io::ErrorKind::InvalidInput, "Invalid address"
        ))?;
        let addr = addr.parse::<std::net::SocketAddr>().map_err(|_| std::io::Error::new(
            std::io::ErrorKind::InvalidInput, "Invalid address"
        ))?;

        Ok(Self(addr))
    }
}

#[derive(Debug)]
struct RouterStatus(Vec<String>);

impl RouterStatus {
    fn parse(line: &mut std::str::Split<&str>) -> std::io::Result<Self> {
        let mut status = vec![];
        while let Some(s) = line.next() {
            status.push(s.to_string());
        }
        Ok(Self(status))
    }
}

#[derive(Debug, Clone)]
pub(crate) enum RouterVersion {
    Tor(String),
    Other(String),
}

impl RouterVersion {
    fn parse(line: &mut std::str::Split<&str>) -> std::io::Result<Self> {
        let version_type = line.next().ok_or(std::io::Error::new(
            std::io::ErrorKind::InvalidInput, "Invalid version"
        ))?;
        let version = line.next().ok_or(std::io::Error::new(
            std::io::ErrorKind::InvalidInput, "Invalid version"
        ))?;
        match version_type {
            "Tor" => Ok(Self::Tor(version.to_string())),
            _ => Ok(Self::Other(version.to_string())),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct RouterBandwidth {
    pub bandwidth: u64,
    pub unmeasured: bool,
}

impl RouterBandwidth {
    fn parse(line: &mut std::str::Split<&str>) -> std::io::Result<Self> {
        let mut bandwidth = None;
        let mut unmeasured = false;

        while let Some(l) = line.next() {
            let (k, v) = l.split_once("=").ok_or(std::io::Error::new(
                std::io::ErrorKind::InvalidInput, "Invalid bandwidth"
            ))?;
            match k {
                "Bandwidth" => bandwidth = Some(v.parse::<u64>().map_err(|_| std::io::Error::new(
                    std::io::ErrorKind::InvalidInput, "Invalid bandwidth"
                ))?),
                "Unmeasured" => unmeasured = true,
                _ => return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput, "Invalid bandwidth"
                ))
            }
        }

        Ok(Self {
            bandwidth: bandwidth.ok_or(std::io::Error::new(
                std::io::ErrorKind::InvalidInput, "Invalid bandwidth"
            ))?,
            unmeasured
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RouterPortPolicy {
    pub policy: RouterPortPolicyType,
    pub ports: Vec<std::ops::Range<u16>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RouterPortPolicyType {
    Accept,
    Reject,
}

impl RouterPortPolicy {
    pub(super) fn parse(line: &mut std::str::Split<&str>) -> std::io::Result<Self> {
        let policy = line.next().ok_or(std::io::Error::new(
            std::io::ErrorKind::InvalidInput, "Invalid port policy"
        ))?;
        let policy = match policy {
            "accept" => RouterPortPolicyType::Accept,
            "reject" => RouterPortPolicyType::Reject,
            _ => return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput, "Invalid port policy"
            ))
        };

        let values = line.next().ok_or(std::io::Error::new(
            std::io::ErrorKind::InvalidInput, "Invalid port policy"
        ))?;
        let values = values.split(",");
        let ports = values.map(|v| match v.split_once("-") {
            Some((start, end)) => {
                let start = start.parse::<u16>().map_err(|_| std::io::Error::new(
                    std::io::ErrorKind::InvalidInput, "Invalid entry"
                ))?;
                let end = end.parse::<u16>().map_err(|_| std::io::Error::new(
                    std::io::ErrorKind::InvalidInput, "Invalid entry"
                ))?;
                Ok(std::ops::Range { start, end })
            }
            None => {
                let value = v.parse::<u16>().map_err(|_| std::io::Error::new(
                    std::io::ErrorKind::InvalidInput, "Invalid entry"
                ))?;
                Ok(std::ops::Range { start: value, end: value + 1 })
            }
        }).collect::<Result<Vec<_>, std::io::Error>>()?;

        Ok(Self {
            policy,
            ports,
        })
    }
}

#[derive(Debug, Clone)]
pub(crate) struct Signature {
    pub algorithm: SignatureAlgorithm,
    pub identity: crate::RsaIdentity,
    pub signing_key_digest: Vec<u8>,
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) enum SignatureAlgorithm {
    Sha1,
    Sha256
}

impl Signature {
    async fn parse<'a >(reader: &mut super::LineReaderIter<'a>) -> std::io::Result<Option<Self>> {
        let line = match reader.next_if(|l| match l {
            Ok(l) => l.starts_with("directory-signature"),
            Err(_) => true
        }).await {
            Some(l) => l?,
            None => return Ok(None)
        };

        let mut parts = line.split(" ").collect::<Vec<_>>();
        if parts.remove(0) != "directory-signature" {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput, "Invalid signature"
            ));
        }

        if parts.len() < 2 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput, "Invalid signature"
            ));
        }
        let alg = if parts.len() == 2 {
            SignatureAlgorithm::Sha1
        } else {
            let a = match parts[0] {
                "sha1" => SignatureAlgorithm::Sha1,
                "sha256" => SignatureAlgorithm::Sha256,
                _ => return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput, "Invalid signature"
                ))
            };
            parts.remove(0);
            a
        };

        let identity = match crate::RsaIdentity::from_hex(&parts[0]) {
            Ok(i) => i,
            Err(_) => return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput, "Invalid signature"
            ))
        };
        let signing_key_digest = match hex::decode(parts[1]) {
            Ok(i) => i,
            Err(_) => return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput, "Invalid signature"
            ))
        };


        let signature = super::read_pem(reader).await.map_err(|_| std::io::Error::new(
            std::io::ErrorKind::InvalidInput, "Invalid signature"
        ))?;
        if signature.label != "SIGNATURE" {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput, "Invalid signature"
            ));
        }

        Ok(Some(Signature {
            algorithm: alg,
            identity,
            signing_key_digest,
            signature: signature.contents,
        }))
    }
}