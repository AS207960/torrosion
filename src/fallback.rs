use std::str::FromStr;

static FALLBACK_DIRS: &'static str = include_str!("../fallback_dirs.inc");

#[derive(Debug)]
pub struct FallbackDirs {
    pub fallbacks: Vec<FallbackDir>,
}

#[derive(Debug)]
pub struct FallbackDir {
    pub id: super::RsaIdentity,
    pub v4: std::net::SocketAddrV4,
    pub v6: Option<std::net::SocketAddrV6>,
}

enum FallbackDirParseState {
    Dir(FallbackDir),
    Between,
}

impl FallbackDirs {
    pub fn new() -> FallbackDirs {
        let first_line_re = regex::Regex::new(r"/\* +type=(.+) +\*/*").unwrap();
        let second_line_re = regex::Regex::new(r"/\* +version=(.+) +\*/*").unwrap();
        let dir_start_re = regex::Regex::new(r#""(.+) +orport=(\d+) +id=(.+)" *"#).unwrap();
        let dir_end_re = regex::Regex::new(r", *").unwrap();
        let dir_ipv6_re = regex::Regex::new(r#"" +ipv6=\[(.+)\]:(\d+)" *"#).unwrap();
        let ver_req = semver::VersionReq::parse("4.0.0").unwrap();

        let mut lines = FALLBACK_DIRS.lines();

        let first_line = lines.next().expect("fallback-dirs.txt is empty");
        let first_line_caps = first_line_re.captures(first_line)
            .expect("fallback-dirs.txt is not a fallback list");
        if first_line_caps.get(1).expect("fallback-dirs.txt is not a fallback list").as_str() != "fallback" {
            panic!("fallback-dirs.txt is not a fallback list");
        }

        let second_line = lines.next().expect("missing version line in fallback-dirs.txt");
        let second_line_caps = second_line_re.captures(second_line)
            .expect("fallback-dirs.txt is not a fallback list");
        let version = semver::Version::parse(
            second_line_caps.get(1)
                .expect("fallback-dirs.txt is not a fallback list").as_str()
        ).expect("fallback list version not semver");
        if !ver_req.matches(&version) {
            panic!("fallback list has an incompatible version");
        }

        let mut out = vec![];
        let mut state = FallbackDirParseState::Between;

        while let Some(line) = lines.next() {
            match &mut state {
                FallbackDirParseState::Between => {
                    if let Some(caps) = dir_start_re.captures(line) {
                        state = FallbackDirParseState::Dir(FallbackDir {
                            id: super::RsaIdentity::new(caps.get(3).unwrap().as_str()),
                            v4: std::net::SocketAddrV4::new(
                                std::net::Ipv4Addr::from_str(caps.get(1).unwrap().as_str()).expect("cannot parse IP"),
                                caps.get(2).unwrap().as_str().parse().expect("cannot parse port"),
                            ),
                            v6: None,
                        });
                    }
                }
                FallbackDirParseState::Dir(d) => {
                    if let Some(caps) = dir_ipv6_re.captures(line) {
                        d.v6 = Some(std::net::SocketAddrV6::new(
                            std::net::Ipv6Addr::from_str(caps.get(1).unwrap().as_str()).expect("cannot parse IP"),
                            caps.get(2).unwrap().as_str().parse().expect("cannot parse port"),
                            0, 0,
                        ));
                    } else if dir_end_re.is_match(line) {
                        let d = std::mem::replace(&mut state, FallbackDirParseState::Between);
                        if let FallbackDirParseState::Dir(d) = d {
                            out.push(d);
                        }
                    }
                }
            }
        }

        FallbackDirs {
            fallbacks: out,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fallback_dirs() {
        let fallback_dirs = FallbackDirs::new();
        assert_ne!(fallback_dirs.fallbacks.len(), 0);
    }
}