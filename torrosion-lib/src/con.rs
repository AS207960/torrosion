pub(crate) async fn connect_to_fallback(fallback: &crate::fallback::FallbackDir) -> Result<tokio::net::TcpStream, std::io::Error> {
    if let Some(v6) = fallback.v6 {
        debug!("Connecting to fallback {} on v6", fallback.id);
        match tokio::net::TcpStream::connect(v6).await {
            Ok(stream) => {
                debug!("TCP connection to fallback {} established", fallback.id);
                return Ok(stream)
            },
            Err(e) => warn!("Failed to connect to fallback {} on v6: {}", fallback.id, e),
        }
    }
    debug!("Connecting to fallback {} on v4", fallback.id);
    match tokio::net::TcpStream::connect(fallback.v4).await {
        Ok(stream) => {
            debug!("TCP connection to fallback {} established", fallback.id);
            return Ok(stream)
        },
        Err(e) => {
            warn!("Failed to connect to fallback {} on v4: {}", fallback.id, e);
            Err(e)
        },
    }
}

pub(crate) async fn connect_to_router(router: &crate::net_status::consensus::Router) -> Result<tokio::net::TcpStream, std::io::Error> {
    for a in &router.addresses {
        debug!("Connecting to router {} ({})", router.name, router.identity);
        match tokio::net::TcpStream::connect(a).await {
            Ok(stream) => {
                debug!("TCP connection to router {} established", router.name);
                return Ok(stream)
            },
            Err(e) => warn!("Failed to connect to router {}: {}", router.name, e),
        }
    }
    Err(std::io::Error::new(std::io::ErrorKind::ConnectionRefused, "No addresses available"))
}

pub struct Connection {
    con: crate::connection::Connection,
    first_hop_descriptor: crate::net_status::descriptor::Descriptor
}

impl Connection {
    pub async fn create_connection<S: crate::storage::Storage + Send + Sync + 'static>(
        router: &crate::net_status::consensus::Router, client: &crate::Client<S>
    ) -> Result<Self, std::io::Error> {
        let first_router_descriptor = match tokio::time::timeout(
            crate::DEFAULT_TIMEOUT,
            crate::net_status::descriptor::get_server_descriptor(router, client)
        ).await {
            Ok(Ok(d)) => d,
            Ok(Err(e)) => return Err(e),
            Err(_) => return Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "Timed out getting server descriptor"))
        };

        let tcp_stream = match tokio::time::timeout(
            crate::DEFAULT_TIMEOUT,
            connect_to_router(&router)
        ).await {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => return Err(e),
            Err(_) => return Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "Timed out connecting to router"))
        };

        match tokio::time::timeout(
            crate::DEFAULT_TIMEOUT,
            crate::connection::Connection::connect(
                tcp_stream, first_router_descriptor.identity
            )
        ).await {
            Ok(Ok(c)) => Ok(Self { con: c, first_hop_descriptor: first_router_descriptor }),
            Ok(Err(e)) => Err(e),
            Err(_) => Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "Timed out connecting to router"))
        }
    }

    pub async fn new_circuit(&self) -> Result<crate::circuit::Circuit, std::io::Error> {
        match tokio::time::timeout(
            crate::DEFAULT_TIMEOUT, self.con.create_circuit(self.first_hop_descriptor.ntor_onion_key)
        ).await {
            Ok(Ok(c)) => Ok(c),
            Ok(Err(e)) => Err(e),
            Err(_) => Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "Timed out creating circuit"))
        }
    }
}