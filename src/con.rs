pub(crate) async fn connect_to_fallback(fallback: &crate::fallback::FallbackDir) -> Result<tokio::net::TcpStream, std::io::Error> {
    if let Some(v6) = fallback.v6 {
        debug!("Connecting to fallback {} on v6", fallback.id);
        match tokio::net::TcpStream::connect(v6).await {
            Ok(stream) => {
                info!("TCP connection to fallback {} established", fallback.id);
                return Ok(stream)
            },
            Err(e) => warn!("Failed to connect to fallback {} on v6: {}", fallback.id, e),
        }
    }
    debug!("Connecting to fallback {} on v4", fallback.id);
    match tokio::net::TcpStream::connect(fallback.v4).await {
        Ok(stream) => {
            info!("TCP connection to fallback {} established", fallback.id);
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
                info!("TCP connection to router {} established", router.name);
                return Ok(stream)
            },
            Err(e) => warn!("Failed to connect to router {}: {}", router.name, e),
        }
    }
    return Err(std::io::Error::new(std::io::ErrorKind::HostUnreachable, "No addresses available"))
}