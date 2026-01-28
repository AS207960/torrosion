use futures::FutureExt;
use http_body_util::BodyExt;

#[derive(Clone)]
pub(crate) struct HyperDirectoryConnector {
    circuit: crate::circuit::Circuit,
}

impl tower::Service<hyper::Uri> for HyperDirectoryConnector {
    type Response = crate::stream::Stream;
    type Error = std::io::Error;
    type Future = futures::future::BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, _cx: &mut std::task::Context<'_>) -> std::task::Poll<Result<(), Self::Error>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn call(&mut self, _req: hyper::Uri) -> Self::Future {
        let circ = self.circuit.clone();
        async move {
            circ.relay_begin_dir_inner(None).await
        }.boxed()
    }
}

#[derive(Clone)]
pub struct HyperConnector {
    circuit: crate::circuit::Circuit,
}

pub trait HttpStream: hyper_util::client::legacy::connect::Connection + hyper::rt::Read + hyper::rt::Write + Send {}
impl HttpStream for crate::stream::Stream {}

struct TlsStream(async_native_tls::TlsStream<crate::stream::Stream>);

impl hyper::rt::Read for TlsStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        mut buf: hyper::rt::ReadBufCursor
    ) -> std::task::Poll<std::io::Result<()>> {
        let mut b = tokio::io::ReadBuf::uninit(unsafe { buf.as_mut() });
        match tokio::io::AsyncRead::poll_read(std::pin::Pin::new(&mut self.0), cx, &mut b) {
            std::task::Poll::Ready(Ok(())) => {
                let l = b.filled().len();
                drop(b);
                unsafe { buf.advance(l) };
                std::task::Poll::Ready(Ok(()))
            },
            std::task::Poll::Ready(Err(e)) => std::task::Poll::Ready(Err(e)),
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    }
}

impl hyper::rt::Write for TlsStream {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8]
    ) -> std::task::Poll<std::io::Result<usize>> {
        tokio::io::AsyncWrite::poll_write(std::pin::Pin::new(&mut self.0), cx, buf)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>
    ) -> std::task::Poll<std::io::Result<()>> {
        tokio::io::AsyncWrite::poll_flush(std::pin::Pin::new(&mut self.0), cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>
    ) -> std::task::Poll<std::io::Result<()>> {
        tokio::io::AsyncWrite::poll_shutdown(std::pin::Pin::new(&mut self.0), cx)
    }
}

impl hyper_util::client::legacy::connect::Connection for TlsStream {
    fn connected(&self) -> hyper_util::client::legacy::connect::Connected {
        hyper_util::client::legacy::connect::Connected::new()
            .proxy(false)
    }
}
impl HttpStream for TlsStream {}

impl hyper_util::client::legacy::connect::Connection for std::pin::Pin<Box<dyn HttpStream>> {
    fn connected(&self) -> hyper_util::client::legacy::connect::Connected {
        use std::ops::Deref;
        self.deref().connected()
    }
}

impl tower::Service<hyper::Uri> for HyperConnector {
    type Response = std::pin::Pin<Box<dyn HttpStream>>;
    type Error = std::io::Error;
    type Future = futures::future::BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, _cx: &mut std::task::Context<'_>) -> std::task::Poll<Result<(), Self::Error>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: hyper::Uri) -> Self::Future {
        let circuit = self.circuit.clone();
        async move {
            let scheme = match req.scheme() {
                Some(s) => s,
                None => return Err(std::io::Error::new(std::io::ErrorKind::Other, "no scheme")),
            };
            let (default_port, is_tls) = match scheme.as_str() {
                "http" => (80, false),
                "https" => (443, true),
                _ => return Err(std::io::Error::new(std::io::ErrorKind::Other, "invalid scheme")),
            };
            let authority = match req.authority() {
                Some(a) => a,
                None => return Err(std::io::Error::new(std::io::ErrorKind::Other, "no authority")),
            };
            let port = authority.port_u16().unwrap_or(default_port);

            let con_to = format!("{}:{}", authority.host(), port);
            debug!("Connecting to {}", con_to);
            let stream = circuit.relay_begin_inner(&con_to, None).await?;
            let res: std::pin::Pin<Box<dyn HttpStream>> = if is_tls {
                let tls_stream = match async_native_tls::TlsConnector::new()
                    .use_sni(true)
                    .connect(authority.host(), stream).await {
                    Ok(s) => s,
                    Err(e) => return Err(std::io::Error::new(std::io::ErrorKind::Other, format!("TLS error: {}", e))),
                };
                Box::pin(TlsStream(tls_stream))
            } else {
                Box::pin(stream)
            };
            Ok(res)
        }.boxed()
    }
}

struct HyperBodyImplStream(http_body_util::BodyDataStream<hyper::body::Incoming>);

impl futures::Stream for HyperBodyImplStream {
    type Item = std::io::Result<hyper::body::Bytes>;

    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>
    ) -> std::task::Poll<Option<Self::Item>> {
        std::pin::Pin::new(&mut self.0).poll_next(cx).map(|opt| {
            opt.map(|res| {
                res.map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))
            })
        })
    }
}

#[derive(Debug)]
pub struct HyperResponse(hyper::Response<hyper::body::Incoming>);

impl std::ops::Deref for HyperResponse {
    type Target = hyper::Response<hyper::body::Incoming>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl HyperResponse {
    pub fn new(resp: hyper::Response<hyper::body::Incoming>) -> HyperResponse {
        HyperResponse(resp)
    }

    pub fn read(self) -> std::io::Result<Box<dyn tokio::io::AsyncRead + Unpin + Send>> {
        let content_encoding = match self.0.headers().get("Content-Encoding") {
            Some(h) => match h.to_str() {
                Ok(s) => Some(s.to_string()),
                Err(_) => return Err(std::io::Error::new(
                    std::io::ErrorKind::Other, "Invalid Content-Encoding header"
                ))
            }
            None => None,
        };

        let body = tokio_util::io::StreamReader::new(
            HyperBodyImplStream(self.0.into_body().into_data_stream())
        );

        Ok(match content_encoding.as_deref() {
            None | Some("identity") => Box::new(body),
            Some("deflate") => {
                let mut decoder = async_compression::tokio::bufread::ZlibDecoder::new(body);
                decoder.multiple_members(true);
                Box::new(decoder)
            }
            Some("x-tor-lzma") => {
                let mut decoder = async_compression::tokio::bufread::XzDecoder::new(body);
                decoder.multiple_members(true);
                Box::new(decoder)
            }
            Some("x-zztd") => {
                let mut decoder = async_compression::tokio::bufread::ZstdDecoder::new(body);
                decoder.multiple_members(true);
                Box::new(decoder)
            },
            Some(other) => return Err(std::io::Error::new(
                std::io::ErrorKind::Other, format!("Unknown Content-Encoding: {}", other)
            )),
        })
    }
}

pub(crate) fn new_directory_client(circ: crate::circuit::Circuit) -> hyper_util::client::legacy::Client<
    HyperDirectoryConnector, http_body_util::Full<bytes::Bytes>> {
    hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new())
        .set_host(false)
        .build::<_, http_body_util::Full<bytes::Bytes>>(HyperDirectoryConnector {
            circuit: circ
        })
}

pub fn new_client(circ: crate::circuit::Circuit) -> hyper_util::client::legacy::Client<
    HyperConnector, http_body_util::Full<bytes::Bytes>> {
    hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new())
        .set_host(true)
        .build::<_, http_body_util::Full<bytes::Bytes>>(HyperConnector {
            circuit: circ
        })
}