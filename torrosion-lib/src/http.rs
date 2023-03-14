use futures::FutureExt;

#[derive(Clone)]
pub(crate) struct HyperDirectoryConnector {
    circuit: crate::circuit::Circuit,
}

impl hyper::service::Service<hyper::Uri> for HyperDirectoryConnector {
    type Response = crate::stream::Stream;
    type Error = std::io::Error;
    type Future = futures::future::BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(
        &mut self,
        _cx: &mut std::task::Context<'_>
    ) -> std::task::Poll<Result<(), Self::Error>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn call(&mut self, _req: hyper::Uri) -> Self::Future {
        let circ = self.circuit.clone();
        async move {
            circ.relay_begin_dir(None).await
        }.boxed()
    }
}

struct HyperBodyImplStream(hyper::Body);

impl futures::Stream for HyperBodyImplStream {
    type Item = std::io::Result<hyper::body::Bytes>;

    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>
    ) -> std::task::Poll<Option<Self::Item>> {
        use hyper::body::HttpBody;
        std::pin::Pin::new(&mut self.0).poll_data(cx).map(|opt| {
            opt.map(|res| res.map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e)))
        })
    }
}

#[derive(Debug)]
pub struct HyperResponse(hyper::Response<hyper::Body>);

impl std::ops::Deref for HyperResponse {
    type Target = hyper::Response<hyper::Body>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl HyperResponse {
    pub fn new(resp: hyper::Response<hyper::Body>) -> HyperResponse {
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

        let body = tokio_util::io::StreamReader::new(HyperBodyImplStream(self.0.into_body()));

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

pub(crate) fn new_directory_client(circ: crate::circuit::Circuit) -> hyper::client::Client<HyperDirectoryConnector, hyper::Body> {
    hyper::client::Client::builder()
        .set_host(false)
        .build::<_, hyper::Body>(HyperDirectoryConnector {
            circuit: circ
        })
}