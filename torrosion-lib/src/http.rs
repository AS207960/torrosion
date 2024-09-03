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
            circ.relay_begin_dir(None).await
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