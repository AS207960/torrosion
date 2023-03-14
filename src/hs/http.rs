use futures::FutureExt;

pub struct HyperHSConnector<S: crate::storage::Storage + Send + Sync + 'static> {
    client: crate::Client<S>,
}

impl<S: crate::storage::Storage + Send + Sync + 'static> Clone for HyperHSConnector<S> {
    fn clone(&self) -> Self {
        HyperHSConnector {
            client: self.client.clone(),
        }
    }
}

impl<S: crate::storage::Storage + Send + Sync + 'static> hyper::service::Service<hyper::Uri> for HyperHSConnector<S> {
    type Response = crate::stream::Stream;
    type Error = std::io::Error;
    type Future = futures::future::BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(
        &mut self,
        _cx: &mut std::task::Context<'_>
    ) -> std::task::Poll<Result<(), Self::Error>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: hyper::Uri) -> Self::Future {
        let client = self.client.clone();
        async move {
            let hs_address = super::HSAddress::from_uri(&req)?;

            let scheme = match req.scheme() {
                Some(s) => s,
                None => return Err(std::io::Error::new(std::io::ErrorKind::Other, "no scheme")),
            };
            let default_port = match scheme.as_str() {
                "http" => 80,
                "https" => 443,
                _ => return Err(std::io::Error::new(std::io::ErrorKind::Other, "invalid scheme")),
            };
            let authority = match req.authority() {
                Some(a) => a,
                None => return Err(std::io::Error::new(std::io::ErrorKind::Other, "no authority")),
            };
            let port = authority.port_u16().unwrap_or(default_port);

            let dirs = client.get_hs_relays().await?;
            let (ds, subcred) = hs_address.fetch_ds(&client, &dirs).await.unwrap();
            let hs_circ = super::con::connect(&client, &ds, &subcred).await.unwrap();

            let con_to = format!("{}:{}", authority.host(), port);
            hs_circ.relay_begin(&con_to, None).await
        }.boxed()
    }
}

pub fn new_hs_client<S: crate::storage::Storage + Send + Sync + 'static>(
    client: crate::Client<S>
) -> hyper::client::Client<HyperHSConnector<S>, hyper::Body> {
    hyper::client::Client::builder()
        .set_host(true)
        .build::<_, hyper::Body>(HyperHSConnector {
            client,
        })
}