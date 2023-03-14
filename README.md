# A Tor library for Rust

## Example usage

```rust
#[tokio::main]
async fn main() {
    pretty_env_logger::init();

    let storage = libtor::storage::FileStorage::new("./storage").await.unwrap();
    let mut client = libtor::Client::new(storage);

    client.run().await;

    while !client.ready().await {
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }
    
    let hs_uri = hyper::Uri::from_static("https://www.bbcweb3hytmzhn5d532owbu6oqadra5z3ar726vq5kgwwn6aucdccrad.onion");
    let hs_client = libtor::hs::http::new_hs_client(client).await.unwrap();
    
    hs_client.get(hs_uri).await.unwrap();
}
```

## Acknowledgements

With thanks to the [Open Technology Fund](https://www.opentech.fund/) for funding the work going into this library.

![Open Technology Fund Logo](https://acmeforonions.org/otf-logo.svg)