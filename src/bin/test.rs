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
    let hs_address = libtor::hs::HSAddress::from_uri(&hs_uri).unwrap();

    let dirs = libtor::hs::get_hs_dirs(&client).await.unwrap();

    let ds = hs_address.fetch_ds(&client, &dirs).await.unwrap();
    println!("{:?}", ds);
}