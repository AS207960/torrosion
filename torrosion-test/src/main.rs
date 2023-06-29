static PRIV_KEY: [u8; 32] = [0x70, 0x0c, 0x8b, 0x01, 0x0f, 0xc4, 0x84, 0x72, 0x5c, 0xe6, 0x61, 0xd4, 0xb0, 0xa7, 0xc3, 0x1f, 0xb1, 0x85, 0xd1, 0xa2, 0x34, 0x5b, 0xd4, 0xb2, 0xa0, 0x39, 0x5a, 0x05, 0x56, 0x07, 0x84, 0x5c];

#[tokio::main]
async fn main() {
    pretty_env_logger::init();

    let storage = torrosion::storage::FileStorage::new("./storage").await.unwrap();
    let mut client = torrosion::Client::new(storage);

    client.run().await;

    while !client.ready().await {
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }

    let a = torrosion::hs::HSAddress::from_str("*.5anebu2glyc235wbbop3m2ukzlaptpkq333vdtdvcjpigyb7x2i2m2qd.onion").unwrap();
    println!("{:?}", a);

    let (
        descriptor, first_layer, blinded_key, hs_subcred
    ) = a.fetch_ds_first_layer(&client).await.unwrap();
    println!("{:?}", first_layer);

    let second_layer = torrosion::hs::HSAddress::get_ds_second_layer(
        descriptor, first_layer, None, &blinded_key, &hs_subcred
    ).await.unwrap();
    println!("{:?}", second_layer.caa);

    // let hs_uri = hyper::Uri::from_static("http://znkiu4wogurrktkqqid2efdg4nvztm7d2jydqenrzeclfgv3byevnbid.onion/test.txt");
    //
    // let hs_addr = torrosion::hs::HSAddress::from_uri(&hs_uri).unwrap();
    //
    // let (descriptor, first_layer, blinded_key, hs_subcred) =
    //     hs_addr.fetch_ds_first_layer(&client).await.unwrap();
    //
    // println!("{:?}", first_layer.caa_critical);
    //
    // let second_layer = torrosion::hs::HSAddress::get_ds_second_layer(
    //     descriptor, first_layer, None, &blinded_key, &hs_subcred
    // ).await.unwrap();
    //
    // println!("{:?}", second_layer.caa);

    // let hs_client = torrosion::hs::http::new_hs_client(client, PRIV_KEY);
    //
    // let res = hs_client.get(hs_uri).await.unwrap();
    // println!("{:?}", res);
    //
    // let body = hyper::body::to_bytes(res.into_body()).await.unwrap();
    // println!("{}", String::from_utf8_lossy(&body));
}