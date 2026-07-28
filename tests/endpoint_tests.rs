use lanternroute::endpoint::SocksEndpoint;

#[test]
fn parses_ipv4_socks_endpoint() {
    let endpoint: SocksEndpoint = "127.0.0.1:10808".parse().expect("valid endpoint");

    assert_eq!(endpoint.host, "127.0.0.1");
    assert_eq!(endpoint.port, 10808);
    assert_eq!(endpoint.to_string(), "127.0.0.1:10808");
}

#[test]
fn parses_localhost_socks_endpoint() {
    let endpoint: SocksEndpoint = "localhost:10808".parse().expect("valid endpoint");

    assert_eq!(endpoint.host, "localhost");
    assert_eq!(endpoint.port, 10808);
}

#[test]
fn rejects_bad_socks_endpoints() {
    for value in ["127.0.0.1", ":10808", "127.0.0.1:0", "127.0.0.1:70000"] {
        assert!(
            value.parse::<SocksEndpoint>().is_err(),
            "{value} should fail"
        );
    }
}
