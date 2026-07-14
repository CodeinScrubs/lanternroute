use proxybridge_rs::socks_probe::{
    SocksProbeResult, parse_socks5_method_response, parse_socks5_udp_associate_response,
    require_udp_for_all_app_coverage, validate_socks_for_mode,
};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

#[test]
fn parses_socks5_no_auth_method_response() {
    assert!(parse_socks5_method_response(&[0x05, 0x00]).is_ok());
    assert!(parse_socks5_method_response(&[0x05, 0xff]).is_err());
    assert!(parse_socks5_method_response(&[0x04, 0x00]).is_err());
}

#[test]
fn parses_ipv4_udp_associate_bind_address() {
    let response = [0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0x2a, 0x38];
    let actual = parse_socks5_udp_associate_response(&response).expect("udp associate");

    assert_eq!(
        actual,
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 10808)
    );
}

#[test]
fn udp_associate_error_decodes_socks_reply_code() {
    let response = [0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
    let error = parse_socks5_udp_associate_response(&response).unwrap_err();

    assert!(error.to_string().contains("command not supported"));
}

#[test]
fn probe_result_is_usable_only_when_socks5_handshake_succeeds() {
    let result = SocksProbeResult {
        tcp_port_open: true,
        socks5_no_auth: true,
        socks5_no_auth_error: None,
        tcp_connect: true,
        tcp_connect_error: None,
        udp_associate: false,
        udp_bind_addr: None,
        udp_associate_error: Some("connection refused".into()),
        udp_relay: false,
        udp_relay_error: Some("skipped".into()),
    };

    assert!(result.usable_for_tcp());
    assert!(!result.usable_for_udp());
}

#[test]
fn successful_socks5_handshake_and_connect_are_tcp_evidence() {
    let result = SocksProbeResult {
        tcp_port_open: false,
        socks5_no_auth: true,
        socks5_no_auth_error: None,
        tcp_connect: true,
        tcp_connect_error: None,
        udp_associate: false,
        udp_bind_addr: None,
        udp_associate_error: Some("connection refused".into()),
        udp_relay: false,
        udp_relay_error: Some("skipped".into()),
    };

    assert!(result.usable_for_tcp());
}

#[test]
fn all_app_coverage_requires_udp_associate() {
    let result = SocksProbeResult {
        tcp_port_open: true,
        socks5_no_auth: true,
        socks5_no_auth_error: None,
        tcp_connect: true,
        tcp_connect_error: None,
        udp_associate: false,
        udp_bind_addr: None,
        udp_associate_error: Some(
            "SOCKS5 UDP ASSOCIATE failed with reply 7 (command not supported)".into(),
        ),
        udp_relay: false,
        udp_relay_error: Some("skipped".into()),
    };

    let error = require_udp_for_all_app_coverage("127.0.0.1:10808", &result).unwrap_err();
    assert!(error.to_string().contains("required for all-app coverage"));
    assert!(error.to_string().contains("command not supported"));
}

#[test]
fn tcp_only_mode_allows_missing_udp_associate() {
    let result = SocksProbeResult {
        tcp_port_open: true,
        socks5_no_auth: true,
        socks5_no_auth_error: None,
        tcp_connect: true,
        tcp_connect_error: None,
        udp_associate: false,
        udp_bind_addr: None,
        udp_associate_error: Some(
            "SOCKS5 UDP ASSOCIATE failed with reply 7 (command not supported)".into(),
        ),
        udp_relay: false,
        udp_relay_error: Some("skipped".into()),
    };

    validate_socks_for_mode("127.0.0.1:10808", &result, true).expect("tcp-only mode");
}

#[test]
fn full_mode_rejects_missing_udp_associate() {
    let result = SocksProbeResult {
        tcp_port_open: true,
        socks5_no_auth: true,
        socks5_no_auth_error: None,
        tcp_connect: true,
        tcp_connect_error: None,
        udp_associate: false,
        udp_bind_addr: None,
        udp_associate_error: Some(
            "SOCKS5 UDP ASSOCIATE failed with reply 7 (command not supported)".into(),
        ),
        udp_relay: false,
        udp_relay_error: Some("skipped".into()),
    };

    let error = validate_socks_for_mode("127.0.0.1:10808", &result, false).unwrap_err();
    assert!(error.to_string().contains("required for all-app coverage"));
}

#[test]
fn full_mode_rejects_udp_associate_without_relay_proof() {
    let result = SocksProbeResult {
        tcp_port_open: true,
        socks5_no_auth: true,
        socks5_no_auth_error: None,
        tcp_connect: true,
        tcp_connect_error: None,
        udp_associate: true,
        udp_bind_addr: Some(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            10808,
        )),
        udp_associate_error: None,
        udp_relay: false,
        udp_relay_error: Some("timed out waiting for UDP relay response".into()),
    };

    let error = validate_socks_for_mode("127.0.0.1:10808", &result, false).unwrap_err();
    let message = error.to_string();

    assert!(message.contains("SOCKS5 UDP relay"));
    assert!(message.contains("timed out"));
}

#[test]
fn full_mode_accepts_udp_relay_proof() {
    let result = SocksProbeResult {
        tcp_port_open: true,
        socks5_no_auth: true,
        socks5_no_auth_error: None,
        tcp_connect: true,
        tcp_connect_error: None,
        udp_associate: true,
        udp_bind_addr: Some(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            10808,
        )),
        udp_associate_error: None,
        udp_relay: true,
        udp_relay_error: None,
    };

    validate_socks_for_mode("127.0.0.1:10808", &result, false).expect("full UDP mode");
}
