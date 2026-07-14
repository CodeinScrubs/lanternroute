use proxybridge_rs::browser_reset::{
    BrowserResetCandidate, should_reset_connection, tcp_port_to_mib_dword,
};
use std::net::Ipv4Addr;

#[test]
fn resets_established_browser_connections_to_public_ips() {
    let candidate = BrowserResetCandidate {
        process_name: "chrome.exe".into(),
        remote_addr: Ipv4Addr::new(8, 8, 8, 8),
        remote_port: 443,
        state: 5,
    };

    assert!(should_reset_connection(&candidate));
}

#[test]
fn keeps_proxy_engine_and_local_connections() {
    let xray = BrowserResetCandidate {
        process_name: "xray.exe".into(),
        remote_addr: Ipv4Addr::new(8, 8, 8, 8),
        remote_port: 443,
        state: 5,
    };
    let local = BrowserResetCandidate {
        process_name: "chrome.exe".into(),
        remote_addr: Ipv4Addr::new(127, 0, 0, 1),
        remote_port: 10808,
        state: 5,
    };

    assert!(!should_reset_connection(&xray));
    assert!(!should_reset_connection(&local));
}

#[test]
fn mib_tcp_port_uses_network_byte_order_in_low_word() {
    assert_eq!(tcp_port_to_mib_dword(443), 0xbb01);
    assert_eq!(tcp_port_to_mib_dword(10808), 0x382a);
}
