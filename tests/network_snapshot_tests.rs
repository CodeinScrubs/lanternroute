use proxybridge_rs::network_snapshot::{
    CommandSnapshot, assert_capture_routes_present, assert_no_competing_capture_routes,
    capture_routes_present, format_snapshot_section, proxybridge_interface_present,
};

#[test]
fn formats_successful_snapshot_section_with_output() {
    let section = format_snapshot_section(&CommandSnapshot {
        title: "IPv4 route".into(),
        command: "route.exe print 0.0.0.0".into(),
        status: Some(0),
        stdout: "Interface List\r\nProxyBridgeRS".into(),
        stderr: String::new(),
    });

    assert!(section.contains("IPv4 route"));
    assert!(section.contains("status=0"));
    assert!(section.contains("ProxyBridgeRS"));
}

#[test]
fn formats_failed_snapshot_section_with_error_output() {
    let section = format_snapshot_section(&CommandSnapshot {
        title: "IPv6 route".into(),
        command: "route.exe print ::/0".into(),
        status: Some(1),
        stdout: String::new(),
        stderr: "not found".into(),
    });

    assert!(section.contains("IPv6 route"));
    assert!(section.contains("status=1"));
    assert!(section.contains("stderr:"));
    assert!(section.contains("not found"));
}

#[test]
fn capture_route_assertion_accepts_all_split_routes() {
    let snapshots = vec![CommandSnapshot {
        title: "ProxyBridgeRS split routes".into(),
        command: "powershell.exe Get-NetRoute".into(),
        status: Some(0),
        stdout: "DestinationPrefix\r\n0.0.0.0/1\r\n128.0.0.0/1\r\n::/1\r\n8000::/1\r\n".into(),
        stderr: String::new(),
    }];

    assert_capture_routes_present(&snapshots).expect("split routes");
}

#[test]
fn capture_route_assertion_rejects_missing_split_route() {
    let snapshots = vec![CommandSnapshot {
        title: "ProxyBridgeRS split routes".into(),
        command: "powershell.exe Get-NetRoute".into(),
        status: Some(0),
        stdout: "DestinationPrefix\r\n0.0.0.0/1\r\n128.0.0.0/1\r\n::/1\r\n".into(),
        stderr: String::new(),
    }];

    let error = assert_capture_routes_present(&snapshots).unwrap_err();

    assert!(error.to_string().contains("8000::1"));
}

#[test]
fn capture_route_assertion_accepts_windows_decomposed_routes() {
    let snapshots = vec![CommandSnapshot {
        title: "ProxyBridgeRS split routes".into(),
        command: "powershell.exe Get-NetRoute".into(),
        status: Some(0),
        stdout: "0.0.0.0/5\r\n8.0.0.0/7\r\n128.0.0.0/3\r\n192.0.0.0/9\r\n::/1\r\n8000::/2\r\n"
            .into(),
        stderr: String::new(),
    }];

    assert_capture_routes_present(&snapshots).expect("decomposed capture routes");
}

#[test]
fn capture_route_predicate_reports_readiness_without_error_detail() {
    let ready = vec![CommandSnapshot {
        title: "ProxyBridgeRS split routes".into(),
        command: "powershell.exe Get-NetRoute".into(),
        status: Some(0),
        stdout: "0.0.0.0/1\r\n128.0.0.0/1\r\n::/1\r\n8000::/1\r\n".into(),
        stderr: String::new(),
    }];
    let not_ready = vec![CommandSnapshot {
        title: "ProxyBridgeRS split routes".into(),
        command: "powershell.exe Get-NetRoute".into(),
        status: Some(1),
        stdout: String::new(),
        stderr: "not found".into(),
    }];

    assert!(capture_routes_present(&ready));
    assert!(!capture_routes_present(&not_ready));
}

#[test]
fn competing_public_route_is_rejected_with_interface_name() {
    let snapshots = vec![CommandSnapshot {
        title: "All route ownership".into(),
        command: "powershell.exe Get-NetRoute".into(),
        status: Some(0),
        stdout: "1.1.1.0/24|ExampleVPN|5\r\n0.0.0.0/0|Wi-Fi|25\r\n".into(),
        stderr: String::new(),
    }];

    let error = assert_no_competing_capture_routes(&snapshots).unwrap_err();
    let message = error.to_string();
    assert!(message.contains("1.1.1.0/24"));
    assert!(message.contains("ExampleVPN"));
}

#[test]
fn proxybridge_route_is_not_reported_as_competing() {
    let snapshots = vec![CommandSnapshot {
        title: "All route ownership".into(),
        command: "powershell.exe Get-NetRoute".into(),
        status: Some(0),
        stdout: "1.1.1.0/24|ProxyBridgeRS|5\r\n".into(),
        stderr: String::new(),
    }];

    assert_no_competing_capture_routes(&snapshots).expect("owned route");
}

#[test]
fn interface_presence_is_detected_only_from_the_interface_snapshot() {
    let snapshots = vec![CommandSnapshot {
        title: "Interfaces".into(),
        command: "netsh.exe interface show interface".into(),
        status: Some(0),
        stdout: "Enabled    Connected    Dedicated    ProxyBridgeRS\r\n".into(),
        stderr: String::new(),
    }];
    assert!(proxybridge_interface_present(&snapshots));
}
