use proxybridge_rs::config::{RuntimeOptions, build_sing_box_config};
use proxybridge_rs::control_api::{
    ConnectionsSnapshot, ControlApiEndpoint, allocate_control_api, format_bytes,
    format_connections_report, generate_secret, load_control_api, process_display,
    save_control_api,
};

#[test]
fn generated_secrets_are_long_and_unique() {
    let first = generate_secret();
    let second = generate_secret();

    assert_eq!(first.len(), 32);
    assert!(first.chars().all(|character| character.is_ascii_hexdigit()));
    assert_ne!(first, second, "secrets must differ across sessions");
}

#[test]
fn allocated_endpoint_uses_a_nonzero_loopback_port() {
    let endpoint = allocate_control_api().expect("allocate");

    assert_ne!(endpoint.port, 0);
    assert_eq!(endpoint.secret.len(), 32);
}

#[test]
fn control_api_state_round_trips_through_disk() {
    let dir = std::env::temp_dir().join(format!(
        "proxybridge-rs-control-api-test-{}",
        std::process::id()
    ));
    let path = dir.join("control-api.json");
    let endpoint = ControlApiEndpoint {
        port: 45123,
        secret: "0123456789abcdef0123456789abcdef".to_string(),
    };

    save_control_api(&path, &endpoint).expect("save");
    let loaded = load_control_api(&path).expect("load");
    let _ = std::fs::remove_dir_all(&dir);

    assert_eq!(loaded, endpoint);
}

#[test]
fn missing_control_api_state_error_tells_user_to_start_a_tunnel() {
    let error = load_control_api(std::path::Path::new(
        r"C:\definitely\missing\control-api.json",
    ))
    .unwrap_err();

    assert!(format!("{error:#}").contains("start a tunnel"));
}

#[test]
fn control_api_is_included_in_config_only_when_enabled() {
    let disabled = build_sing_box_config(&RuntimeOptions::default());
    assert!(disabled.get("experimental").is_none());

    let enabled = build_sing_box_config(&RuntimeOptions {
        control_api: Some(ControlApiEndpoint {
            port: 45123,
            secret: "s3cret".to_string(),
        }),
        ..RuntimeOptions::default()
    });
    assert_eq!(
        enabled["experimental"]["clash_api"]["external_controller"],
        "127.0.0.1:45123"
    );
    assert_eq!(enabled["experimental"]["clash_api"]["secret"], "s3cret");
}

#[test]
fn connections_response_parses_and_formats_as_a_table() {
    let body = r#"{
        "downloadTotal": 1048576,
        "uploadTotal": 2048,
        "connections": [
            {
                "id": "abc",
                "metadata": {
                    "network": "tcp",
                    "type": "tun",
                    "sourceIP": "172.19.0.1",
                    "destinationIP": "93.184.216.34",
                    "sourcePort": "50000",
                    "destinationPort": "443",
                    "host": "example.com",
                    "processPath": "C:\\Program Files\\Browser\\browser.exe"
                },
                "upload": 512,
                "download": 4096,
                "start": "2026-07-17T00:00:00Z",
                "chains": ["proxy"],
                "rule": "final",
                "rulePayload": ""
            },
            {
                "id": "def",
                "metadata": {
                    "network": "tcp",
                    "destinationIP": "192.0.2.10",
                    "destinationPort": "8443",
                    "host": "",
                    "processPath": ""
                },
                "upload": 10,
                "download": 20,
                "chains": ["direct"],
                "rule": "ip_cidr",
                "rulePayload": "192.0.2.0/24"
            }
        ]
    }"#;

    let snapshot: ConnectionsSnapshot = serde_json::from_str(body).expect("parse");
    assert_eq!(snapshot.download_total, 1_048_576);
    assert_eq!(snapshot.upload_total, 2048);

    let report = format_connections_report(&snapshot);
    assert!(report.contains("Active connections: 2"));
    assert!(report.contains("1.0 MiB"));
    assert!(report.contains("browser.exe"));
    assert!(report.contains("example.com:443"));
    assert!(report.contains("192.0.2.10:8443"));
    assert!(report.contains("ip_cidr(192.0.2.0/24)"));
    assert!(report.contains("proxy"));
    assert!(report.contains("direct"));
}

#[test]
fn empty_connections_report_is_explicit() {
    let snapshot: ConnectionsSnapshot = serde_json::from_str("{}").expect("parse");
    let report = format_connections_report(&snapshot);

    assert!(report.contains("Active connections: 0"));
    assert!(report.contains("No active connections."));
}

#[test]
fn byte_formatting_uses_binary_units() {
    assert_eq!(format_bytes(0), "0 B");
    assert_eq!(format_bytes(1023), "1023 B");
    assert_eq!(format_bytes(1024), "1.0 KiB");
    assert_eq!(format_bytes(1536), "1.5 KiB");
    assert_eq!(format_bytes(1024 * 1024 * 3 / 2), "1.5 MiB");
}

#[test]
fn process_display_shows_file_name_or_placeholder() {
    assert_eq!(
        process_display(r"C:\Program Files\Browser\browser.exe"),
        "browser.exe"
    );
    assert_eq!(process_display(""), "-");
}
