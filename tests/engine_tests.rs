use proxybridge_rs::engine::{
    RunningEngine, format_running_engine_conflict, process_path_is_owned_engine,
    process_paths_match,
};
use proxybridge_rs::engine::{
    SING_BOX_EXE_SHA256, SING_BOX_SHA256, SING_BOX_VERSION, validate_sing_box_archive_hash,
    validate_sing_box_exe_hash, validate_sing_box_version_line,
};
use proxybridge_rs::engine::{
    WINTUN_DLL_SHA256, WINTUN_SHA256, build_taskkill_args, format_stop_summary, sha256_hex,
    tun_start_failure_hint, validate_wintun_archive_hash, validate_wintun_dll_hash,
    wintun_archive_entry_is_amd64_dll,
};
use std::path::Path;
use std::path::PathBuf;

#[test]
fn process_path_matching_is_case_insensitive_and_separator_tolerant() {
    assert!(process_paths_match(
        r"C:\Users\TestUser\AppData\Local\ProxyBridgeRS\engine\sing-box.exe",
        r"c:/users/testuser/appdata/local/proxybridgers/engine/SING-BOX.EXE"
    ));
}

#[test]
fn process_path_matching_accepts_extended_length_windows_prefix() {
    assert!(process_paths_match(
        r"C:\ProxyBridgeRS\engine\sing-box-1.13.14\sing-box.exe",
        r"\\?\C:\ProxyBridgeRS\engine\sing-box-1.13.14\sing-box.exe"
    ));
}

#[test]
fn process_path_matching_rejects_other_engine_locations() {
    assert!(!process_paths_match(
        r"C:\Users\TestUser\AppData\Local\ProxyBridgeRS\engine\sing-box.exe",
        r"C:\Tools\sing-box\sing-box.exe"
    ));
}

#[test]
fn owned_engine_detection_accepts_old_version_under_same_engine_root() {
    assert!(process_path_is_owned_engine(
        r"C:\ProxyBridgeRS\engine\sing-box-1.13.14\sing-box.exe",
        r"C:\ProxyBridgeRS\engine\sing-box-1.13.11\sing-box.exe"
    ));
}

#[test]
fn owned_engine_detection_rejects_unrelated_sing_box_installation() {
    assert!(!process_path_is_owned_engine(
        r"C:\ProxyBridgeRS\engine\sing-box-1.13.14\sing-box.exe",
        r"C:\Tools\sing-box-1.13.11\sing-box.exe"
    ));
}

#[test]
fn duplicate_engine_message_is_actionable() {
    let message = format_running_engine_conflict(&[RunningEngine {
        pid: 1234,
        exe_path: PathBuf::from(r"C:\ProxyBridgeRS\sing-box.exe"),
    }]);

    assert!(message.contains("already running"));
    assert!(message.contains("1234"));
    assert!(message.contains(r"C:\ProxyBridgeRS\sing-box.exe"));
}

#[test]
fn taskkill_args_target_pid_tree_and_force() {
    assert_eq!(build_taskkill_args(4321), vec!["/PID", "4321", "/T", "/F"]);
}

#[test]
fn stop_summary_reports_no_owned_engines() {
    let message = format_stop_summary(&[], &[]);

    assert!(message.contains("No owned sing-box engine"));
}

#[test]
fn stop_summary_reports_stopped_pids() {
    let message = format_stop_summary(
        &[RunningEngine {
            pid: 4321,
            exe_path: PathBuf::from(r"C:\ProxyBridgeRS\sing-box.exe"),
        }],
        &[4321],
    );

    assert!(message.contains("Stopped"));
    assert!(message.contains("4321"));
}

#[test]
fn pinned_sing_box_version_line_is_accepted() {
    validate_sing_box_version_line(&format!("sing-box version {SING_BOX_VERSION}")).unwrap();
}

#[test]
fn mismatched_sing_box_version_line_is_rejected_with_actionable_context() {
    let error = validate_sing_box_version_line("sing-box version 1.13.11").unwrap_err();
    let message = error.to_string();

    assert!(message.contains(SING_BOX_VERSION));
    assert!(message.contains("1.13.11"));
}

#[test]
fn wintun_archive_selector_accepts_only_amd64_dll_entry() {
    assert!(wintun_archive_entry_is_amd64_dll(Path::new(
        "wintun/bin/amd64/wintun.dll"
    )));
    assert!(!wintun_archive_entry_is_amd64_dll(Path::new(
        "wintun/bin/arm64/wintun.dll"
    )));
    assert!(!wintun_archive_entry_is_amd64_dll(Path::new(
        "wintun/wintun.dll"
    )));
}

#[test]
fn sha256_hex_uses_lowercase_hex() {
    assert_eq!(
        sha256_hex(b"abc"),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
}

#[test]
fn wintun_archive_hash_rejects_unexpected_bytes() {
    let error = validate_wintun_archive_hash(b"not the official zip").unwrap_err();
    let message = error.to_string();

    assert!(message.contains(WINTUN_SHA256));
    assert!(message.contains("Wintun archive SHA256 mismatch"));
}

#[test]
fn sing_box_archive_hash_rejects_unexpected_bytes() {
    let error = validate_sing_box_archive_hash(b"not the official zip").unwrap_err();
    let message = error.to_string();

    assert!(message.contains(SING_BOX_SHA256));
    assert!(message.contains("sing-box archive SHA256 mismatch"));
}

#[test]
fn sing_box_executable_hash_rejects_unexpected_file() {
    let path = std::env::temp_dir().join(format!(
        "proxybridge-rs-engine-hash-test-{}.exe",
        std::process::id()
    ));
    std::fs::write(&path, b"not the official executable").unwrap();
    let error = validate_sing_box_exe_hash(&path).unwrap_err();
    let _ = std::fs::remove_file(&path);
    let message = error.to_string();

    assert!(message.contains(SING_BOX_EXE_SHA256));
    assert!(message.contains("sing-box executable SHA256 mismatch"));
}

#[test]
fn wintun_dll_hash_rejects_unexpected_file() {
    let path = std::env::temp_dir().join(format!(
        "proxybridge-rs-wintun-hash-test-{}.dll",
        std::process::id()
    ));
    std::fs::write(&path, b"not the official Wintun DLL").unwrap();
    let error = validate_wintun_dll_hash(&path).unwrap_err();
    let _ = std::fs::remove_file(&path);
    let message = error.to_string();

    assert!(message.contains(WINTUN_DLL_SHA256));
    assert!(message.contains("Wintun DLL SHA256 mismatch"));
}

#[test]
fn tun_start_failure_hint_explains_missing_tun_dependency() {
    let stderr = "FATAL start service: start inbound/tun[tun-in]: configure tun interface: The system cannot find the file specified.";
    let hint = tun_start_failure_hint(stderr, Path::new(r"C:\ProxyBridgeRS\engine\wintun.dll"))
        .expect("hint");

    assert!(hint.contains("TUN interface creation failed"));
    assert!(hint.contains("wintun.dll"));
    assert!(hint.contains(r"C:\ProxyBridgeRS\engine\wintun.dll"));
}

#[test]
fn tun_start_failure_hint_ignores_unrelated_engine_errors() {
    assert!(tun_start_failure_hint("proxy connection refused", Path::new("wintun.dll")).is_none());
}
