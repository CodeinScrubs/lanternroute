use proxybridge_rs::gui_support::{
    GuiOptions, build_cli_args, build_path_args, cli_exe_for_gui_exe, load_profile, profile_path,
    runtime_home_for_gui_exe, save_profile,
};
use std::path::Path;

#[test]
fn start_args_include_proxy_and_selected_flags() {
    let args = build_cli_args(
        "run",
        &GuiOptions {
            socks: "127.0.0.1:10808".into(),
            dns_via_proxy: true,
            allow_quic: false,
            no_reconnect_apps: true,
            allow_tcp_only: true,
            proxy_local_networks: false,
            bypass_processes: vec![],
            bypass_ips: vec![],
            bypass_domains: vec![],
            bypass_ports: vec![],
            rules: vec![],
            log_level: "info".into(),
            smoke_iterations: 10,
        },
    );

    assert_eq!(
        args,
        vec![
            "run",
            "--socks",
            "127.0.0.1:10808",
            "--log-level",
            "info",
            "--dns-via-proxy",
            "--no-reconnect-apps",
            "--allow-tcp-only"
        ]
    );
}

#[test]
fn default_gui_args_use_tcp_only_stable_mode() {
    let args = build_cli_args("run", &GuiOptions::default());

    assert!(args.contains(&"--allow-tcp-only".to_string()));
    assert!(!args.contains(&"--allow-quic".to_string()));
}

#[test]
fn gui_forwards_explicit_local_network_capture_policy() {
    let args = build_cli_args(
        "run",
        &GuiOptions {
            proxy_local_networks: true,
            ..GuiOptions::default()
        },
    );

    assert!(args.contains(&"--proxy-local-networks".to_string()));
}

#[test]
fn tcp_only_omits_conflicting_quic_flag() {
    let args = build_cli_args(
        "run",
        &GuiOptions {
            allow_quic: true,
            allow_tcp_only: true,
            ..GuiOptions::default()
        },
    );

    assert!(args.contains(&"--allow-tcp-only".to_string()));
    assert!(!args.contains(&"--allow-quic".to_string()));
}

#[test]
fn doctor_args_validate_the_gui_selected_tcp_only_mode() {
    let args = build_cli_args("doctor", &GuiOptions::default());

    assert!(args.contains(&"--allow-tcp-only".to_string()));
}

#[test]
fn gui_bypass_values_are_forwarded_as_repeatable_cli_options() {
    let args = build_cli_args(
        "run",
        &GuiOptions {
            bypass_processes: vec!["game.exe".into(), "helper.exe".into()],
            bypass_ips: vec!["192.0.2.0/24".into()],
            ..GuiOptions::default()
        },
    );

    assert!(
        args.windows(2)
            .any(|pair| pair == ["--bypass-process", "game.exe"])
    );
    assert!(
        args.windows(2)
            .any(|pair| pair == ["--bypass-process", "helper.exe"])
    );
    assert!(
        args.windows(2)
            .any(|pair| pair == ["--bypass-ip", "192.0.2.0/24"])
    );
}

#[test]
fn gui_domain_and_port_values_are_forwarded_as_repeatable_cli_options() {
    let args = build_cli_args(
        "run",
        &GuiOptions {
            bypass_domains: vec!["example.com".into(), ".internal.example".into()],
            bypass_ports: vec!["443".into(), "8000:8100".into()],
            ..GuiOptions::default()
        },
    );

    assert!(
        args.windows(2)
            .any(|pair| pair == ["--bypass-domain", "example.com"])
    );
    assert!(
        args.windows(2)
            .any(|pair| pair == ["--bypass-domain", ".internal.example"])
    );
    assert!(args.windows(2).any(|pair| pair == ["--bypass-port", "443"]));
    assert!(
        args.windows(2)
            .any(|pair| pair == ["--bypass-port", "8000:8100"])
    );
}

#[test]
fn gui_rules_are_forwarded_in_order() {
    let args = build_cli_args(
        "run",
        &GuiOptions {
            rules: vec![
                "block domain=ads.example.com".into(),
                "direct process=game.exe".into(),
            ],
            ..GuiOptions::default()
        },
    );
    let first = args.iter().position(|value| value == "--rule").unwrap();
    assert_eq!(args[first + 1], "block domain=ads.example.com");
    assert_eq!(args[first + 2], "--rule");
    assert_eq!(args[first + 3], "direct process=game.exe");
}

#[test]
fn smoke_test_args_include_iteration_count() {
    let args = build_cli_args(
        "smoke-test",
        &GuiOptions {
            smoke_iterations: 0,
            ..GuiOptions::default()
        },
    );

    assert!(args.ends_with(&["--smoke-iterations".into(), "1".into()]));
}

#[test]
fn stop_args_do_not_require_proxy_options() {
    assert_eq!(build_path_args("stop"), vec!["stop"]);
}

#[test]
fn gui_finds_cli_binary_next_to_itself() {
    let cli = cli_exe_for_gui_exe(Path::new(
        r"C:\Users\TestUser\Desktop\Work\15_proxybridge\target\release\proxybridge-gui.exe",
    ));

    assert_eq!(
        cli,
        Path::new(
            r"C:\Users\TestUser\Desktop\Work\15_proxybridge\target\release\proxybridge-rs.exe"
        )
    );
}

#[test]
fn release_build_uses_project_runtime_home() {
    let runtime = runtime_home_for_gui_exe(Path::new(
        r"C:\Users\TestUser\Desktop\Work\15_proxybridge\target\release\proxybridge-gui.exe",
    ));

    assert_eq!(
        runtime,
        Path::new(r"C:\Users\TestUser\Desktop\Work\15_proxybridge\.runtime")
    );
}

#[test]
fn packaged_gui_uses_user_data_runtime_home() {
    let installed = Path::new(r"C:\Program Files\ProxyBridgeRS\proxybridge-gui.exe");
    let runtime = runtime_home_for_gui_exe(installed);

    if let Some(local_app_data) = std::env::var_os("LOCALAPPDATA") {
        assert_eq!(runtime, Path::new(&local_app_data).join("ProxyBridgeRS"));
    } else {
        assert_eq!(runtime, installed.parent().unwrap().join(".runtime"));
    }
}

#[test]
fn gui_profile_round_trips_and_uses_the_runtime_home() {
    let root = std::env::temp_dir().join(format!(
        "proxybridge-rs-gui-profile-test-{}",
        std::process::id()
    ));
    let options = GuiOptions {
        socks: "127.0.0.1:10809".into(),
        bypass_processes: vec!["example.exe".into()],
        bypass_ips: vec!["192.168.10.0/24".into()],
        bypass_domains: vec!["example.com".into()],
        bypass_ports: vec!["443".into()],
        rules: vec!["block network=udp".into()],
        ..GuiOptions::default()
    };
    save_profile(&root, &options).expect("save profile");
    assert_eq!(profile_path(&root), root.join("gui-settings.json"));
    assert_eq!(load_profile(&root), options);
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn incomplete_legacy_gui_profile_falls_back_to_defaults_per_field() {
    let root = std::env::temp_dir().join(format!(
        "proxybridge-rs-gui-legacy-profile-test-{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&root).expect("create profile directory");
    std::fs::write(
        profile_path(&root),
        r#"{"socks":"127.0.0.1:10809","allow_tcp_only":false}"#,
    )
    .expect("write legacy profile");

    let loaded = load_profile(&root);
    assert_eq!(loaded.socks, "127.0.0.1:10809");
    assert!(!loaded.allow_tcp_only);
    assert_eq!(loaded.smoke_iterations, 10);
    assert!(loaded.bypass_processes.is_empty());
    let _ = std::fs::remove_dir_all(root);
}
