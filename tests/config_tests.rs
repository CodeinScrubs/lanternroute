use lanternroute::config::{DnsMode, RuntimeOptions, build_sing_box_config};
use lanternroute::endpoint::SocksEndpoint;
use lanternroute::rules::parse_rule_lines;
use serde_json::Value;

fn default_options() -> RuntimeOptions {
    RuntimeOptions {
        socks: "127.0.0.1:10808".parse::<SocksEndpoint>().unwrap(),
        ..RuntimeOptions::default()
    }
}

#[test]
fn default_config_is_tun_first_and_routes_to_socks() {
    let config = build_sing_box_config(&default_options());

    assert_eq!(config["inbounds"][0]["type"], "tun");
    assert_eq!(config["inbounds"][0]["interface_name"], "LanternRoute");
    assert_eq!(config["inbounds"][0]["auto_route"], true);
    assert_eq!(config["inbounds"][0]["strict_route"], true);
    assert_eq!(config["inbounds"][0]["stack"], "mixed");
    assert_eq!(config["log"]["level"], "warn");
    assert_eq!(config["route"]["final"], "proxy");
    assert_eq!(config["route"]["default_domain_resolver"], "local");

    let addresses = config["inbounds"][0]["address"].as_array().unwrap();
    assert!(addresses.contains(&Value::String("172.19.0.1/30".into())));
    assert!(addresses.contains(&Value::String("fdfe:dcba:9876::1/126".into())));

    let route_addresses = config["inbounds"][0]["route_address"].as_array().unwrap();
    for required in ["0.0.0.0/1", "128.0.0.0/1", "::/1", "8000::/1"] {
        assert!(
            route_addresses.contains(&Value::String(required.into())),
            "missing full-capture route {required}"
        );
    }

    let excluded_routes = config["inbounds"][0]["route_exclude_address"]
        .as_array()
        .unwrap();
    for required in ["192.168.0.0/16", "fc00::/7", "fe80::/10"] {
        assert!(
            excluded_routes.contains(&Value::String(required.into())),
            "missing local-network exclusion {required}"
        );
    }

    let proxy = config["outbounds"]
        .as_array()
        .unwrap()
        .iter()
        .find(|outbound| outbound["tag"] == "proxy")
        .expect("proxy outbound");
    assert_eq!(proxy["type"], "socks");
    assert_eq!(proxy["server"], "127.0.0.1");
    assert_eq!(proxy["server_port"], 10808);

    let dns_index = config["route"]["rules"]
        .as_array()
        .unwrap()
        .iter()
        .position(|rule| rule["action"] == "hijack-dns")
        .expect("DNS hijack rule");
    let loopback_index = config["route"]["rules"]
        .as_array()
        .unwrap()
        .iter()
        .position(|rule| {
            rule["ip_cidr"] == serde_json::json!(["127.0.0.0/8", "::1/128", "::ffff:127.0.0.0/104"])
        })
        .expect("loopback rule");
    assert!(dns_index < loopback_index);
}

#[test]
fn default_config_bypasses_local_proxy_engine_processes() {
    let config = build_sing_box_config(&default_options());
    let rules = config["route"]["rules"].as_array().unwrap();

    let process_rule = rules
        .iter()
        .find(|rule| rule["process_name"].is_array())
        .expect("process bypass rule");

    let names: Vec<&str> = process_rule["process_name"]
        .as_array()
        .unwrap()
        .iter()
        .map(|name| name.as_str().unwrap())
        .collect();

    for required in [
        "v2rayN.exe",
        "v2ray.exe",
        "xray.exe",
        "sing-box.exe",
        "mihomo.exe",
        "clash-verge.exe",
        "nekoray.exe",
        "shadowsocks-windows.exe",
        "lanternroute.exe",
    ] {
        assert!(
            names.contains(&required),
            "missing engine bypass process {required}"
        );
    }
    assert_eq!(process_rule["action"], "route");
    assert_eq!(process_rule["outbound"], "direct");

    let cidr_rule = rules
        .iter()
        .find(|rule| rule["ip_cidr"].is_array())
        .expect("cidr bypass rule");
    let cidrs: Vec<&str> = cidr_rule["ip_cidr"]
        .as_array()
        .unwrap()
        .iter()
        .map(|cidr| cidr.as_str().unwrap())
        .collect();
    assert_eq!(
        cidrs,
        vec!["127.0.0.0/8", "::1/128", "::ffff:127.0.0.0/104"]
    );
}

#[test]
fn default_config_hijacks_dns_locally_and_blocks_quic() {
    let config = build_sing_box_config(&default_options());

    assert_eq!(config["dns"]["final"], "local");
    assert_eq!(config["dns"]["strategy"], "prefer_ipv4");

    let rules = config["route"]["rules"].as_array().unwrap();
    assert!(
        rules
            .iter()
            .any(|rule| { rule["port"] == 53 && rule["action"] == "hijack-dns" })
    );
    assert!(rules.iter().any(|rule| {
        rule["network"] == "udp"
            && rule["port"] == 443
            && rule["action"] == "reject"
            && rule["method"] == "default"
    }));
}

#[test]
fn remote_dns_mode_is_explicit_and_tightens_tun_routes() {
    let config = build_sing_box_config(&RuntimeOptions {
        dns_mode: DnsMode::RemoteViaProxy,
        ..default_options()
    });

    assert_eq!(config["dns"]["final"], "remote");
    assert_eq!(config["inbounds"][0]["strict_route"], true);

    let remote = config["dns"]["servers"]
        .as_array()
        .unwrap()
        .iter()
        .find(|server| server["tag"] == "remote")
        .expect("remote DNS server");
    assert_eq!(remote["type"], "https");
    assert_eq!(remote["server"], "1.1.1.1");
    assert_eq!(remote["path"], "/dns-query");
    assert_eq!(remote["tls"]["server_name"], "cloudflare-dns.com");
    assert_eq!(remote["detour"], "proxy");

    let proxy = config["outbounds"]
        .as_array()
        .unwrap()
        .iter()
        .find(|outbound| outbound["tag"] == "proxy")
        .expect("proxy outbound");
    assert_eq!(proxy["domain_resolver"], "local");
}

#[test]
fn proxy_local_networks_removes_private_network_exclusions_but_keeps_link_local_guards() {
    let config = build_sing_box_config(&RuntimeOptions {
        proxy_local_networks: true,
        ..default_options()
    });
    let excluded = config["inbounds"][0]["route_exclude_address"]
        .as_array()
        .unwrap();

    for private in [
        "10.0.0.0/8",
        "100.64.0.0/10",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "fc00::/7",
    ] {
        assert!(!excluded.contains(&Value::String(private.into())));
    }
    for required in ["169.254.0.0/16", "224.0.0.0/4", "fe80::/10", "ff00::/8"] {
        assert!(excluded.contains(&Value::String(required.into())));
    }
}

#[test]
fn tcp_only_mode_rejects_remaining_udp_after_dns_handling() {
    let config = build_sing_box_config(&RuntimeOptions {
        tcp_only: true,
        ..default_options()
    });

    let rules = config["route"]["rules"].as_array().unwrap();
    let dns_index = rules
        .iter()
        .position(|rule| rule["port"] == 53 && rule["action"] == "hijack-dns")
        .expect("dns hijack rule");
    let udp_reject_index = rules
        .iter()
        .position(|rule| {
            rule["network"] == "udp" && rule["action"] == "reject" && rule["method"] == "default"
        })
        .expect("tcp-only udp reject rule");

    assert!(udp_reject_index > dns_index);
    assert_eq!(config["inbounds"][0]["stack"], "system");
}

#[test]
fn custom_log_level_is_reflected_in_generated_config() {
    let config = build_sing_box_config(&RuntimeOptions {
        log_level: "debug".into(),
        ..default_options()
    });

    assert_eq!(config["log"]["level"], "debug");
}

#[test]
fn custom_bypass_processes_and_cidrs_are_direct_rules() {
    let config = build_sing_box_config(&RuntimeOptions {
        custom_direct_process_names: vec!["game.exe".into()],
        direct_ip_cidrs: vec!["192.0.2.0/24".into()],
        ..default_options()
    });
    let rules = config["route"]["rules"].as_array().unwrap();

    let processes = rules
        .iter()
        .find(|rule| rule["process_name"] == serde_json::json!(["game.exe"]))
        .expect("process bypass rule");
    assert_eq!(processes["process_name"], serde_json::json!(["game.exe"]));

    let cidrs = rules
        .iter()
        .find(|rule| {
            rule["ip_cidr"]
                .as_array()
                .is_some_and(|values| values.contains(&serde_json::json!("192.0.2.0/24")))
        })
        .expect("cidr bypass rule");
    assert!(
        cidrs["ip_cidr"]
            .as_array()
            .unwrap()
            .contains(&serde_json::json!("192.0.2.0/24"))
    );
}

#[test]
fn custom_domains_and_ports_are_direct_rules() {
    let config = build_sing_box_config(&RuntimeOptions {
        direct_domains: vec!["example.com".into()],
        direct_domain_suffixes: vec![".internal.example".into()],
        direct_ports: vec![443],
        direct_port_ranges: vec!["8000:8100".into()],
        ..default_options()
    });
    let rules = config["route"]["rules"].as_array().unwrap();

    let domain_rule = rules
        .iter()
        .find(|rule| rule["domain"].is_array())
        .expect("domain bypass rule");
    assert_eq!(domain_rule["domain"], serde_json::json!(["example.com"]));
    assert_eq!(
        domain_rule["domain_suffix"],
        serde_json::json!([".internal.example"])
    );

    let port_rule = rules
        .iter()
        .find(|rule| rule["port"].is_array())
        .expect("port bypass rule");
    assert_eq!(port_rule["port"], serde_json::json!([443]));
    assert_eq!(port_rule["port_range"], serde_json::json!(["8000:8100"]));
}

#[test]
fn dns_hijack_precedes_custom_direct_port_exception() {
    let config = build_sing_box_config(&RuntimeOptions {
        direct_ports: vec![53],
        ..default_options()
    });
    let rules = config["route"]["rules"].as_array().unwrap();
    let direct_index = rules
        .iter()
        .position(|rule| rule["action"] == "route" && rule["port"] == serde_json::json!([53]))
        .expect("direct port rule");
    let dns_index = rules
        .iter()
        .position(|rule| rule["action"] == "hijack-dns")
        .expect("DNS hijack rule");
    assert!(dns_index < direct_index);
}

#[test]
fn ordered_user_rules_render_proxy_direct_and_block_actions_in_order() {
    let user_rules = parse_rule_lines(&[
        "block domain=ads.example.com".into(),
        "direct process=game.exe".into(),
        "proxy port=443".into(),
    ])
    .expect("user rules");
    let config = build_sing_box_config(&RuntimeOptions {
        user_rules,
        ..default_options()
    });
    let rules = config["route"]["rules"].as_array().unwrap();
    let blocked_domain_index = rules
        .iter()
        .position(|rule| {
            rule["action"] == "reject" && rule["domain"] == serde_json::json!(["ads.example.com"])
        })
        .expect("blocked domain rule");
    let direct_process_index = rules
        .iter()
        .position(|rule| {
            rule["outbound"] == "direct" && rule["process_name"] == serde_json::json!(["game.exe"])
        })
        .expect("direct process rule");
    let proxy_port_index = rules
        .iter()
        .position(|rule| rule["outbound"] == "proxy" && rule["port"] == serde_json::json!([443]))
        .expect("proxy port rule");

    assert_eq!(rules[blocked_domain_index]["action"], "reject");
    assert_eq!(
        rules[blocked_domain_index]["domain"],
        serde_json::json!(["ads.example.com"])
    );
    assert_eq!(rules[direct_process_index]["outbound"], "direct");
    assert_eq!(
        rules[direct_process_index]["process_name"],
        serde_json::json!(["game.exe"])
    );
    assert_eq!(rules[proxy_port_index]["outbound"], "proxy");
    assert_eq!(rules[proxy_port_index]["port"], serde_json::json!([443]));
    assert!(blocked_domain_index < direct_process_index);
    assert!(direct_process_index < proxy_port_index);

    let dns_index = rules
        .iter()
        .position(|rule| rule["action"] == "hijack-dns")
        .expect("DNS hijack rule");
    let quic_index = rules
        .iter()
        .position(|rule| rule["network"] == "udp" && rule["port"] == 443)
        .expect("QUIC guard");
    assert!(dns_index < blocked_domain_index);
    assert!(quic_index < blocked_domain_index);
}
