use crate::control_api::ControlApiEndpoint;
use crate::endpoint::SocksEndpoint;
use crate::rules::{RuleAction, RuleMatcher, UserRule};
use serde_json::{Value, json};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DnsMode {
    Local,
    RemoteViaProxy,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeOptions {
    pub socks: SocksEndpoint,
    pub dns_mode: DnsMode,
    pub block_quic: bool,
    pub tcp_only: bool,
    pub reconnect_apps: bool,
    pub proxy_local_networks: bool,
    pub interface_name: String,
    pub mtu: u16,
    pub log_level: String,
    pub direct_process_names: Vec<String>,
    pub custom_direct_process_names: Vec<String>,
    pub direct_ip_cidrs: Vec<String>,
    pub direct_domains: Vec<String>,
    pub direct_domain_suffixes: Vec<String>,
    pub direct_ports: Vec<u16>,
    pub direct_port_ranges: Vec<String>,
    pub user_rules: Vec<UserRule>,
    pub control_api: Option<ControlApiEndpoint>,
}

impl Default for RuntimeOptions {
    fn default() -> Self {
        Self {
            socks: SocksEndpoint::default(),
            dns_mode: DnsMode::Local,
            block_quic: true,
            tcp_only: false,
            reconnect_apps: true,
            proxy_local_networks: false,
            interface_name: "LanternRoute".to_string(),
            // 1500 is the interoperable default across Wi-Fi, VPN, and
            // virtual adapters; larger values remain available explicitly.
            mtu: 1500,
            log_level: "warn".to_string(),
            direct_process_names: default_direct_process_names(),
            custom_direct_process_names: Vec::new(),
            direct_ip_cidrs: Vec::new(),
            direct_domains: Vec::new(),
            direct_domain_suffixes: Vec::new(),
            direct_ports: Vec::new(),
            direct_port_ranges: Vec::new(),
            user_rules: Vec::new(),
            control_api: None,
        }
    }
}

pub fn default_direct_process_names() -> Vec<String> {
    [
        "lanternroute.exe",
        "sing-box.exe",
        "v2rayN.exe",
        "v2rayn.exe",
        "v2rayN.Desktop.exe",
        "v2rayn.desktop.exe",
        "xray.exe",
        "v2ray.exe",
        "wv2ray.exe",
        "mihomo.exe",
        "clash.exe",
        "clash-meta.exe",
        "clash-verge.exe",
        "clash-verge-rev.exe",
        "nekoray.exe",
        "nekobox.exe",
        "shadowsocks-windows.exe",
        "Shadowsocks.exe",
        "hysteria.exe",
        "hysteria2.exe",
        "tuic-client.exe",
        "naive.exe",
    ]
    .into_iter()
    .map(String::from)
    .collect()
}

pub fn build_sing_box_config(options: &RuntimeOptions) -> Value {
    let dns_final = match options.dns_mode {
        DnsMode::Local => "local",
        DnsMode::RemoteViaProxy => "remote",
    };
    let tun_stack = if options.tcp_only { "system" } else { "mixed" };

    // DNS interception must run before loopback/direct rules so DNS sent to a
    // local resolver is still handled by sing-box when remote DNS is enabled.
    let mut route_rules = vec![json!({
        "port": 53,
        "action": "hijack-dns"
    })];
    route_rules.extend([
        json!({
            "ip_cidr": [
                "127.0.0.0/8",
                "::1/128",
                "::ffff:127.0.0.0/104"
            ],
            "action": "route",
            "outbound": "direct"
        }),
        json!({
            "process_name": options.direct_process_names,
            "action": "route",
            "outbound": "direct"
        }),
    ]);

    if options.block_quic {
        route_rules.push(json!({
            "network": "udp",
            "port": 443,
            "action": "reject",
            "method": "default"
        }));
    }

    if options.tcp_only {
        route_rules.push(json!({
            "network": "udp",
            "action": "reject",
            "method": "default"
        }));
    }

    // Keep DNS handling and fail-closed UDP guards ahead of user rules.
    route_rules.extend(options.user_rules.iter().map(user_rule_to_value));

    if !options.custom_direct_process_names.is_empty() {
        route_rules.push(json!({
            "process_name": options.custom_direct_process_names,
            "action": "route",
            "outbound": "direct"
        }));
    }

    if !options.direct_ip_cidrs.is_empty() {
        route_rules.push(json!({
            "ip_cidr": options.direct_ip_cidrs,
            "action": "route",
            "outbound": "direct"
        }));
    }

    if !options.direct_domains.is_empty() || !options.direct_domain_suffixes.is_empty() {
        let mut rule = json!({
            "action": "route",
            "outbound": "direct"
        });
        if !options.direct_domains.is_empty() {
            rule["domain"] = json!(options.direct_domains);
        }
        if !options.direct_domain_suffixes.is_empty() {
            rule["domain_suffix"] = json!(options.direct_domain_suffixes);
        }
        route_rules.push(rule);
    }

    if !options.direct_ports.is_empty() || !options.direct_port_ranges.is_empty() {
        let mut rule = json!({
            "action": "route",
            "outbound": "direct"
        });
        if !options.direct_ports.is_empty() {
            rule["port"] = json!(options.direct_ports);
        }
        if !options.direct_port_ranges.is_empty() {
            rule["port_range"] = json!(options.direct_port_ranges);
        }
        route_rules.push(rule);
    }

    let mut route_exclude_address = vec!["169.254.0.0/16", "224.0.0.0/4", "fe80::/10", "ff00::/8"];
    if !options.proxy_local_networks {
        route_exclude_address.splice(
            0..0,
            [
                "10.0.0.0/8",
                "100.64.0.0/10",
                "172.16.0.0/12",
                "192.168.0.0/16",
                "fc00::/7",
            ],
        );
    }

    let mut config = json!({
        "log": {
            "level": options.log_level,
            "timestamp": true
        },
        "dns": {
            "servers": [
                {
                    "tag": "local",
                    "type": "local"
                },
                {
                    "tag": "remote",
                    "type": "https",
                    "server": "1.1.1.1",
                    "path": "/dns-query",
                    "tls": {
                        "enabled": true,
                        "server_name": "cloudflare-dns.com"
                    },
                    "detour": "proxy"
                }
            ],
            "final": dns_final,
            "strategy": "prefer_ipv4"
        },
        "inbounds": [
            {
                "type": "tun",
                "tag": "tun-in",
                "interface_name": options.interface_name,
                "address": [
                    "172.19.0.1/30",
                    "fdfe:dcba:9876::1/126"
                ],
                "mtu": options.mtu,
                "auto_route": true,
                "strict_route": true,
                "route_address": [
                    "0.0.0.0/1",
                    "128.0.0.0/1",
                    "::/1",
                    "8000::/1"
                ],
                "route_exclude_address": route_exclude_address,
                "stack": tun_stack
            }
        ],
        "outbounds": [
            {
                "type": "socks",
                "tag": "proxy",
                "server": options.socks.host,
                "server_port": options.socks.port,
                "version": "5",
                "domain_resolver": "local"
            },
            {
                "type": "direct",
                "tag": "direct"
            },
            {
                "type": "block",
                "tag": "block"
            }
        ],
        "route": {
            "auto_detect_interface": true,
            "default_domain_resolver": dns_final,
            "final": "proxy",
            "rules": route_rules
        }
    });

    // The loopback Clash API powers the live connection table. It is only
    // enabled when the controller allocated a per-session secret for it.
    if let Some(api) = &options.control_api {
        config["experimental"] = json!({
            "clash_api": {
                "external_controller": format!("127.0.0.1:{}", api.port),
                "secret": api.secret
            }
        });
    }

    config
}

fn user_rule_to_value(rule: &UserRule) -> Value {
    let mut value = match rule.action {
        RuleAction::Proxy => json!({
            "action": "route",
            "outbound": "proxy"
        }),
        RuleAction::Direct => json!({
            "action": "route",
            "outbound": "direct"
        }),
        RuleAction::Block => json!({
            "action": "reject",
            "method": "default"
        }),
    };

    match &rule.matcher {
        RuleMatcher::Process(process) => value["process_name"] = json!([process]),
        RuleMatcher::IpCidr(cidr) => value["ip_cidr"] = json!([cidr]),
        RuleMatcher::Domain(domain) => value["domain"] = json!([domain]),
        RuleMatcher::DomainSuffix(suffix) => value["domain_suffix"] = json!([suffix]),
        RuleMatcher::Port(port) => value["port"] = json!([port]),
        RuleMatcher::PortRange(range) => value["port_range"] = json!([range]),
        RuleMatcher::Network(network) => value["network"] = json!(network),
    }

    value
}
