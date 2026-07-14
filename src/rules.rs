use anyhow::{Context, Result, bail};
use ipnet::IpNet;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RuleAction {
    Proxy,
    Direct,
    Block,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RuleMatcher {
    Process(String),
    IpCidr(String),
    Domain(String),
    DomainSuffix(String),
    Port(u16),
    PortRange(String),
    Network(String),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UserRule {
    pub action: RuleAction,
    pub matcher: RuleMatcher,
}

pub fn parse_rule_lines(lines: &[String]) -> Result<Vec<UserRule>> {
    lines
        .iter()
        .enumerate()
        .filter_map(|(index, line)| {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                return None;
            }
            Some(
                parse_rule_line(trimmed)
                    .with_context(|| format!("invalid rule on line {}", index + 1)),
            )
        })
        .collect()
}

pub fn parse_rule_line(line: &str) -> Result<UserRule> {
    let (action, expression) = line
        .split_once(char::is_whitespace)
        .ok_or_else(|| anyhow::anyhow!("expected '<proxy|direct|block> <matcher>=<value>'"))?;
    let action = parse_action(action)?;
    let expression = expression.trim();
    let (kind, value) = expression
        .split_once('=')
        .ok_or_else(|| anyhow::anyhow!("expected a matcher such as process=game.exe"))?;
    let kind = kind.trim().to_ascii_lowercase();
    let value = value.trim();
    if value.is_empty() {
        bail!("matcher value cannot be empty");
    }

    let matcher = match kind.as_str() {
        "process" => RuleMatcher::Process(normalize_process_name(value)?),
        "ip" | "cidr" => {
            let network = value
                .parse::<IpNet>()
                .with_context(|| format!("invalid IP CIDR: {value:?}"))?;
            RuleMatcher::IpCidr(network.to_string())
        }
        "domain" => {
            let normalized = normalize_domain(value)?;
            if normalized.starts_with('.') {
                RuleMatcher::DomainSuffix(normalized)
            } else {
                RuleMatcher::Domain(normalized)
            }
        }
        "port" => parse_port_matcher(value)?,
        "network" => {
            let network = value.to_ascii_lowercase();
            if !matches!(network.as_str(), "tcp" | "udp" | "icmp") {
                bail!("network must be tcp, udp, or icmp");
            }
            RuleMatcher::Network(network)
        }
        _ => bail!("unknown matcher {kind:?}; use process, ip, domain, port, or network"),
    };

    Ok(UserRule { action, matcher })
}

fn parse_action(value: &str) -> Result<RuleAction> {
    match value.trim().to_ascii_lowercase().as_str() {
        "proxy" => Ok(RuleAction::Proxy),
        "direct" => Ok(RuleAction::Direct),
        "block" => Ok(RuleAction::Block),
        _ => bail!("action must be proxy, direct, or block"),
    }
}

pub fn normalize_process_name(value: &str) -> Result<String> {
    let process = value.trim();
    if process.is_empty()
        || process.chars().any(|character| {
            character.is_whitespace()
                || matches!(character, '/' | '\\' | '=' | ':' | ',' | ';' | '"' | '\'')
        })
    {
        bail!("process matcher must be an executable name, not a path");
    }
    Ok(process.to_string())
}

pub fn normalize_domain(value: &str) -> Result<String> {
    let mut domain = value.trim().to_ascii_lowercase();
    if domain.ends_with('.') {
        domain.pop();
    }
    if let Some(stripped) = domain.strip_prefix("*.") {
        domain = format!(".{stripped}");
    }
    let bare = domain.strip_prefix('.').unwrap_or(&domain);
    if bare.is_empty()
        || domain.chars().any(|character| {
            character.is_whitespace() || matches!(character, '/' | ':' | '\\' | '=')
        })
        || domain.contains('*')
    {
        bail!("invalid domain {value:?}");
    }
    for label in bare.split('.') {
        if label.is_empty()
            || label.starts_with('-')
            || label.ends_with('-')
            || !label
                .chars()
                .all(|character| character.is_ascii_alphanumeric() || character == '-')
        {
            bail!("invalid domain label in {value:?}");
        }
    }
    Ok(domain)
}

fn parse_port_matcher(value: &str) -> Result<RuleMatcher> {
    if let Ok(port) = value.parse::<u16>() {
        if port == 0 {
            bail!("port must be between 1 and 65535");
        }
        return Ok(RuleMatcher::Port(port));
    }

    let Some((start, end)) = value.split_once(':') else {
        bail!("port must be a number or range such as 8000:8100");
    };
    let start = parse_optional_port(start)?;
    let end = parse_optional_port(end)?;
    if start.is_none() && end.is_none()
        || start == Some(0)
        || end == Some(0)
        || matches!((start, end), (Some(first), Some(last)) if first > last)
    {
        bail!("invalid port range {value:?}");
    }
    Ok(RuleMatcher::PortRange(value.to_string()))
}

fn parse_optional_port(value: &str) -> Result<Option<u16>> {
    if value.is_empty() {
        return Ok(None);
    }
    value
        .parse::<u16>()
        .map(Some)
        .with_context(|| format!("invalid port range value {value:?}"))
}

#[cfg(test)]
mod tests {
    use super::{
        RuleAction, RuleMatcher, normalize_domain, normalize_process_name, parse_rule_line,
        parse_rule_lines,
    };

    #[test]
    fn parses_ordered_rule_forms() {
        let rules = parse_rule_lines(&[
            "direct process=game.exe".into(),
            "block domain=*.ads.example".into(),
            "proxy port=443".into(),
            "block network=udp".into(),
        ])
        .expect("rules");

        assert_eq!(rules[0].action, RuleAction::Direct);
        assert_eq!(rules[0].matcher, RuleMatcher::Process("game.exe".into()));
        assert_eq!(
            rules[1].matcher,
            RuleMatcher::DomainSuffix(".ads.example".into())
        );
        assert_eq!(rules[2].matcher, RuleMatcher::Port(443));
        assert_eq!(rules[3].matcher, RuleMatcher::Network("udp".into()));
    }

    #[test]
    fn ignores_comments_and_blank_lines() {
        let rules = parse_rule_lines(&[
            "# comment".into(),
            "  ".into(),
            "direct ip=192.0.2.0/24".into(),
        ])
        .expect("rules");
        assert_eq!(rules.len(), 1);
    }

    #[test]
    fn rejects_invalid_rule_values() {
        for line in [
            "maybe process=game.exe",
            "direct process=C:/game.exe",
            "block domain=bad..example",
            "direct port=0:0",
            "direct network=gre",
        ] {
            assert!(
                parse_rule_line(line).is_err(),
                "unexpectedly accepted {line}"
            );
        }
    }

    #[test]
    fn normalizes_domains_and_rejects_malformed_labels() {
        assert_eq!(normalize_domain("EXAMPLE.COM.").unwrap(), "example.com");
        assert_eq!(normalize_domain("*.Example.COM.").unwrap(), ".example.com");
        for value in ["bad..example", "-bad.example", "bad_.example", "*.bad.*"] {
            assert!(
                normalize_domain(value).is_err(),
                "unexpectedly accepted {value}"
            );
        }
    }

    #[test]
    fn process_names_reject_paths_and_shell_separators() {
        assert_eq!(normalize_process_name("game.exe").unwrap(), "game.exe");
        for value in ["C:/game.exe", "game name.exe", "game.exe,other.exe"] {
            assert!(
                normalize_process_name(value).is_err(),
                "unexpectedly accepted {value}"
            );
        }
    }
}
