use anyhow::{Context, bail};
use std::fmt::{Display, Formatter};
use std::str::FromStr;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SocksEndpoint {
    pub host: String,
    pub port: u16,
}

impl Default for SocksEndpoint {
    fn default() -> Self {
        Self {
            host: "127.0.0.1".to_string(),
            port: 10808,
        }
    }
}

impl Display for SocksEndpoint {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        if self.host.contains(':') && !self.host.starts_with('[') {
            write!(f, "[{}]:{}", self.host, self.port)
        } else {
            write!(f, "{}:{}", self.host, self.port)
        }
    }
}

impl FromStr for SocksEndpoint {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let value = value.trim();
        let (host, port) = if let Some(rest) = value.strip_prefix('[') {
            let (host, rest) = rest
                .split_once(']')
                .context("IPv6 SOCKS endpoints must look like [::1]:10808")?;
            let port = rest
                .strip_prefix(':')
                .context("missing port after IPv6 host")?;
            (host, port)
        } else {
            value
                .rsplit_once(':')
                .context("SOCKS endpoint must look like 127.0.0.1:10808")?
        };

        let host = host.trim();
        if host.is_empty() {
            bail!("SOCKS endpoint host cannot be empty");
        }

        let parsed_port = port
            .parse::<u32>()
            .with_context(|| format!("invalid SOCKS endpoint port `{port}`"))?;
        if !(1..=u16::MAX as u32).contains(&parsed_port) {
            bail!("SOCKS endpoint port must be between 1 and 65535");
        }

        Ok(Self {
            host: host.to_string(),
            port: parsed_port as u16,
        })
    }
}
