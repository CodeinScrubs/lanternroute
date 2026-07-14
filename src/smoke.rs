use anyhow::{Context, Result, bail};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LatencySummary {
    pub count: usize,
    pub average_ms: u128,
    pub max_ms: u128,
}

pub fn assert_same_egress_ip(explicit_socks_ip: &str, tun_ip: &str) -> Result<()> {
    let explicit_socks_ip = explicit_socks_ip.trim();
    let tun_ip = tun_ip.trim();
    if explicit_socks_ip.is_empty() {
        bail!("explicit SOCKS egress IP was empty");
    }
    if tun_ip.is_empty() {
        bail!("TUN egress IP was empty");
    }
    if explicit_socks_ip != tun_ip {
        bail!(
            "TUN egress IP did not match explicit SOCKS egress IP; explicit={explicit_socks_ip}, tun={tun_ip}"
        );
    }

    Ok(())
}

pub fn assert_dns_https_ok(body: &str) -> Result<()> {
    if !body.contains("Example Domain") {
        bail!("DNS/HTTPS smoke check did not receive expected example.com content");
    }

    Ok(())
}

pub fn summarize_latency(samples_ms: &[u128]) -> Result<LatencySummary> {
    if samples_ms.is_empty() {
        bail!("no latency samples were collected");
    }

    let total = samples_ms.iter().sum::<u128>();
    let max_ms = samples_ms.iter().copied().max().unwrap_or(0);
    Ok(LatencySummary {
        count: samples_ms.len(),
        average_ms: total / samples_ms.len() as u128,
        max_ms,
    })
}

pub fn combine_smoke_and_cleanup_results(
    smoke_result: Result<()>,
    cleanup_result: Result<()>,
) -> Result<()> {
    match (smoke_result, cleanup_result) {
        (Ok(()), Ok(())) => Ok(()),
        (Ok(()), Err(cleanup_error)) => Err(cleanup_error),
        (Err(smoke_error), Ok(())) => Err(smoke_error),
        (Err(smoke_error), Err(cleanup_error)) => {
            Err(smoke_error).with_context(|| format!("cleanup also failed: {cleanup_error:#}"))
        }
    }
}
