use anyhow::anyhow;
use lanternroute::smoke::{
    assert_dns_https_ok, assert_same_egress_ip, combine_smoke_and_cleanup_results,
    summarize_latency,
};

#[test]
fn accepts_matching_explicit_and_tun_egress_ip() {
    assert_same_egress_ip("92.118.9.85\n", "92.118.9.85").expect("same IP");
}

#[test]
fn rejects_different_explicit_and_tun_egress_ip() {
    let error = assert_same_egress_ip("92.118.9.85", "1.1.1.1").unwrap_err();

    assert!(
        error
            .to_string()
            .contains("TUN egress IP did not match explicit SOCKS egress IP")
    );
}

#[test]
fn accepts_expected_example_domain_body() {
    assert_dns_https_ok("<html><title>Example Domain</title></html>").expect("example.com body");
}

#[test]
fn rejects_unexpected_dns_https_body() {
    let error = assert_dns_https_ok("not the expected page").unwrap_err();

    assert!(
        error
            .to_string()
            .contains("DNS/HTTPS smoke check did not receive expected example.com content")
    );
}

#[test]
fn summarizes_latency_samples() {
    let summary = summarize_latency(&[100, 140, 160]).expect("summary");

    assert_eq!(summary.count, 3);
    assert_eq!(summary.average_ms, 133);
    assert_eq!(summary.max_ms, 160);
}

#[test]
fn rejects_empty_latency_samples() {
    let error = summarize_latency(&[]).unwrap_err();

    assert!(error.to_string().contains("no latency samples"));
}

#[test]
fn cleanup_success_preserves_smoke_success() {
    combine_smoke_and_cleanup_results(Ok(()), Ok(())).expect("both ok");
}

#[test]
fn cleanup_failure_is_returned_when_smoke_succeeded() {
    let error =
        combine_smoke_and_cleanup_results(Ok(()), Err(anyhow!("cleanup failed"))).unwrap_err();

    assert!(error.to_string().contains("cleanup failed"));
}

#[test]
fn smoke_failure_is_not_hidden_by_cleanup_failure() {
    let error = combine_smoke_and_cleanup_results(
        Err(anyhow!("egress mismatch")),
        Err(anyhow!("cleanup failed")),
    )
    .unwrap_err();
    let message = format!("{error:#}");

    assert!(message.contains("egress mismatch"));
    assert!(message.contains("cleanup also failed"));
    assert!(message.contains("cleanup failed"));
}
