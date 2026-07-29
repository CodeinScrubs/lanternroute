use lanternroute::runtime_status::{RuntimeHealth, RuntimeSignals};

#[test]
fn all_runtime_signals_are_required_for_healthy_status() {
    let healthy = RuntimeSignals {
        engine_running: true,
        capture_routes_present: true,
        tun_interface_present: true,
        control_api_reachable: true,
    };
    assert_eq!(healthy.health(), RuntimeHealth::Healthy);

    for signals in [
        RuntimeSignals {
            engine_running: false,
            ..healthy
        },
        RuntimeSignals {
            capture_routes_present: false,
            ..healthy
        },
        RuntimeSignals {
            tun_interface_present: false,
            ..healthy
        },
        RuntimeSignals {
            control_api_reachable: false,
            ..healthy
        },
    ] {
        assert_eq!(signals.health(), RuntimeHealth::Inconsistent);
    }
}

#[test]
fn stopped_status_allows_irrelevant_stale_control_metadata() {
    let stopped = RuntimeSignals {
        engine_running: false,
        capture_routes_present: false,
        tun_interface_present: false,
        control_api_reachable: false,
    };

    assert_eq!(stopped.health(), RuntimeHealth::Stopped);
}

#[test]
fn orphaned_routes_or_interface_are_inconsistent() {
    for signals in [
        RuntimeSignals {
            engine_running: false,
            capture_routes_present: true,
            tun_interface_present: false,
            control_api_reachable: false,
        },
        RuntimeSignals {
            engine_running: false,
            capture_routes_present: false,
            tun_interface_present: true,
            control_api_reachable: false,
        },
    ] {
        assert_eq!(signals.health(), RuntimeHealth::Inconsistent);
    }
}
