#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RuntimeSignals {
    pub engine_running: bool,
    pub capture_routes_present: bool,
    pub tun_interface_present: bool,
    pub control_api_reachable: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeHealth {
    Healthy,
    Stopped,
    Inconsistent,
}

impl RuntimeSignals {
    pub fn health(self) -> RuntimeHealth {
        if self.engine_running
            && self.capture_routes_present
            && self.tun_interface_present
            && self.control_api_reachable
        {
            RuntimeHealth::Healthy
        } else if !self.engine_running
            && !self.capture_routes_present
            && !self.tun_interface_present
        {
            RuntimeHealth::Stopped
        } else {
            RuntimeHealth::Inconsistent
        }
    }
}
