use anyhow::{Context, Result};
use std::collections::HashMap;
use std::net::Ipv4Addr;

pub const MIB_TCP_STATE_ESTAB: u32 = 5;
pub const MIB_TCP_STATE_DELETE_TCB: u32 = 12;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BrowserResetCandidate {
    pub process_name: String,
    pub remote_addr: Ipv4Addr,
    pub remote_port: u16,
    pub state: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BrowserResetSummary {
    pub inspected: usize,
    pub reset: usize,
}

pub fn tcp_port_to_mib_dword(port: u16) -> u32 {
    u16::to_be(port) as u32
}

pub fn mib_dword_to_tcp_port(port: u32) -> u16 {
    u16::from_be(port as u16)
}

pub fn should_reset_connection(candidate: &BrowserResetCandidate) -> bool {
    candidate.state == MIB_TCP_STATE_ESTAB
        && is_browser_or_chat_app(&candidate.process_name)
        && !is_proxy_engine(&candidate.process_name)
        && is_public_ipv4(candidate.remote_addr)
        && candidate.remote_port != 0
}

fn is_browser_or_chat_app(process_name: &str) -> bool {
    matches!(
        process_name.to_ascii_lowercase().as_str(),
        "chrome.exe"
            | "msedge.exe"
            | "firefox.exe"
            | "brave.exe"
            | "opera.exe"
            | "opera_gx.exe"
            | "vivaldi.exe"
            | "telegram.exe"
            | "telegramdesktop.exe"
    )
}

fn is_proxy_engine(process_name: &str) -> bool {
    matches!(
        process_name.to_ascii_lowercase().as_str(),
        "proxybridge-rs.exe"
            | "sing-box.exe"
            | "v2rayn.exe"
            | "v2rayn.desktop.exe"
            | "xray.exe"
            | "v2ray.exe"
    )
}

fn is_public_ipv4(addr: Ipv4Addr) -> bool {
    !(addr.is_private()
        || addr.is_loopback()
        || addr.is_link_local()
        || addr.is_multicast()
        || addr.is_broadcast()
        || addr.is_unspecified()
        || is_cgnat(addr)
        || is_documentation(addr))
}

fn is_cgnat(addr: Ipv4Addr) -> bool {
    let octets = addr.octets();
    octets[0] == 100 && (64..=127).contains(&octets[1])
}

fn is_documentation(addr: Ipv4Addr) -> bool {
    let octets = addr.octets();
    matches!(
        (octets[0], octets[1], octets[2]),
        (192, 0, 2) | (198, 51, 100) | (203, 0, 113)
    )
}

#[cfg(windows)]
pub fn reset_browser_connections() -> Result<BrowserResetSummary> {
    use std::mem::size_of;
    use std::ptr::null_mut;
    use sysinfo::{ProcessesToUpdate, System};
    use windows_sys::Win32::Foundation::{ERROR_INSUFFICIENT_BUFFER, NO_ERROR};
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        GetExtendedTcpTable, MIB_TCPROW_LH, MIB_TCPROW_LH_0, MIB_TCPROW_OWNER_PID, SetTcpEntry,
        TCP_TABLE_OWNER_PID_ALL,
    };
    use windows_sys::Win32::Networking::WinSock::AF_INET;

    let mut size = 0u32;
    let first = unsafe {
        GetExtendedTcpTable(
            null_mut(),
            &mut size,
            0,
            AF_INET as u32,
            TCP_TABLE_OWNER_PID_ALL,
            0,
        )
    };
    if first != ERROR_INSUFFICIENT_BUFFER && first != NO_ERROR {
        anyhow::bail!("GetExtendedTcpTable sizing failed with Win32 error {first}");
    }

    // The table can grow between the sizing call and the read. Windows then
    // returns ERROR_INSUFFICIENT_BUFFER and updates `size`; retry with the
    // newly reported size instead of turning that normal race into a GUI error.
    let mut buffer = None;
    for attempt in 0..4 {
        let mut candidate = vec![0u8; size as usize];
        let result = unsafe {
            GetExtendedTcpTable(
                candidate.as_mut_ptr().cast(),
                &mut size,
                0,
                AF_INET as u32,
                TCP_TABLE_OWNER_PID_ALL,
                0,
            )
        };
        if result == NO_ERROR {
            buffer = Some(candidate);
            break;
        }
        if result != ERROR_INSUFFICIENT_BUFFER || attempt == 3 {
            anyhow::bail!(
                "GetExtendedTcpTable failed with Win32 error {result} after {} attempt(s)",
                attempt + 1
            );
        }
    }
    let buffer = buffer.expect("TCP table query must either succeed or return an error");

    let mut system = System::new_all();
    system.refresh_processes(ProcessesToUpdate::All, true);
    let mut process_names = HashMap::new();
    for (pid, process) in system.processes() {
        process_names.insert(
            pid.as_u32(),
            process.name().to_string_lossy().to_ascii_lowercase(),
        );
    }

    if buffer.len() < 4 {
        anyhow::bail!("GetExtendedTcpTable returned an undersized table");
    }
    let entry_count = u32::from_ne_bytes(buffer[0..4].try_into().unwrap()) as usize;
    let rows_offset = 4usize;
    let row_size = size_of::<MIB_TCPROW_OWNER_PID>();
    let mut inspected = 0usize;
    let mut reset = 0usize;

    for index in 0..entry_count {
        let offset = rows_offset + (index * row_size);
        if offset + row_size > buffer.len() {
            break;
        }

        let row = unsafe { *(buffer.as_ptr().add(offset).cast::<MIB_TCPROW_OWNER_PID>()) };
        let process_name = process_names
            .get(&row.dwOwningPid)
            .cloned()
            .unwrap_or_default();
        let candidate = BrowserResetCandidate {
            process_name,
            remote_addr: Ipv4Addr::from(row.dwRemoteAddr.to_ne_bytes()),
            remote_port: mib_dword_to_tcp_port(row.dwRemotePort),
            state: row.dwState,
        };
        inspected += 1;

        if !should_reset_connection(&candidate) {
            continue;
        }

        let tcp_row = MIB_TCPROW_LH {
            Anonymous: MIB_TCPROW_LH_0 {
                dwState: MIB_TCP_STATE_DELETE_TCB,
            },
            dwLocalAddr: row.dwLocalAddr,
            dwLocalPort: row.dwLocalPort,
            dwRemoteAddr: row.dwRemoteAddr,
            dwRemotePort: row.dwRemotePort,
        };
        let result = unsafe { SetTcpEntry(&tcp_row) };
        if result == NO_ERROR {
            reset += 1;
        }
    }

    Ok(BrowserResetSummary { inspected, reset })
}

#[cfg(not(windows))]
pub fn reset_browser_connections() -> Result<BrowserResetSummary> {
    Ok(BrowserResetSummary {
        inspected: 0,
        reset: 0,
    })
}

pub fn reset_browser_connections_with_context() -> Result<BrowserResetSummary> {
    reset_browser_connections().context("resetting existing browser connections")
}
