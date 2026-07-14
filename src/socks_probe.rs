use crate::endpoint::SocksEndpoint;
use anyhow::{Context, Result, bail};
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream, ToSocketAddrs, UdpSocket};
use std::time::Duration;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SocksProbeResult {
    pub tcp_port_open: bool,
    pub socks5_no_auth: bool,
    pub socks5_no_auth_error: Option<String>,
    pub tcp_connect: bool,
    pub tcp_connect_error: Option<String>,
    pub udp_associate: bool,
    pub udp_bind_addr: Option<SocketAddr>,
    pub udp_associate_error: Option<String>,
    pub udp_relay: bool,
    pub udp_relay_error: Option<String>,
}

impl SocksProbeResult {
    pub fn usable_for_tcp(&self) -> bool {
        self.socks5_no_auth && self.tcp_connect
    }

    pub fn usable_for_udp(&self) -> bool {
        self.usable_for_tcp() && self.udp_associate && self.udp_relay
    }
}

pub fn require_udp_for_all_app_coverage(
    endpoint: impl std::fmt::Display,
    result: &SocksProbeResult,
) -> Result<()> {
    if result.usable_for_udp() {
        return Ok(());
    }

    if !result.udp_associate {
        let detail = result
            .udp_associate_error
            .as_deref()
            .unwrap_or("unknown UDP ASSOCIATE failure");
        bail!(
            "SOCKS5 UDP ASSOCIATE is required for all-app coverage but failed for {endpoint}: {detail}. Use --allow-tcp-only / -AllowTcpOnly only for browser-style TCP mode."
        );
    }

    let detail = result
        .udp_relay_error
        .as_deref()
        .unwrap_or("unknown UDP relay failure");
    bail!(
        "SOCKS5 UDP relay is required for all-app coverage but failed for {endpoint}: {detail}. Use --allow-tcp-only / -AllowTcpOnly only for browser-style TCP mode."
    );
}

pub fn validate_socks_for_mode(
    endpoint: impl std::fmt::Display,
    result: &SocksProbeResult,
    allow_tcp_only: bool,
) -> Result<()> {
    if !result.usable_for_tcp() {
        let detail = if !result.socks5_no_auth {
            result
                .socks5_no_auth_error
                .as_deref()
                .unwrap_or("SOCKS5 no-auth handshake failed")
        } else {
            result
                .tcp_connect_error
                .as_deref()
                .unwrap_or("SOCKS5 TCP CONNECT probe failed")
        };
        let capability = if result.socks5_no_auth {
            "SOCKS5 TCP CONNECT"
        } else {
            "SOCKS5 no-auth"
        };
        bail!("SOCKS endpoint {endpoint} is not usable for {capability}: {detail}");
    }

    if !allow_tcp_only {
        require_udp_for_all_app_coverage(endpoint, result)?;
    }

    Ok(())
}

pub fn probe_socks5(endpoint: &SocksEndpoint, timeout: Duration) -> SocksProbeResult {
    let tcp_port_open = crate::engine::socks_is_listening(endpoint, timeout);
    let no_auth = socks5_no_auth_handshake(endpoint, timeout);
    let socks5_no_auth = no_auth.is_ok();
    let socks5_no_auth_error = no_auth.err().map(|error| format!("{error:#}"));
    let tcp_connect_result = socks5_tcp_connect_probe(endpoint, timeout);
    let tcp_connect = tcp_connect_result.is_ok();
    let tcp_connect_error = tcp_connect_result
        .as_ref()
        .err()
        .map(|error| format!("{error:#}"));
    let udp_associate_result = socks5_udp_associate(endpoint, timeout);
    let udp_associate_error = udp_associate_result
        .as_ref()
        .err()
        .map(|error| format!("{error:#}"));
    let (udp_guard, udp_bind_addr) = match udp_associate_result {
        Ok((stream, bind_addr)) => (Some(stream), Some(bind_addr)),
        Err(_) => (None, None),
    };
    let udp_relay_result = match (udp_guard.as_ref(), udp_bind_addr) {
        (Some(_stream), Some(bind_addr)) => verify_socks5_udp_relay(endpoint, bind_addr, timeout),
        _ => Err(anyhow::anyhow!("skipped because UDP ASSOCIATE failed")),
    };
    let udp_relay_error = udp_relay_result
        .as_ref()
        .err()
        .map(|error| format!("{error:#}"));

    SocksProbeResult {
        tcp_port_open,
        socks5_no_auth,
        socks5_no_auth_error,
        tcp_connect,
        tcp_connect_error,
        udp_associate: udp_bind_addr.is_some(),
        udp_bind_addr,
        udp_associate_error,
        udp_relay: udp_relay_result.is_ok(),
        udp_relay_error,
    }
}

pub fn probe_socks5_tcp(endpoint: &SocksEndpoint, timeout: Duration) -> SocksProbeResult {
    let tcp_port_open = crate::engine::socks_is_listening(endpoint, timeout);
    let no_auth = socks5_no_auth_handshake(endpoint, timeout);
    let socks5_no_auth = no_auth.is_ok();
    let socks5_no_auth_error = no_auth.err().map(|error| format!("{error:#}"));
    let tcp_connect_result = socks5_tcp_connect_probe(endpoint, timeout);
    let tcp_connect = tcp_connect_result.is_ok();
    let tcp_connect_error = tcp_connect_result
        .as_ref()
        .err()
        .map(|error| format!("{error:#}"));

    SocksProbeResult {
        tcp_port_open,
        socks5_no_auth,
        socks5_no_auth_error,
        tcp_connect,
        tcp_connect_error,
        udp_associate: false,
        udp_bind_addr: None,
        udp_associate_error: Some("skipped in explicit TCP-only mode".to_string()),
        udp_relay: false,
        udp_relay_error: Some("skipped in explicit TCP-only mode".to_string()),
    }
}

fn connect(endpoint: &SocksEndpoint, timeout: Duration) -> Result<TcpStream> {
    let mut last_error = None;
    for addr in endpoint
        .to_string()
        .to_socket_addrs()
        .context("resolving SOCKS endpoint")?
    {
        match TcpStream::connect_timeout(&addr, timeout) {
            Ok(stream) => {
                stream.set_read_timeout(Some(timeout)).ok();
                stream.set_write_timeout(Some(timeout)).ok();
                return Ok(stream);
            }
            Err(error) => last_error = Some(error),
        }
    }

    Err(last_error
        .map(anyhow::Error::from)
        .unwrap_or_else(|| anyhow::anyhow!("SOCKS endpoint resolved to no addresses")))
}

fn socks5_no_auth_handshake(endpoint: &SocksEndpoint, timeout: Duration) -> Result<()> {
    let mut stream = connect(endpoint, timeout)?;
    write_socks5_method_request(&mut stream)?;
    let mut response = [0u8; 2];
    stream
        .read_exact(&mut response)
        .context("reading SOCKS5 method response")?;
    parse_socks5_method_response(&response)
}

fn socks5_tcp_connect_probe(endpoint: &SocksEndpoint, timeout: Duration) -> Result<()> {
    let targets = [
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 443),
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 443),
    ];
    let mut last_error = None;

    for target in targets {
        match socks5_connect(endpoint, target, timeout) {
            Ok(()) => return Ok(()),
            Err(error) => last_error = Some(error),
        }
    }

    Err(last_error.unwrap_or_else(|| anyhow::anyhow!("SOCKS5 TCP CONNECT probe failed")))
}

fn socks5_connect(endpoint: &SocksEndpoint, target: SocketAddr, timeout: Duration) -> Result<()> {
    let mut stream = connect(endpoint, timeout)?;
    write_socks5_method_request(&mut stream)?;
    let mut method_response = [0u8; 2];
    stream
        .read_exact(&mut method_response)
        .context("reading SOCKS5 method response for TCP CONNECT")?;
    parse_socks5_method_response(&method_response)?;

    let mut request = vec![0x05, 0x01, 0x00];
    match target.ip() {
        IpAddr::V4(address) => {
            request.push(0x01);
            request.extend(address.octets());
        }
        IpAddr::V6(address) => {
            request.push(0x04);
            request.extend(address.octets());
        }
    }
    request.extend(target.port().to_be_bytes());
    stream
        .write_all(&request)
        .context("writing SOCKS5 TCP CONNECT request")?;

    let mut header = [0u8; 4];
    stream
        .read_exact(&mut header)
        .context("reading SOCKS5 TCP CONNECT response")?;
    if header[0] != 0x05 {
        bail!("SOCKS server returned unsupported version {}", header[0]);
    }
    if header[2] != 0x00 {
        bail!("SOCKS5 TCP CONNECT response reserved byte was not zero");
    }
    if header[1] != 0x00 {
        bail!(
            "SOCKS5 TCP CONNECT failed with reply {} ({})",
            header[1],
            socks5_reply_description(header[1])
        );
    }

    let address_length = match header[3] {
        0x01 => 4,
        0x04 => 16,
        0x03 => {
            let mut length = [0u8; 1];
            stream
                .read_exact(&mut length)
                .context("reading SOCKS5 TCP CONNECT domain length")?;
            length[0] as usize
        }
        atyp => bail!("unsupported SOCKS5 TCP CONNECT address type {atyp:#x}"),
    };
    let mut bound_address = vec![0u8; address_length + 2];
    stream
        .read_exact(&mut bound_address)
        .context("reading SOCKS5 TCP CONNECT bound address")?;
    Ok(())
}

fn socks5_udp_associate(
    endpoint: &SocksEndpoint,
    timeout: Duration,
) -> Result<(TcpStream, SocketAddr)> {
    let mut stream = connect(endpoint, timeout)?;
    write_socks5_method_request(&mut stream)?;
    let mut method_response = [0u8; 2];
    stream
        .read_exact(&mut method_response)
        .context("reading SOCKS5 method response")?;
    parse_socks5_method_response(&method_response)?;

    stream
        .write_all(&[0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .context("writing SOCKS5 UDP ASSOCIATE request")?;

    let mut header = [0u8; 4];
    stream
        .read_exact(&mut header)
        .context("reading SOCKS5 UDP ASSOCIATE header")?;
    let atyp = header[3];
    let mut body = Vec::new();
    match atyp {
        0x01 => {
            body.resize(6, 0);
            stream
                .read_exact(&mut body)
                .context("reading IPv4 UDP ASSOCIATE body")?;
        }
        0x04 => {
            body.resize(18, 0);
            stream
                .read_exact(&mut body)
                .context("reading IPv6 UDP ASSOCIATE body")?;
        }
        0x03 => {
            let mut len = [0u8; 1];
            stream
                .read_exact(&mut len)
                .context("reading domain UDP ASSOCIATE length")?;
            body.push(len[0]);
            body.resize(1 + len[0] as usize + 2, 0);
            stream
                .read_exact(&mut body[1..])
                .context("reading domain UDP ASSOCIATE body")?;
        }
        _ => bail!("unsupported SOCKS5 UDP ASSOCIATE address type {atyp:#x}"),
    }

    let mut response = header.to_vec();
    response.extend(body);
    let bind_addr = parse_socks5_udp_associate_response(&response)?;
    let peer_addr = stream
        .peer_addr()
        .context("reading connected SOCKS peer address")?;
    Ok((stream, normalize_udp_bind_addr(peer_addr, bind_addr)?))
}

fn write_socks5_method_request(stream: &mut TcpStream) -> Result<()> {
    stream
        .write_all(&[0x05, 0x01, 0x00])
        .context("writing SOCKS5 no-auth method request")
}

pub fn parse_socks5_method_response(response: &[u8]) -> Result<()> {
    if response.len() != 2 {
        bail!("SOCKS5 method response must be exactly 2 bytes");
    }
    if response[0] != 0x05 {
        bail!("SOCKS server returned unsupported version {}", response[0]);
    }
    if response[1] != 0x00 {
        bail!("SOCKS server did not accept no-auth method");
    }
    Ok(())
}

pub fn parse_socks5_udp_associate_response(response: &[u8]) -> Result<SocketAddr> {
    if response.len() < 6 {
        bail!("SOCKS5 UDP ASSOCIATE response too short");
    }
    if response[0] != 0x05 {
        bail!("SOCKS server returned unsupported version {}", response[0]);
    }
    if response[1] != 0x00 {
        bail!(
            "SOCKS5 UDP ASSOCIATE failed with reply {} ({})",
            response[1],
            socks5_reply_description(response[1])
        );
    }
    if response[2] != 0x00 {
        bail!("SOCKS5 UDP ASSOCIATE response reserved byte was not zero");
    }

    match response[3] {
        0x01 => {
            if response.len() < 10 {
                bail!("SOCKS5 IPv4 UDP ASSOCIATE response too short");
            }
            let addr = Ipv4Addr::new(response[4], response[5], response[6], response[7]);
            let port = u16::from_be_bytes([response[8], response[9]]);
            Ok(SocketAddr::new(IpAddr::V4(addr), port))
        }
        0x04 => {
            if response.len() < 22 {
                bail!("SOCKS5 IPv6 UDP ASSOCIATE response too short");
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&response[4..20]);
            let port = u16::from_be_bytes([response[20], response[21]]);
            Ok(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(octets)), port))
        }
        0x03 => {
            let len = response[4] as usize;
            if response.len() < 5 + len + 2 {
                bail!("SOCKS5 domain UDP ASSOCIATE response too short");
            }
            let port_index = 5 + len;
            let port = u16::from_be_bytes([response[port_index], response[port_index + 1]]);
            Ok(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), port))
        }
        value => bail!("unsupported SOCKS5 address type {value:#x}"),
    }
}

fn normalize_udp_bind_addr(peer_addr: SocketAddr, bind_addr: SocketAddr) -> Result<SocketAddr> {
    if !bind_addr.ip().is_unspecified() {
        return Ok(bind_addr);
    }

    // RFC 1928 permits an unspecified relay address. Use the address family
    // of the actual connected peer instead of re-resolving the endpoint and
    // accidentally selecting a different A/AAAA result.
    Ok(SocketAddr::new(peer_addr.ip(), bind_addr.port()))
}

fn verify_socks5_udp_relay(
    endpoint: &SocksEndpoint,
    bind_addr: SocketAddr,
    timeout: Duration,
) -> Result<()> {
    let bind_local = if bind_addr.is_ipv4() {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
    } else {
        SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)
    };
    let socket =
        UdpSocket::bind(bind_local).context("binding UDP socket for SOCKS5 relay probe")?;
    socket.set_read_timeout(Some(timeout)).ok();
    socket.set_write_timeout(Some(timeout)).ok();

    let dns_query = build_dns_probe_query();
    let mut last_error = None;
    for dns_server in [
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 53),
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 53),
    ] {
        let packet = build_socks5_udp_packet(dns_server, &dns_query);
        if let Err(error) = socket.send_to(&packet, bind_addr) {
            last_error = Some(anyhow::Error::from(error).context("sending SOCKS5 UDP probe"));
            continue;
        }

        let mut response = [0u8; 2048];
        match socket.recv_from(&mut response) {
            Ok((size, _from)) => {
                if dns_probe_response_matches(&response[..size]) {
                    return Ok(());
                }
                last_error = Some(anyhow::anyhow!(
                    "SOCKS5 UDP relay response did not contain the expected DNS probe reply"
                ));
            }
            Err(error) => {
                last_error = Some(anyhow::Error::from(error).context(format!(
                    "timed out waiting for UDP relay response via {endpoint} to {dns_server}"
                )));
            }
        }
    }

    Err(last_error.unwrap_or_else(|| anyhow::anyhow!("SOCKS5 UDP relay probe failed")))
}

fn build_dns_probe_query() -> Vec<u8> {
    let mut query = vec![
        0x50, 0x42, // transaction id: "PB"
        0x01, 0x00, // standard recursive query
        0x00, 0x01, // one question
        0x00, 0x00, // answer RRs
        0x00, 0x00, // authority RRs
        0x00, 0x00, // additional RRs
    ];
    for label in ["example", "com"] {
        query.push(label.len() as u8);
        query.extend(label.as_bytes());
    }
    query.extend([0x00, 0x00, 0x01, 0x00, 0x01]);
    query
}

fn build_socks5_udp_packet(destination: SocketAddr, payload: &[u8]) -> Vec<u8> {
    let mut packet = vec![0x00, 0x00, 0x00];
    match destination.ip() {
        IpAddr::V4(addr) => {
            packet.push(0x01);
            packet.extend(addr.octets());
        }
        IpAddr::V6(addr) => {
            packet.push(0x04);
            packet.extend(addr.octets());
        }
    }
    packet.extend(destination.port().to_be_bytes());
    packet.extend(payload);
    packet
}

fn dns_probe_response_matches(packet: &[u8]) -> bool {
    let Some(payload_offset) = socks5_udp_payload_offset(packet) else {
        return false;
    };
    let payload = &packet[payload_offset..];
    payload.len() >= 12 && payload[0] == 0x50 && payload[1] == 0x42 && payload[2] & 0x80 == 0x80
}

fn socks5_udp_payload_offset(packet: &[u8]) -> Option<usize> {
    if packet.len() < 7 || packet[0] != 0 || packet[1] != 0 || packet[2] != 0 {
        return None;
    }

    match packet[3] {
        0x01 => {
            if packet.len() >= 10 {
                Some(10)
            } else {
                None
            }
        }
        0x04 => {
            if packet.len() >= 22 {
                Some(22)
            } else {
                None
            }
        }
        0x03 => {
            let len = *packet.get(4)? as usize;
            let offset = 5 + len + 2;
            if packet.len() >= offset {
                Some(offset)
            } else {
                None
            }
        }
        _ => None,
    }
}

fn socks5_reply_description(reply: u8) -> &'static str {
    match reply {
        0x00 => "succeeded",
        0x01 => "general SOCKS server failure",
        0x02 => "connection not allowed by ruleset",
        0x03 => "network unreachable",
        0x04 => "host unreachable",
        0x05 => "connection refused",
        0x06 => "TTL expired",
        0x07 => "command not supported",
        0x08 => "address type not supported",
        _ => "unknown reply code",
    }
}
