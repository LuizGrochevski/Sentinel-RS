use std::net::IpAddr;
use std::str::FromStr;
use tokio::task;
use tokio::time::{Duration, timeout};
use tracing::{debug, trace};

pub async fn resolver_hostname_reverso(ip_str: &str, timeout_ms: u64) -> Option<String> {
    let ip = match IpAddr::from_str(ip_str) {
        Ok(parsed_ip) => parsed_ip,
        Err(_) => return None,
    };

    trace!("Iniciando consulta PTR real para o IP: {}", ip_str);

    match timeout(
        Duration::from_millis(timeout_ms),
        task::spawn_blocking(move || resolver_hostname_reverso_bloqueante(ip)),
    )
    .await
    {
        Ok(Ok(Some(hostname))) => {
            debug!("Reverse DNS com sucesso! {} -> {}", ip_str, hostname);
            Some(hostname)
        }
        Ok(Ok(None)) => None,
        Ok(Err(erro_join)) => {
            debug!(
                "Falha ao executar consulta PTR para {}: {}",
                ip_str, erro_join
            );
            None
        }
        Err(_) => {
            debug!("Timeout ao resolver PTR para {}", ip_str);
            None
        }
    }
}

#[cfg(unix)]
fn resolver_hostname_reverso_bloqueante(ip: IpAddr) -> Option<String> {
    use std::ffi::CStr;
    use std::mem;

    let mut host = [0 as libc::c_char; 1025];

    let retorno = match ip {
        IpAddr::V4(ipv4) => {
            let sockaddr = libc::sockaddr_in {
                sin_family: libc::AF_INET as libc::sa_family_t,
                sin_port: 0,
                sin_addr: libc::in_addr {
                    s_addr: u32::from_ne_bytes(ipv4.octets()),
                },
                sin_zero: [0; 8],
            };

            unsafe {
                libc::getnameinfo(
                    &sockaddr as *const libc::sockaddr_in as *const libc::sockaddr,
                    mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
                    host.as_mut_ptr(),
                    host.len() as libc::socklen_t,
                    std::ptr::null_mut(),
                    0,
                    libc::NI_NAMEREQD,
                )
            }
        }
        IpAddr::V6(ipv6) => {
            let sockaddr = libc::sockaddr_in6 {
                sin6_family: libc::AF_INET6 as libc::sa_family_t,
                sin6_port: 0,
                sin6_flowinfo: 0,
                sin6_addr: libc::in6_addr {
                    s6_addr: ipv6.octets(),
                },
                sin6_scope_id: 0,
            };

            unsafe {
                libc::getnameinfo(
                    &sockaddr as *const libc::sockaddr_in6 as *const libc::sockaddr,
                    mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
                    host.as_mut_ptr(),
                    host.len() as libc::socklen_t,
                    std::ptr::null_mut(),
                    0,
                    libc::NI_NAMEREQD,
                )
            }
        }
    };

    if retorno != 0 {
        return None;
    }

    let hostname = unsafe { CStr::from_ptr(host.as_ptr()) }
        .to_string_lossy()
        .trim_end_matches('.')
        .to_string();

    if hostname.is_empty() || hostname == ip.to_string() {
        None
    } else {
        Some(hostname)
    }
}

#[cfg(not(unix))]
fn resolver_hostname_reverso_bloqueante(_ip: IpAddr) -> Option<String> {
    None
}
