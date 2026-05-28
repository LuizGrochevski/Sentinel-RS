use tokio::time::{timeout, Duration};
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use tracing::{debug, trace};

pub async fn resolver_hostname_reverso(ip_str: &str) -> String {
    let ip = match IpAddr::from_str(ip_str) {
        Ok(parsed_ip) => parsed_ip,
        Err(_) => return ip_str.to_string(),
    };

    trace!("Iniciando consulta de Reverse DNS nativa para o IP: {}", ip_str);

    let sockaddr = SocketAddr::new(ip, 0);

    match timeout(Duration::from_millis(150), tokio::net::lookup_host(format!("{}", sockaddr.ip()))).await {
        Ok(Ok(mut iterador)) => {
            if let Some(endereco_resolvido) = iterador.next() {
                let nome = format!("{}", endereco_resolvido.ip());
                if nome != ip_str && !nome.is_empty() {
                    debug!("Reverse DNS nativo com sucesso! {} -> {}", ip_str, nome);
                    return format!("{} ({})", ip_str, nome);
                }
            }
            ip_str.to_string()
        }
        _ => {
            ip_str.to_string()
        }
    }
}

