use serde::Serialize;
use std::net::SocketAddr;
use tokio::net::UdpSocket;
use tokio::time::{Duration, timeout};
use tracing::{debug, trace};

#[derive(Debug, Clone, Serialize)]
pub struct ResultadoUdp {
    pub status: String,
    pub servico: Option<String>,
    pub produto: Option<String>,
    pub versao: Option<String>,
}

impl ResultadoUdp {
    fn fechada() -> Self {
        Self {
            status: "Fechada".to_string(),
            servico: None,
            produto: None,
            versao: None,
        }
    }
    fn erro(msg: &str) -> Self {
        Self {
            status: msg.to_string(),
            servico: None,
            produto: None,
            versao: None,
        }
    }
    fn aberta_filtrada(motivo: &str) -> Self {
        Self {
            status: format!("Aberta | Filtrada ({})", motivo),
            servico: None,
            produto: None,
            versao: None,
        }
    }
    fn identificada(servico: &str, produto: Option<&str>, versao: Option<String>) -> Self {
        Self {
            status: "Aberta (Ativo)".to_string(),
            servico: Some(servico.to_string()),
            produto: produto.map(|p| p.to_string()),
            versao,
        }
    }
}

fn obter_payload_porta(porta: u16) -> Vec<u8> {
    match porta {
        53 => vec![
            0x1a, 0x2b, 0x01, 0x00, 0x00, 0x01,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ],
        123 => {
            let mut p = vec![0u8; 48];
            p[0] = 0x1b;
            p
        }
        // SNMP GetRequest v1, community "public", OID sysDescr (1.3.6.1.2.1.1.1.0)
        161 => vec![
            0x30, 0x26, 0x02, 0x01, 0x00, 0x04, 0x06, b'p', b'u', b'b', b'l', b'i', b'c',
            0xa0, 0x19, 0x02, 0x01, 0x01, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00,
            0x30, 0x0e, 0x30, 0x0c, 0x06, 0x08,
            0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00,
            0x05, 0x00,
        ],
        // NetBIOS Name Service - query genérica
        137 => vec![
            0x82, 0x28, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x20, 0x43, 0x4b, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
            0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
            0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x00,
            0x00, 0x21, 0x00, 0x01,
        ],
        // SSDP/UPnP M-SEARCH
        1900 => b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\nST: ssdp:all\r\n\r\n".to_vec(),
        // mDNS query genérica (_services._dns-sd._udp.local)
        5353 => vec![
            0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x09, b'_', b's', b'e', b'r', b'v', b'i', b'c', b'e', b's',
            0x07, b'_', b'd', b'n', b's', b'-', b's', b'd',
            0x04, b'_', b'u', b'd', b'p',
            0x05, b'l', b'o', b'c', b'a', b'l', 0x00,
            0x00, 0x0c, 0x00, 0x01,
        ],
        // TFTP Read Request (arquivo inexistente só pra provocar resposta de erro)
        69 => {
            let mut p = vec![0x00, 0x01];
            p.extend_from_slice(b"nonexistent\0octet\0");
            p
        }
        _ => vec![],
    }
}

fn interpretar_resposta_conhecida(porta: u16, buffer: &[u8], bytes_lidos: usize) -> ResultadoUdp {
    match porta {
        53 => ResultadoUdp::identificada("DNS Server", Some("DNS"), None),
        123 => ResultadoUdp::identificada("NTP Server", Some("NTP"), None),
        161 => {
            let texto = String::from_utf8_lossy(&buffer[..bytes_lidos]);
            let printable: String = texto
                .chars()
                .filter(|c| c.is_ascii_graphic() || *c == ' ')
                .collect();
            let versao = if printable.trim().is_empty() {
                None
            } else {
                Some(printable.trim().to_string())
            };
            ResultadoUdp::identificada("SNMP Agent", Some("SNMP"), versao)
        }
        137 => ResultadoUdp::identificada("NetBIOS Name Service", Some("NetBIOS"), None),
        1900 => {
            let texto = String::from_utf8_lossy(&buffer[..bytes_lidos]);
            let server_line = texto
                .lines()
                .find(|l| l.to_lowercase().starts_with("server:"));
            let versao = server_line.map(|l| {
                l.trim_start_matches("Server:")
                    .trim_start_matches("server:")
                    .trim()
                    .to_string()
            });
            ResultadoUdp::identificada("SSDP/UPnP", Some("UPnP"), versao)
        }
        5353 => ResultadoUdp::identificada("mDNS Responder", Some("mDNS"), None),
        69 => ResultadoUdp::identificada("TFTP Server", Some("TFTP"), None),
        _ => ResultadoUdp::identificada("Aberta (Resposta Recebida)", None, None),
    }
}

pub async fn escanear_porta_udp(ip: &str, porta: u16, timeout_ms: u64) -> ResultadoUdp {
    let endereco_alvo = format!("{}:{}", ip, porta);

    let endereco: SocketAddr = match endereco_alvo.parse() {
        Ok(addr) => addr,
        Err(_) => return ResultadoUdp::erro("Erro de Endereço"),
    };

    let socket = match UdpSocket::bind("0.0.0.0:0").await {
        Ok(s) => s,
        Err(_) => return ResultadoUdp::erro("Falha de Socket Local"),
    };

    if socket.connect(endereco).await.is_err() {
        return ResultadoUdp::erro("Falha de Conexão UDP");
    }

    let payload = obter_payload_porta(porta);

    trace!(
        "Disparando probe UDP para {} ({} bytes)",
        endereco_alvo,
        payload.len()
    );
    if socket.send(&payload).await.is_err() {
        return ResultadoUdp::aberta_filtrada("Erro de Envio");
    }

    let mut buffer = [0; 512];
    match timeout(Duration::from_millis(timeout_ms), socket.recv(&mut buffer)).await {
        Ok(Ok(bytes_lidos)) => {
            debug!(
                "Resposta direta recebida na porta UDP {}: {} bytes",
                porta, bytes_lidos
            );
            interpretar_resposta_conhecida(porta, &buffer, bytes_lidos)
        }
        Ok(Result::Err(ref e)) if e.kind() == std::io::ErrorKind::ConnectionRefused => {
            debug!("Porta UDP {} fechada (ICMP Connection Refused)", porta);
            ResultadoUdp::fechada()
        }
        Ok(Result::Err(_)) => ResultadoUdp::aberta_filtrada("Erro de Leitura"),
        Err(_) => {
            let portas_com_probe_dedicado = [53, 123, 161, 137, 1900, 5353, 69];
            if portas_com_probe_dedicado.contains(&porta) {
                return ResultadoUdp::aberta_filtrada("Sem resposta ao Probe");
            }

            let payload_generico = b"HELP\r\n\r\n";
            let _ = socket.send(payload_generico).await;

            let mut buffer_banner = [0; 256];
            match timeout(
                Duration::from_millis(std::cmp::max(timeout_ms / 2, 10)),
                socket.recv(&mut buffer_banner),
            )
            .await
            {
                Ok(Ok(bytes_lidos)) if bytes_lidos > 0 => {
                    let texto = String::from_utf8_lossy(&buffer_banner[..bytes_lidos]);
                    let banner_limpo = texto.lines().next().unwrap_or("").trim();
                    if !banner_limpo.is_empty() {
                        debug!("Banner UDP capturado na porta {}: {}", porta, banner_limpo);
                        return ResultadoUdp {
                            status: "Aberta (Banner)".to_string(),
                            servico: Some(banner_limpo.to_string()),
                            produto: None,
                            versao: None,
                        };
                    }
                    ResultadoUdp::aberta_filtrada("Resposta Vazia")
                }
                _ => ResultadoUdp::aberta_filtrada("Sem Resposta"),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_payload_dns_nao_vazio() {
        assert!(!obter_payload_porta(53).is_empty());
    }

    #[test]
    fn test_payload_ntp_48_bytes() {
        assert_eq!(obter_payload_porta(123).len(), 48);
    }

    #[test]
    fn test_payload_snmp_nao_vazio() {
        assert!(!obter_payload_porta(161).is_empty());
    }

    #[test]
    fn test_payload_ssdp_contem_msearch() {
        let payload = obter_payload_porta(1900);
        let texto = String::from_utf8_lossy(&payload);
        assert!(texto.contains("M-SEARCH"));
    }

    #[test]
    fn test_payload_porta_desconhecida_vazio() {
        assert!(obter_payload_porta(9999).is_empty());
    }

    #[test]
    fn test_interpretar_dns() {
        let resultado = interpretar_resposta_conhecida(53, &[], 0);
        assert_eq!(resultado.servico, Some("DNS Server".to_string()));
        assert_eq!(resultado.produto, Some("DNS".to_string()));
    }

    #[test]
    fn test_interpretar_ntp() {
        let resultado = interpretar_resposta_conhecida(123, &[], 0);
        assert_eq!(resultado.servico, Some("NTP Server".to_string()));
    }

    #[test]
    fn test_interpretar_ssdp_com_server_header() {
        let resposta = b"HTTP/1.1 200 OK\r\nServer: Linux/3.10 UPnP/1.0 MiniUPnPd/2.1\r\n\r\n";
        let resultado = interpretar_resposta_conhecida(1900, resposta, resposta.len());
        assert_eq!(resultado.servico, Some("SSDP/UPnP".to_string()));
        assert!(resultado.versao.unwrap().contains("MiniUPnPd"));
    }

    #[test]
    fn test_interpretar_porta_desconhecida() {
        let resultado = interpretar_resposta_conhecida(9999, &[], 0);
        assert_eq!(resultado.status, "Aberta (Ativo)");
        assert!(resultado.produto.is_none());
    }

    #[test]
    fn test_resultado_udp_fechada() {
        let r = ResultadoUdp::fechada();
        assert_eq!(r.status, "Fechada");
    }
}
