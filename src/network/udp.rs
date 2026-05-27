use tokio::net::UdpSocket;
use tokio::time::{timeout, Duration};
use std::net::SocketAddr;
use tracing::{debug, trace};

fn obter_payload_porta(porta: u16) -> Vec<u8> {
    match porta {
        53 => vec![
            0x1a, 0x2b, // Transaction ID
            0x01, 0x00, // Flags: Standard query
            0x00, 0x01, // Questions: 1
            0x00, 0x00, // Answer RRs: 0
            0x00, 0x00, // Authority RRs: 0
            0x00, 0x00, // Additional RRs: 0
        ],
        123 => {
            let mut p = vec![0u8; 48];
            p[0] = 0x1b; 
            p
        }
        _ => vec![],
    }
}

pub async fn escanear_porta_udp(ip: &str, porta: u16, timeout_ms: u64) -> String {
    let endereco_alvo = format!("{}:{}", ip, porta);
    
    let endereco: SocketAddr = match endereco_alvo.parse() {
        Ok(addr) => addr,
        Err(_) => return "Erro de Endereço".to_string(),
    };

    let socket = match UdpSocket::bind("0.0.0.0:0").await {
        Ok(s) => s,
        Err(_) => return "Falha de Socket Local".to_string(),
    };

    if socket.connect(endereco).await.is_err() {
        return "Falha de Conexão UDP".to_string();
    }

    let payload = obter_payload_porta(porta);
    
    trace!("Disparando probe UDP para {} ({} bytes)", endereco_alvo, payload.len());
    if socket.send(&payload).await.is_err() {
        return "Filtrada/Erro de Envio".to_string();
    }

    let mut buffer = [0; 512];
    match timeout(Duration::from_millis(timeout_ms), socket.recv(&mut buffer)).await {
        Ok(Ok(bytes_lidos)) => {
            debug!("Resposta recebida na porta UDP {}: {} bytes", porta, bytes_lidos);
            match porta {
                53 => "DNS Server (Ativo)".to_string(),
                123 => "NTP Server (Ativo)".to_string(),
                _ => "Aberta (Resposta Recebida)".to_string(),
            }
        }
        Ok(Result::Err(ref e)) if e.kind() == std::io::ErrorKind::ConnectionRefused => {
            debug!("Porta UDP {} fechada (ICMP Connection Refused)", porta);
            "Fechada".to_string()
        }
        Ok(Result::Err(_)) => {
            "Aberta | Filtrada".to_string()
        }
        Err(_) => {
            if porta == 53 || porta == 123 {
                "Aberta | Filtrada (Sem resposta ao Probe)".to_string()
            } else {
                "Aberta | Filtrada".to_string()
            }
        }
    }
}

