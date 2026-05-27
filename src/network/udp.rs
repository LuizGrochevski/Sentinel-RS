use tokio::net::UdpSocket;
use tokio::time::{timeout, Duration};
use std::net::SocketAddr;
use tracing::{debug, trace};

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

    let payload: [u8; 0] = [];
    
    trace!("Disparando datagrama UDP para {}", endereco_alvo);
    if socket.send(&payload).await.is_err() {
        return "Filtrada/Erro de Envio".to_string();
    }

    let mut buffer = [0; 1];
    match timeout(Duration::from_millis(timeout_ms), socket.recv(&mut buffer)).await {
        Ok(Result::Err(ref e)) if e.kind() == std::io::ErrorKind::ConnectionRefused => {
            debug!("Porta UDP {} fechada (ICMP Connection Refused)", porta);
            "Fechada".to_string()
        }
        Ok(_) => {
            format!("Aberta (Resposta Recebida)")
        }
        Err(_) => {
            "Aberta | Filtrada".to_string()
        }
    }
}

