use tokio::net::TcpStream;
use tokio::time::{timeout, Duration};

pub async fn verificar_host_ativo(ip: &str, timeout_ms: u64) -> bool {
    let portas_teste = vec![80, 443, 22];

    for porta in portas_teste {
        let endereco = format!("{}:{}", ip, porta);
        if let Ok(resultado_conexao) = timeout(Duration::from_millis(timeout_ms), TcpStream::connect(&endereco)).await {
            if resultado_conexao.is_ok() {
                return true;
            }
        }
    }
    false
}

