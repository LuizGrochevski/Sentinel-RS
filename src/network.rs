use tokio::net::TcpStream;
use tokio::time::{timeout, Duration};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub async fn verificar_host_ativo(ip: &str) -> bool {
    let portas_teste = vec![80, 443, 22];

    for porta in portas_teste {
        let endereco = format!("{}:{}", ip, porta);
        if let Ok(resultado_conexao) = timeout(Duration::from_millis(800), TcpStream::connect(&endereco)).await {
            if resultado_conexao.is_ok() {
                return true;
            }
        }
    }
    false
}

fn nome_padrao_porta(porta: u16) -> String {
    match porta {
        80 => "HTTP".to_string(),
        21 => "FTP (Provável)".to_string(),
        23 => "Telnet (Provável)".to_string(),
        25 => "SMTP (Provável)".to_string(),
        110 => "POP3 (Provável)".to_string(),
        143 => "IMAP (Provável)".to_string(),
        8080 => "HTTP-Proxy".to_string(),
        _ => "Desconhecido".to_string(),
    }
}

pub async fn detectar_servico(porta: u16, ip: &str, fluxo: &mut TcpStream) -> String {
    let mut buffer = [0; 128];

    match porta {
        22 => {
            if let Ok(Ok(bytes_lidos)) = timeout(Duration::from_secs(2), fluxo.read(&mut buffer)).await {
                if bytes_lidos > 0 {
                    let banner = String::from_utf8_lossy(&buffer[..bytes_lidos]);
                    return banner.lines().next().unwrap_or("SSH").trim().to_string();
                }
            }
            "SSH (Sem Banner)".to_string()
        }

        53 => "DNS (TCP)".to_string(),

        443 => {
            let requisicao = format!(
                "HEAD / HTTP/1.1\r\n\
                 Host: {}\r\n\
                 User-Agent: SentinelRS/1.0\r\n\
                 Accept: text/html,application/xhtml+xml\r\n\
                 Connection: close\r\n\r\n",
                ip
            );
            if fluxo.write_all(requisicao.as_bytes()).await.is_ok() {
                if let Ok(Ok(bytes_lidos)) = timeout(Duration::from_secs(2), fluxo.read(&mut buffer)).await {
                    if bytes_lidos > 0 {
                        return "HTTPS (Possível)".to_string();
                    }
                }
            }
            "HTTPS".to_string()
        }

        5432 => "PostgreSQL".to_string(),

        3306 => {
            if let Ok(Ok(bytes_lidos)) = timeout(Duration::from_secs(2), fluxo.read(&mut buffer)).await {
                if bytes_lidos > 5 {
                    let resposta = String::from_utf8_lossy(&buffer[5..bytes_lidos]);
                    if resposta.contains("mysql") || resposta.contains("MariaDB") || !resposta.is_empty() {
                        let versao = resposta.lines().next().unwrap_or("MySQL").trim();
                        let versao_limpa: String = versao.chars().filter(|c| c.is_alphanumeric() || ".-_ ".contains(*c)).collect();
                        return format!("MySQL/MariaDB ({})", versao_limpa.trim());
                    }
                }
            }
            "MySQL (Provável)".to_string()
        }

        6379 => {
            let probe_redis = "PING\r\n";
            if fluxo.write_all(probe_redis.as_bytes()).await.is_ok() {
                if let Ok(Ok(bytes_lidos)) = timeout(Duration::from_secs(1), fluxo.read(&mut buffer)).await {
                    let resposta = String::from_utf8_lossy(&buffer[..bytes_lidos]);
                    if resposta.contains("+PONG") {
                        return "Redis Cache Server (Ativo)".to_string();
                    }
                }
            }
            "Redis (Provável)".to_string()
        }

        _ => {
            let requisicao = format!(
                "HEAD / HTTP/1.1\r\n\
                 Host: {}\r\n\
                 User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\r\n\
                 Accept: text/html,application/xhtml+xml\r\n\
                 Connection: close\r\n\r\n",
                ip
            );
            if fluxo.write_all(requisicao.as_bytes()).await.is_ok() {
                if let Ok(Ok(bytes_lidos)) = timeout(Duration::from_secs(2), fluxo.read(&mut buffer)).await {
                    if bytes_lidos > 0 {
                        let banner = String::from_utf8_lossy(&buffer[..bytes_lidos]);
                        let primeira_linha = banner.lines().next().unwrap_or("").trim();
                        if !primeira_linha.is_empty() {
                            return primeira_linha.to_string();
                        }
                    }
                }
            }
            nome_padrao_porta(porta)
        }
    }
}