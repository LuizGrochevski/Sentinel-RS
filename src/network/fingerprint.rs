use crate::network::signatures::identificar_por_banner;
use tokio::net::TcpStream;
use tokio::time::{timeout, Duration};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_rustls::rustls::{ClientConfig, RootCertStore};
use tokio_rustls::TlsConnector;
use rustls_pki_types::ServerName;
use std::sync::Arc;
use anyhow::Result;

fn nome_padrao_porta(porta: u16) -> String {
    // Fallback por porta conhecida
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

#[derive(Debug)]
struct VerificadorInseguro;
impl tokio_rustls::rustls::client::danger::ServerCertVerifier for VerificadorInseguro {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls_pki_types::CertificateDer<'_>,
        _intermediates: &[rustls_pki_types::CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls_pki_types::UnixTime,
    ) -> Result<tokio_rustls::rustls::client::danger::ServerCertVerified, tokio_rustls::rustls::Error> {
        Ok(tokio_rustls::rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls_pki_types::CertificateDer<'_>,
        _dss: &tokio_rustls::rustls::DigitallySignedStruct,
    ) -> Result<tokio_rustls::rustls::client::danger::HandshakeSignatureValid, tokio_rustls::rustls::Error> {
        Ok(tokio_rustls::rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls_pki_types::CertificateDer<'_>,
        _dss: &tokio_rustls::rustls::DigitallySignedStruct,
    ) -> Result<tokio_rustls::rustls::client::danger::HandshakeSignatureValid, tokio_rustls::rustls::Error> {
        Ok(tokio_rustls::rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<tokio_rustls::rustls::SignatureScheme> {
        vec![
            tokio_rustls::rustls::SignatureScheme::RSA_PKCS1_SHA256,
            tokio_rustls::rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            tokio_rustls::rustls::SignatureScheme::ED25519,
        ]
    }
}

pub async fn detectar_servico(porta: u16, ip: &str, fluxo: &mut TcpStream, timeout_ms: u64) -> String {
    let mut buffer = [0; 256];
    let d_timeout = Duration::from_millis(timeout_ms);

    match porta {
        21 => {
            if let Ok(Ok(bytes_lidos)) = timeout(d_timeout, fluxo.read(&mut buffer)).await {
                if bytes_lidos > 0 {
                    let resposta = String::from_utf8_lossy(&buffer[..bytes_lidos]);
                    if resposta.starts_with("220") {
                        let banner = resposta["220".len()..].trim();
                        return format!("FTP -> {}", banner.lines().next().unwrap_or(""));
                    }
                    return resposta.lines().next().unwrap_or("FTP").trim().to_string();
                }
            }
            "FTP (Sem Banner)".to_string()
        }

        22 => {
            if let Ok(Ok(bytes_lidos)) = timeout(d_timeout, fluxo.read(&mut buffer)).await {
                if bytes_lidos > 0 {
                    let banner = String::from_utf8_lossy(&buffer[..bytes_lidos]);
                    return banner.lines().next().unwrap_or("SSH").trim().to_string();
                }
            }
            "SSH (Sem Banner)".to_string()
        }

        25 => {
            if let Ok(Ok(bytes_lidos)) = timeout(d_timeout, fluxo.read(&mut buffer)).await {
                if bytes_lidos > 0 {
                    let resposta = String::from_utf8_lossy(&buffer[..bytes_lidos]);
                    if resposta.starts_with("220") {
                        let banner = resposta["220".len()..].trim();
                        return format!("SMTP -> {}", banner.lines().next().unwrap_or(""));
                    }
                    return resposta.lines().next().unwrap_or("SMTP").trim().to_string();
                }
            }
            "SMTP (Sem Banner)".to_string()
        }

        53 => "DNS (TCP)".to_string(),

        443 => {
            let mut raizes = RootCertStore::empty();
            for ancora in webpki_roots::TLS_SERVER_ROOTS {
                let certificado = rustls_pki_types::CertificateDer::from(ancora.subject.as_ref());
                let _ = raizes.add(certificado);
            }
            let mut config = ClientConfig::builder()
                .with_root_certificates(raizes)
                .with_no_client_auth();

            config.dangerous().set_certificate_verifier(Arc::new(VerificadorInseguro));

            let conector = TlsConnector::from(Arc::new(config));

            if let Ok(nome_servidor) = ServerName::try_from(ip) {
                let nome_estatico: ServerName<'static> = nome_servidor.to_owned();
                if let Ok(Ok(mut fluxo_tls)) = timeout(d_timeout, conector.connect(nome_estatico, fluxo)).await {

                    let requisicao = format!(
                        "HEAD / HTTP/1.1\r\n\
                         Host: {}\r\n\
                         User-Agent: SentinelRS/1.0\r\n\
                         Connection: close\r\n\r\n",
                        ip
                    );

                    if fluxo_tls.write_all(requisicao.as_bytes()).await.is_ok() {
                        if let Ok(Ok(bytes_lidos)) = timeout(d_timeout, fluxo_tls.read(&mut buffer)).await {
                            if bytes_lidos > 0 {
                                let resposta = String::from_utf8_lossy(&buffer[..bytes_lidos]);
                                let status_line = resposta.lines().next().unwrap_or("").trim();

                                let mut banner_servidor = String::new();
                                for linha in resposta.lines() {
                                    if linha.to_lowercase().starts_with("server:") {
                                        banner_servidor = linha["server:".len()..].trim().to_string();
                                        break;
                                    }
                                }

                                if !banner_servidor.is_empty() {
                                    return format!("HTTPS ({}) -> Servidor: {}", status_line, banner_servidor);
                                } else if !status_line.is_empty() {
                                    return format!("HTTPS ({})", status_line);
                                }
                            }
                        }
                    }
                    return "HTTPS (Conexão Segura Estabelecida)".to_string();
                }
            }
            "HTTPS (Falha no Handshake TLS)".to_string()
        }

        5432 => "PostgreSQL".to_string(),

        3306 => {
            if let Ok(Ok(bytes_lidos)) = timeout(d_timeout, fluxo.read(&mut buffer)).await {
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
                if let Ok(Ok(bytes_lidos)) = timeout(d_timeout, fluxo.read(&mut buffer)).await {
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
                 User-Agent: SentinelRS/1.0\r\n\
                 Connection: close\r\n\r\n",
                ip
            );
            if fluxo.write_all(requisicao.as_bytes()).await.is_ok() {
                let timeout_leitura = Duration::from_millis(std::cmp::min(timeout_ms, 100));
                if let Ok(Ok(bytes_lidos)) = timeout(timeout_leitura, fluxo.read(&mut buffer)).await {
                    if bytes_lidos > 0 {
                        let banner = String::from_utf8_lossy(&buffer[..bytes_lidos]);
                        let primeira_linha = banner.lines().next().unwrap_or("").trim();

                        if primeira_linha.to_uppercase().starts_with("HTTP/") {
                            let mut banner_servidor = String::new();
                            for linha in banner.lines() {
                                if linha.to_lowercase().starts_with("server:") {
                                    banner_servidor = linha["server:".len()..].trim().to_string();
                                    break;
                                }
                            }
                            if !banner_servidor.is_empty() {
                                return format!("HTTP/Serviço Web ({}) -> Servidor: {}", primeira_linha, banner_servidor);
                            }
                            return format!("HTTP/Serviço Web ({})", primeira_linha);
                        }

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


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nome_padrao_http() {
        assert_eq!(nome_padrao_porta(80), "HTTP");
    }

    #[test]
    fn test_nome_padrao_ftp() {
        assert!(nome_padrao_porta(21).contains("FTP"));
    }

    #[test]
    fn test_nome_padrao_desconhecido() {
        assert_eq!(nome_padrao_porta(9999), "Desconhecido");
    }
}
