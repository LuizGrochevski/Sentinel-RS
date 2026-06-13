use tokio::net::TcpStream;
use tokio::time::{timeout, Duration};
use tokio_rustls::rustls::{ClientConfig, RootCertStore};
use tokio_rustls::TlsConnector;
use rustls_pki_types::ServerName;
use std::sync::Arc;
use tracing::debug;

#[derive(Debug, Clone)]
pub struct TlsInfo {
    pub versao: String,
    pub cipher_suite: String,
    pub certificado_cn: Option<String>,
    pub certificado_sans: Vec<String>,
    pub certificado_emissor: Option<String>,
    pub certificado_valido_ate: Option<String>,
    pub certificado_expirado: bool,
}

impl TlsInfo {
    pub fn resumo(&self) -> String {
        let mut partes = vec![
            format!("TLS/{}", self.versao),
            format!("cipher={}", self.cipher_suite),
        ];

        if let Some(cn) = &self.certificado_cn {
            partes.push(format!("CN={}", cn));
        }

        if self.certificado_expirado {
            partes.push("⚠️ CERTIFICADO EXPIRADO".to_string());
        }

        if let Some(valido_ate) = &self.certificado_valido_ate {
            partes.push(format!("expira={}", valido_ate));
        }

        partes.join(" | ")
    }
}

pub async fn fingerprint_tls(ip: &str, porta: u16, timeout_ms: u64) -> Option<TlsInfo> {
    let endereco = format!("{}:{}", ip, porta);
    let d_timeout = Duration::from_millis(timeout_ms);

    let fluxo = match timeout(d_timeout, TcpStream::connect(&endereco)).await {
        Ok(Ok(f)) => f,
        _ => {
            debug!(ip, porta, "Falha ao conectar para TLS fingerprint.");
            return None;
        }
    };

    let mut raizes = RootCertStore::empty();
    for ancora in webpki_roots::TLS_SERVER_ROOTS {
        let cert = rustls_pki_types::CertificateDer::from(ancora.subject.as_ref());
        let _ = raizes.add(cert);
    }

    let mut config = ClientConfig::builder()
        .with_root_certificates(raizes)
        .with_no_client_auth();

    config.dangerous().set_certificate_verifier(Arc::new(VerificadorInseguro));

    let conector = TlsConnector::from(Arc::new(config));

    let nome_servidor = match ServerName::try_from(ip) {
        Ok(n) => n.to_owned(),
        Err(_) => {
            debug!(ip, "IP inválido para SNI no TLS fingerprint.");
            return None;
        }
    };

    let fluxo_tls = match timeout(d_timeout, conector.connect(nome_servidor, fluxo)).await {
        Ok(Ok(f)) => f,
        _ => {
            debug!(ip, porta, "Falha no handshake TLS.");
            return None;
        }
    };

    let (_, sessao) = fluxo_tls.get_ref();

    let versao = sessao
        .protocol_version()
        .map(|v| format!("{:?}", v).replace("TLSv1_", "1.").replace("TLSv1_3", "1.3").replace("TLSv1_2", "1.2"))
        .unwrap_or_else(|| "Desconhecida".to_string());

    let cipher_suite = sessao
        .negotiated_cipher_suite()
        .map(|c| format!("{:?}", c.suite()))
        .unwrap_or_else(|| "Desconhecida".to_string());

    let mut certificado_cn = None;
    let mut certificado_sans: Vec<String> = Vec::new();
    let mut certificado_emissor = None;
    let mut certificado_valido_ate = None;
    let mut certificado_expirado = false;

    if let Some(certs) = sessao.peer_certificates() {
        if let Some(cert_der) = certs.first() {
            if let Ok((_rem, cert)) = x509_parser::parse_x509_certificate(cert_der.as_ref()) {
                // CN do subject
                for rdn in cert.subject().iter() {
                    for attr in rdn.iter() {
                        if attr.attr_type().to_string() == "2.5.4.3" {
                            certificado_cn = Some(attr.attr_value().as_str().unwrap_or("").to_string());
                        }
                    }
                }

                // Emissor
                for rdn in cert.issuer().iter() {
                    for attr in rdn.iter() {
                        if attr.attr_type().to_string() == "2.5.4.3" {
                            certificado_emissor = Some(attr.attr_value().as_str().unwrap_or("").to_string());
                        }
                    }
                }

                // Validade
                let validade = cert.validity();
                certificado_valido_ate = Some(validade.not_after.to_datetime().to_string());
                let agora = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                certificado_expirado = (validade.not_after.timestamp() as u64) < agora;

                // SANs
                if let Ok(Some(san_ext)) = cert.subject_alternative_name() {
                    for san in &san_ext.value.general_names {
                        match san {
                            x509_parser::extensions::GeneralName::DNSName(nome) => {
                                certificado_sans.push(nome.to_string());
                            }
                            x509_parser::extensions::GeneralName::IPAddress(ip_bytes) => {
                                if ip_bytes.len() == 4 {
                                    certificado_sans.push(format!(
                                        "{}.{}.{}.{}",
                                        ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3]
                                    ));
                                }
                            }
                            _ => {}
                        }
                    }
                }
            }
        }
    }

    debug!(
        ip,
        porta,
        versao = %versao,
        cipher = %cipher_suite,
        cn = ?certificado_cn,
        "TLS fingerprint concluído."
    );

    Some(TlsInfo {
        versao,
        cipher_suite,
        certificado_cn,
        certificado_sans,
        certificado_emissor,
        certificado_valido_ate,
        certificado_expirado,
    })
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tls_info_resumo_basico() {
        let info = TlsInfo {
            versao: "1.3".to_string(),
            cipher_suite: "TLS_AES_256_GCM_SHA384".to_string(),
            certificado_cn: Some("example.com".to_string()),
            certificado_sans: vec!["example.com".to_string(), "www.example.com".to_string()],
            certificado_emissor: Some("Let's Encrypt".to_string()),
            certificado_valido_ate: Some("2025-12-31".to_string()),
            certificado_expirado: false,
        };
        let resumo = info.resumo();
        assert!(resumo.contains("TLS/1.3"));
        assert!(resumo.contains("example.com"));
        assert!(resumo.contains("2025-12-31"));
        assert!(!resumo.contains("EXPIRADO"));
    }

    #[test]
    fn test_tls_info_expirado() {
        let info = TlsInfo {
            versao: "1.2".to_string(),
            cipher_suite: "TLS_RSA_WITH_AES_128_CBC_SHA".to_string(),
            certificado_cn: Some("old.example.com".to_string()),
            certificado_sans: vec![],
            certificado_emissor: None,
            certificado_valido_ate: Some("2020-01-01".to_string()),
            certificado_expirado: true,
        };
        let resumo = info.resumo();
        assert!(resumo.contains("EXPIRADO"));
        assert!(resumo.contains("TLS/1.2"));
    }

    #[test]
    fn test_tls_info_sem_cn() {
        let info = TlsInfo {
            versao: "1.3".to_string(),
            cipher_suite: "TLS_AES_128_GCM_SHA256".to_string(),
            certificado_cn: None,
            certificado_sans: vec![],
            certificado_emissor: None,
            certificado_valido_ate: None,
            certificado_expirado: false,
        };
        let resumo = info.resumo();
        assert!(resumo.contains("TLS/1.3"));
        assert!(!resumo.contains("CN="));
    }
}
