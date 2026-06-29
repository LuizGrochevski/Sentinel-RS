/// Base de assinaturas de serviços para fingerprinting por banner
pub struct Assinatura {
    pub gatilho: &'static str,
    pub nome: &'static str,
    pub categoria: &'static str,
}

pub fn identificar_estruturado(banner: &str) -> (Option<String>, Option<String>, Option<&'static str>) {
    let assinaturas = vec![
        // Web Servers
        Assinatura { gatilho: "Apache/", nome: "Apache HTTPD", categoria: "Web Server" },
        Assinatura { gatilho: "nginx/", nome: "Nginx", categoria: "Web Server" },
        Assinatura { gatilho: "Microsoft-IIS/", nome: "Microsoft IIS", categoria: "Web Server" },
        Assinatura { gatilho: "LiteSpeed", nome: "LiteSpeed", categoria: "Web Server" },
        Assinatura { gatilho: "cloudflare", nome: "Cloudflare", categoria: "Web Server" },
        Assinatura { gatilho: "openresty", nome: "OpenResty", categoria: "Web Server" },
        Assinatura { gatilho: "Caddy", nome: "Caddy", categoria: "Web Server" },

        // SSH
        Assinatura { gatilho: "OpenSSH_", nome: "OpenSSH", categoria: "SSH" },
        Assinatura { gatilho: "SSH-2.0-dropbear", nome: "Dropbear SSH", categoria: "SSH" },
        Assinatura { gatilho: "SSH-2.0-libssh", nome: "libssh", categoria: "SSH" },
        Assinatura { gatilho: "SSH-2.0-PuTTY", nome: "PuTTY SSH Server", categoria: "SSH" },

        // FTP
        Assinatura { gatilho: "vsftpd", nome: "vsftpd", categoria: "FTP" },
        Assinatura { gatilho: "ProFTPD", nome: "ProFTPD", categoria: "FTP" },
        Assinatura { gatilho: "FileZilla Server", nome: "FileZilla Server", categoria: "FTP" },
        Assinatura { gatilho: "Pure-FTPd", nome: "Pure-FTPd", categoria: "FTP" },
        Assinatura { gatilho: "wu-ftpd", nome: "WU-FTPd", categoria: "FTP" },

        // Mail
        Assinatura { gatilho: "Postfix", nome: "Postfix SMTP", categoria: "Mail" },
        Assinatura { gatilho: "Exim", nome: "Exim SMTP", categoria: "Mail" },
        Assinatura { gatilho: "Sendmail", nome: "Sendmail", categoria: "Mail" },
        Assinatura { gatilho: "Dovecot", nome: "Dovecot", categoria: "Mail" },
        Assinatura { gatilho: "Microsoft Exchange", nome: "Microsoft Exchange", categoria: "Mail" },

        // Databases
        Assinatura { gatilho: "MariaDB", nome: "MariaDB", categoria: "Database" },
        Assinatura { gatilho: "MySQL", nome: "MySQL", categoria: "Database" },
        Assinatura { gatilho: "PostgreSQL", nome: "PostgreSQL", categoria: "Database" },
        Assinatura { gatilho: "MongoDB", nome: "MongoDB", categoria: "Database" },
        Assinatura { gatilho: "+PONG", nome: "Redis", categoria: "Database" },
        Assinatura { gatilho: "Elasticsearch", nome: "Elasticsearch", categoria: "Database" },

        // Proxy / Load Balancer
        Assinatura { gatilho: "Squid/", nome: "Squid Proxy", categoria: "Proxy" },
        Assinatura { gatilho: "HAProxy", nome: "HAProxy", categoria: "Load Balancer" },
        Assinatura { gatilho: "Varnish", nome: "Varnish Cache", categoria: "Cache" },

        // CMS / Frameworks
        Assinatura { gatilho: "WordPress", nome: "WordPress", categoria: "CMS" },
        Assinatura { gatilho: "Drupal", nome: "Drupal", categoria: "CMS" },
        Assinatura { gatilho: "Joomla", nome: "Joomla", categoria: "CMS" },

        // Outros
        Assinatura { gatilho: "Werkzeug", nome: "Python Werkzeug", categoria: "Framework" },
        Assinatura { gatilho: "Jetty/", nome: "Eclipse Jetty", categoria: "Web Server" },
        Assinatura { gatilho: "Tomcat/", nome: "Apache Tomcat", categoria: "Web Server" },
        Assinatura { gatilho: "Python/", nome: "Python HTTP Server", categoria: "Web Server" },
        Assinatura { gatilho: "Ruby", nome: "Ruby Server", categoria: "Web Server" },
        Assinatura { gatilho: "Node.js", nome: "Node.js", categoria: "Runtime" },
        Assinatura { gatilho: "Kestrel", nome: "ASP.NET Kestrel", categoria: "Web Server" },
        Assinatura { gatilho: "Phusion Passenger", nome: "Phusion Passenger", categoria: "Web Server" },
    ];

    let banner_lower = banner.to_lowercase();

    for sig in &assinaturas {
        if banner_lower.contains(&sig.gatilho.to_lowercase()) {
            let versao = extrair_versao(banner, sig.gatilho);
            return (Some(sig.nome.to_string()), versao, Some(sig.categoria));
        }
    }
    (None, None, None)
}

pub fn identificar_por_banner(banner: &str) -> Option<String> {
    let (nome, versao, categoria) = identificar_estruturado(banner);
    let nome = nome?;
    let categoria = categoria.unwrap_or("Desconhecido");
    match versao {
        Some(v) => Some(format!("{} {} [{}]", nome, v, categoria)),
        None => Some(format!("{} [{}]", nome, categoria)),
    }
}

fn extrair_versao(banner: &str, gatilho: &str) -> Option<String> {
    let idx = banner.to_lowercase().find(&gatilho.to_lowercase())?;
    let depois = &banner[idx + gatilho.len()..];
    let versao: String = depois
        .chars()
        .take_while(|c| c.is_alphanumeric() || *c == '.' || *c == '-' || *c == '_')
        .collect();
    if versao.is_empty() {
        None
    } else {
        Some(versao)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_identificar_apache() {
        let resultado = identificar_por_banner("Server: Apache/2.4.51 (Ubuntu)");
        assert!(resultado.is_some());
        assert!(resultado.unwrap().contains("Apache HTTPD"));
    }

    #[test]
    fn test_identificar_nginx() {
        let resultado = identificar_por_banner("Server: nginx/1.18.0");
        assert!(resultado.is_some());
        let r = resultado.unwrap();
        assert!(r.contains("Nginx"));
        assert!(r.contains("1.18.0"));
    }

    #[test]
    fn test_identificar_openssh() {
        let resultado = identificar_por_banner("SSH-2.0-OpenSSH_8.9p1 Ubuntu-3");
        assert!(resultado.is_some());
        assert!(resultado.unwrap().contains("OpenSSH"));
    }

    #[test]
    fn test_identificar_redis() {
        let resultado = identificar_por_banner("+PONG\r\n");
        assert!(resultado.is_some());
        assert!(resultado.unwrap().contains("Redis"));
    }

    #[test]
    fn test_identificar_mysql() {
        let resultado = identificar_por_banner("MySQL 8.0.32 Community Server");
        assert!(resultado.is_some());
        assert!(resultado.unwrap().contains("MySQL"));
    }

    #[test]
    fn test_sem_assinatura() {
        let resultado = identificar_por_banner("banner desconhecido xyz");
        assert!(resultado.is_none());
    }

    #[test]
    fn test_extrair_versao_nginx() {
        let versao = super::extrair_versao("nginx/1.18.0 (Ubuntu)", "nginx/");
        assert_eq!(versao, Some("1.18.0".to_string()));
    }

    #[test]
    fn test_extrair_versao_apache() {
        let versao = super::extrair_versao("Apache/2.4.51 (Ubuntu)", "Apache/");
        assert_eq!(versao, Some("2.4.51".to_string()));
    }

    #[test]
    fn test_case_insensitive() {
        let resultado = identificar_por_banner("SERVER: NGINX/1.20.0");
        assert!(resultado.is_some());
    }
}
