use serde::Serialize;

#[derive(Serialize, Clone, Debug)]
pub struct ResultadoPorta {
    pub ip: String,
    pub hostname: Option<String>,
    pub porta: u16,
    pub status: String,
    pub servico: String,
    pub versao: Option<String>,
    pub produto: Option<String>,
}

pub struct TrabalhoScan {
    pub ip: String,
    pub display_name: Option<String>,
    pub porta: u16,
}

pub struct VulnerabilidadeConhecida {
    pub gatilho: &'static str,
    pub cve: &'static str,
    pub severidade: &'static str,
    pub descricao: &'static str,
}

pub fn checar_vulnerabilidades(banner: &str) -> Option<VulnerabilidadeConhecida> {
    let base_dados = vec![
        VulnerabilidadeConhecida {
            gatilho: "OpenSSH_7.4",
            cve: "CVE-2016-10009",
            severidade: "ALTA",
            descricao: "Execução remota de código (RCE) via encaminhamento de agente SSH.",
        },
        VulnerabilidadeConhecida {
            gatilho: "5.5.42",
            cve: "CVE-2016-6662",
            severidade: "CRÍTICA",
            descricao: "Injeção de configuração no MySQL que permite escalonamento de privilégios e RCE.",
        },
        VulnerabilidadeConhecida {
            gatilho: "vsftpd 2.3.4",
            cve: "Backdoor Nativo",
            severidade: "CRÍTICA",
            descricao: "Versão famosa com backdoor que abre um shell root na porta 6200 ao enviar um smile :) no usuário.",
        },
    ];

    for vuln in base_dados {
        if banner.contains(vuln.gatilho) {
            return Some(vuln);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vulnerabilidade_openssh() {
        let resultado = checar_vulnerabilidades("OpenSSH_7.4p1 Ubuntu");
        assert!(resultado.is_some());
        let vuln = resultado.unwrap();
        assert_eq!(vuln.cve, "CVE-2016-10009");
        assert_eq!(vuln.severidade, "ALTA");
    }

    #[test]
    fn test_vulnerabilidade_mysql() {
        let resultado = checar_vulnerabilidades("5.5.42-MySQL Community Server");
        assert!(resultado.is_some());
        let vuln = resultado.unwrap();
        assert_eq!(vuln.cve, "CVE-2016-6662");
        assert_eq!(vuln.severidade, "CRÍTICA");
    }

    #[test]
    fn test_vulnerabilidade_vsftpd() {
        let resultado = checar_vulnerabilidades("vsftpd 2.3.4");
        assert!(resultado.is_some());
        let vuln = resultado.unwrap();
        assert_eq!(vuln.cve, "Backdoor Nativo");
        assert_eq!(vuln.severidade, "CRÍTICA");
    }

    #[test]
    fn test_sem_vulnerabilidade() {
        let resultado = checar_vulnerabilidades("OpenSSH_9.0 Ubuntu");
        assert!(resultado.is_none());
    }

    #[test]
    fn test_banner_vazio() {
        let resultado = checar_vulnerabilidades("");
        assert!(resultado.is_none());
    }

    #[test]
    fn test_resultado_porta_serialize() {
        let r = ResultadoPorta {
            ip: "192.168.0.1".to_string(),
            hostname: Some("router.local".to_string()),
            porta: 80,
            status: "Aberta (TCP)".to_string(),
            servico: "HTTP".to_string(),
            versao: None,
            produto: None,
        };
        let json = serde_json::to_string(&r).unwrap();
        assert!(json.contains("192.168.0.1"));
        assert!(json.contains("router.local"));
        assert!(json.contains("80"));
    }

    #[test]
    fn test_resultado_porta_hostname_none() {
        let r = ResultadoPorta {
            ip: "10.0.0.1".to_string(),
            hostname: None,
            porta: 443,
            status: "Aberta (TCP)".to_string(),
            servico: "HTTPS".to_string(),
            versao: None,
            produto: None,
        };
        let json = serde_json::to_string(&r).unwrap();
        assert!(json.contains("null"));
    }
}
