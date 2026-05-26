use serde::Serialize;

#[derive(Serialize, Clone, Debug)]
pub struct ResultadoPorta {
    pub ip: String,
    pub porta: u16,
    pub status: String,
    pub servico: String,
}

pub struct TrabalhoScan {
    pub ip: String,
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

