use tokio::process::Command;
use std::collections::HashMap;
use std::net::IpAddr;
use tracing::{debug, trace};

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct ArpEntry {
    pub ip: IpAddr,
    pub mac: String,
    pub interface: String,
}

pub async fn ler_tabela_arp() -> HashMap<IpAddr, ArpEntry> {
    let mut mapa_arp = HashMap::new();

    let output = match Command::new("ip")
        .arg("neighbor")
        .arg("show")
        .output()
        .await 
    {
        Ok(out) => out,
        Err(e) => {
            debug!("Falha ao executar comando 'ip neighbor': {:?}", e);
            return mapa_arp;
        }
    };

    if !output.status.success() {
        debug!("O comando 'ip neighbor' retornou status de erro");
        return mapa_arp;
    }

    let stdout_str = String::from_utf8_lossy(&output.stdout);

    for linha in stdout_str.lines() {
        let partes: Vec<&str> = linha.split_whitespace().collect();
        
        if partes.len() >= 5 {
            let ip_str = partes[0];
            let interface_str = partes[2];
            
            if let Some(pos_lladdr) = partes.iter().position(|&x| x == "lladdr") {
                if partes.len() > pos_lladdr + 1 {
                    let mac_str = partes[pos_lladdr + 1];
                    let status_str = partes.last().unwrap_or(&"");

                    if *status_str == "FAILED" || mac_str == "00:00:00:00:00:00" {
                        continue;
                    }

                    if let Ok(ip) = ip_str.parse::<IpAddr>() {
                        mapa_arp.insert(ip, ArpEntry {
                            ip,
                            mac: mac_str.to_string(),
                            interface: interface_str.to_string(),
                        });
                    }
                }
            }
        }
    }

    trace!("Tabela ARP via 'ip neighbor' lida. Encontradas {} entradas válidas.", mapa_arp.len());
    mapa_arp
}
