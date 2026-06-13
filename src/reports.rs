use crate::models::ResultadoPorta;
use colored::*;
use serde::Serialize;
use std::fs::File;
use std::io::Write as IoWrite;
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

pub fn gerar_relatorios(dados_finais: &[ResultadoPorta]) {
    if let Err(e) = std::fs::create_dir_all("reports") {
        eprintln!("{}: {}", "Erro crítico ao criar a pasta 'reports'".red().bold(), e);
        std::process::exit(1);
    }

    if !dados_finais.is_empty() {
        gerar_json(dados_finais);
        gerar_markdown(dados_finais);
        gerar_csv(dados_finais);
        gerar_yaml(dados_finais);
        gerar_xml(dados_finais);
        gerar_nmap_xml(dados_finais);
    } else {
        println!("{}", "Nenhuma porta aberta encontrada para gerar o relatório.".red());
    }
}

fn gerar_json(dados_finais: &[ResultadoPorta]) {
    match File::create("reports/relatorio.json") {
        Ok(arquivo) => {
            if serde_json::to_writer_pretty(arquivo, dados_finais).is_ok() {
                println!("{}", "💾 Relatório JSON salvo com sucesso em 'reports/relatorio.json'!".green().bold());
            } else {
                eprintln!("{}", "Erro: Falha ao estruturar os dados no arquivo JSON.".red());
            }
        }
        Err(e) => eprintln!("{}: {}", "Erro ao criar o arquivo 'relatorio.json'".red(), e),
    }
}

fn gerar_markdown(dados_finais: &[ResultadoPorta]) {
    match File::create("reports/relatorio.md") {
        Ok(mut arquivo_md) => {
            let mut sucesso = true;
            sucesso &= writeln!(arquivo_md, "# 🛡 Relatório de Scan - Sentinel-RS\n").is_ok();
            sucesso &= writeln!(arquivo_md, "| IP Alvo | Hostname | Porta | Status | Serviço Detectado |").is_ok();
            sucesso &= writeln!(arquivo_md, "| :--- | :--- | :--- | :--- | :--- |").is_ok();

            for resultado in dados_finais {
                sucesso &= writeln!(
                    arquivo_md,
                    "| {} | {} | {} | {} | {} |",
                    resultado.ip,
                    resultado.hostname.as_deref().unwrap_or("-"),
                    resultado.porta,
                    resultado.status,
                    resultado.servico
                ).is_ok();
            }

            if sucesso {
                println!("{}", "📊 Tabela em Markdown gerada em 'reports/relatorio.md'!".green().bold());
            } else {
                eprintln!("{}", "Aviso: Algumas linhas não puderam ser escritas no relatório Markdown.".yellow());
            }
        }
        Err(e) => eprintln!("{}: {}", "Erro ao criar o arquivo 'relatorio.md'".red(), e),
    }
}

fn gerar_csv(dados_finais: &[ResultadoPorta]) {
    match File::create("reports/relatorio.csv") {
        Ok(mut arquivo_csv) => {
            let mut sucesso = writeln!(arquivo_csv, "IP;Hostname;Porta;Status;Servico").is_ok();

            for resultado_csv in dados_finais {
                sucesso &= writeln!(
                    arquivo_csv,
                    "{};{};{};{};{}",
                    resultado_csv.ip,
                    resultado_csv.hostname.as_deref().unwrap_or(""),
                    resultado_csv.porta,
                    resultado_csv.status,
                    resultado_csv.servico
                ).is_ok();
            }

            if sucesso {
                println!("{}", "📈 CSV gerado com sucesso em 'reports/relatorio.csv'!".green().bold());
            } else {
                eprintln!("{}", "Aviso: Falha ao escrever os dados completos no CSV.".yellow());
            }
        }
        Err(e) => eprintln!("{}: {}", "Erro ao criar o arquivo 'relatorio.csv'".red(), e),
    }
}

fn gerar_yaml(dados_finais: &[ResultadoPorta]) {
    match File::create("reports/relatorio.yaml") {
        Ok(arquivo_yaml) => {
            if serde_yaml::to_writer(arquivo_yaml, dados_finais).is_ok() {
                println!("{}", "💾 Relatório YAML salvo com sucesso em 'reports/relatorio.yaml'!".green().bold());
            } else {
                eprintln!("{}", "Erro: Falha ao estruturar os dados no arquivo YAML.".red());
            }
        }
        Err(e) => eprintln!("{}: {}", "Erro ao criar o arquivo 'relatorio.yaml'".red(), e),
    }
}

fn gerar_xml(dados_finais: &[ResultadoPorta]) {
    match File::create("reports/relatorio.xml") {
        Ok(mut arquivo_xml) => {
            #[derive(Serialize)]
            struct Resultados<'a> {
                #[serde(rename = "PortaScan")]
                itens: &'a [ResultadoPorta],
            }

            let wrapper = Resultados { itens: dados_finais };

            match quick_xml::se::to_string(&wrapper) {
                Ok(xml_conteudo) => {
                    let mut sucesso = writeln!(arquivo_xml, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>").is_ok();
                    sucesso &= writeln!(arquivo_xml, "{}", xml_conteudo).is_ok();

                    if sucesso {
                        println!("{}", "🔮 Relatório XML gerado com sucesso em 'reports/relatorio.xml'!".green().bold());
                    } else {
                        eprintln!("{}", "Erro: Falha ao escrever os dados no arquivo XML.".red());
                    }
                }
                Err(_) => eprintln!("{}", "Erro: Falha na serialização do XML.".red()),
            }
        }
        Err(e) => eprintln!("{}: {}", "Erro ao criar o arquivo 'relatorio.xml'".red(), e),
    }
}

fn gerar_nmap_xml(dados_finais: &[ResultadoPorta]) {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    // Agrupa portas por IP
    let mut hosts: HashMap<String, Vec<&ResultadoPorta>> = HashMap::new();
    for resultado in dados_finais {
        hosts.entry(resultado.ip.clone()).or_default().push(resultado);
    }

    let mut linhas: Vec<String> = Vec::new();
    linhas.push(r#"<?xml version="1.0" encoding="UTF-8"?>"#.to_string());
    linhas.push(r#"<!DOCTYPE nmaprun>"#.to_string());
    linhas.push(format!(
        r#"<nmaprun scanner="sentinel-rs" version="0.1.0" start="{}" startstr="" args="sentinel-rs" xmloutputversion="1.04">"#,
        timestamp
    ));

    for (ip, portas) in &hosts {
        let hostname = portas.first()
            .and_then(|p| p.hostname.as_deref())
            .unwrap_or("");

        linhas.push(format!(r#"  <host starttime="{}" endtime="{}">"#, timestamp, timestamp));
        linhas.push(format!(r#"    <status state="up" reason="syn-ack"/>"#));
        linhas.push(format!(r#"    <address addr="{}" addrtype="ipv4"/>"#, ip));

        if !hostname.is_empty() {
            linhas.push(format!(r#"    <hostnames><hostname name="{}" type="PTR"/></hostnames>"#, hostname));
        } else {
            linhas.push(r#"    <hostnames/>"#.to_string());
        }

        linhas.push(r#"    <ports>"#.to_string());

        for porta in portas {
            let estado = if porta.status.to_lowercase().contains("aberta") {
                "open"
            } else {
                "closed"
            };

            let protocolo = if porta.status.to_lowercase().contains("udp") {
                "udp"
            } else {
                "tcp"
            };

            let servico = porta.servico.to_lowercase();
            let servico = servico.trim();

            linhas.push(format!(
                r#"      <port protocol="{}" portid="{}">"#,
                protocolo, porta.porta
            ));
            linhas.push(format!(
                r#"        <state state="{}" reason="syn-ack"/>"#,
                estado
            ));
            linhas.push(format!(
                r#"        <service name="{}" method="table" conf="3"/>"#,
                servico
            ));
            linhas.push(r#"      </port>"#.to_string());
        }

        linhas.push(r#"    </ports>"#.to_string());
        linhas.push(r#"  </host>"#.to_string());
    }

    linhas.push(format!(r#"  <runstats><finished time="{}" elapsed="0"/></runstats>"#, timestamp));
    linhas.push(r#"</nmaprun>"#.to_string());

    let conteudo = linhas.join("\n");

    match File::create("reports/relatorio_nmap.xml") {
        Ok(mut arquivo) => {
            if arquivo.write_all(conteudo.as_bytes()).is_ok() {
                println!("{}", "🗺  Relatório Nmap XML gerado em 'reports/relatorio_nmap.xml'!".green().bold());
            } else {
                eprintln!("{}", "Erro: Falha ao escrever o Nmap XML.".red());
            }
        }
        Err(e) => eprintln!("{}: {}", "Erro ao criar 'relatorio_nmap.xml'".red(), e),
    }
}
