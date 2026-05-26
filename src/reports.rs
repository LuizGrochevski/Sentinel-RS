use std::fs::File;
use std::io::Write as IoWrite;
use serde::Serialize;
use colored::*;
use crate::models::ResultadoPorta;

pub fn gerar_relatorios(dados_finais: &[ResultadoPorta]) {
    if let Err(e) = std::fs::create_dir_all("reports") {
        eprintln!("{}: {}", "Erro crítico ao criar a pasta 'reports'".red().bold(), e);
        std::process::exit(1);
    }

    if !dados_finais.is_empty() {
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

        match File::create("reports/relatorio.md") {
            Ok(mut arquivo_md) => {
                let mut sucesso = true;
                sucesso &= writeln!(arquivo_md, "# 🛡 Relatório de Scan - Sentinel-RS\n").is_ok();
                sucesso &= writeln!(arquivo_md, "| IP Alvo | Porta | Status | Serviço Detectado |").is_ok();
                sucesso &= writeln!(arquivo_md, "| :--- | :--- | :--- | :--- |").is_ok();

                for resultado in dados_finais {
                    sucesso &= writeln!(
                        arquivo_md,
                        "| {} | {} | {} | {} |",
                        resultado.ip, resultado.porta, resultado.status, resultado.servico
                    ).is_ok();
                }

                if sucesso {
                    println!("{}", "📊 Tabela em Markdown gerada em 'reports/relatorio.md'!".green().bold());
                } else {
                    eprintln!("{}", "Aviso: Algumas lines não puderam ser escritas no relatório Markdown.".yellow());
                }
            }
            Err(e) => eprintln!("{}: {}", "Erro ao criar o arquivo 'relatorio.md'".red(), e),
        }

        match File::create("reports/relatorio.csv") {
            Ok(mut arquivo_csv) => {
                let mut sucesso = writeln!(arquivo_csv, "IP;Porta;Status;Servico").is_ok();

                for resultado_csv in dados_finais {
                    sucesso &= writeln!(
                        arquivo_csv,
                        "{};{};{};{}",
                        resultado_csv.ip, resultado_csv.porta, resultado_csv.status, resultado_csv.servico
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

    } else {
        println!("{}", "Nenhuma porta aberta encontrada para gerar o relatório.".red());
    }
}
