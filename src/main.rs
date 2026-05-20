use tokio::net::TcpStream;
use tokio::time::{timeout, Duration};
use std::sync::Arc;
use tokio::sync::Semaphore;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use std::fs::File;
use serde::Serialize;
use std::sync::Mutex;
use clap::Parser;
use colored::*;
use indicatif::{ProgressBar, ProgressStyle};

async fn detectar_servico(porta: u16, ip: &str, fluxo: &mut TcpStream) -> String {
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
            let requisicao = format!("HEAD / HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n", ip);
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

        3306 => "MySQL".to_string(),

        6379 => "Redis".to_string(),

        _ => {
            let requisicao = format!("HEAD / HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n", ip);
            if fluxo.write_all(requisicao.as_bytes()).await.is_ok() {
                if let Ok(Ok(bytes_lidos)) = timeout(Duration::from_secs(2), fluxo.read(&mut buffer)).await {
                    if bytes_lidos > 0 {
                        let banner = String::from_utf8_lossy(&buffer[..bytes_lidos]);
                        return banner.lines().next().unwrap_or("HTTP").trim().to_string();
                    }
                }
            }
            "Desconhecido".to_string()
        }
    }
}

#[derive(Serialize, Clone)]
struct ResultadoPorta {
    porta: u16,
    status: String,
    servico: String,
}

#[derive(Parser, Debug)]
#[command(name = "sentinel-rs", author = "Luiz Grochevski", version = "1.0", about = "Scanner de portas assíncrono e ultra rápido")]
struct Cli {
    target: String,

    #[arg(short = 'p', long = "ports", default_value = "1-1000")]
    ports: String,

    #[arg(short = 't', long = "threads", default_value = "50")]
    threads: usize,
}

#[tokio::main]
async fn main() {

    let args = Cli::parse();

    let ip_alvo = args.target;
    let limite_threads = args.threads;

    let partes_porta: Vec<&str> = args.ports.split('-').collect();
    if partes_porta.len() != 2 {
        eprintln!("{}", "Erro: O formato das portas deve ser INICIO-FIM (ex: -p 1-1000)".red().bold());
        std::process::exit(1);
    }

    let porta_inicial: u16 = partes_porta[0].parse().expect("Porta inicial inválida");
    let porta_final: u16 = partes_porta[1].parse().expect("Porta final inválida");

    let semaforo = Arc::new(Semaphore::new(limite_threads));
    let resultados_compartilhados = Arc::new(Mutex::new(Vec::new()));

    let portas = porta_inicial..=porta_final;
    let total_portas = porta_final - porta_inicial + 1;

    println!("{}", "🛡 Sentinel-RS iniciado!".blue().bold());
    println!("{} {}", "Alvo:".cyan(), ip_alvo);
    println!("{} {} até {}", "Intervalo:".cyan(), porta_inicial, porta_final);
    println!("{} {} conexões simultâneas\n", "Concorrência máxima:".cyan(), limite_threads.to_string().yellow());

    let mut tarefas = vec![];

    let barra = ProgressBar::new(total_portas.into());
    barra.set_style(
       ProgressStyle::default_bar()
          .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} portas ({eta})")
          .unwrap()
          .progress_chars("#>-"),
    );


    let barra_compartilhada = Arc::new(barra);

    for porta in portas {
        let permissao = Arc::clone(&semaforo);
        let ip = ip_alvo.clone();
        let lista_resultados = Arc::clone(&resultados_compartilhados);
        let pb = Arc::clone(&barra_compartilhada);

        let tarefa = tokio::spawn(async move {
            let _guarda = permissao.acquire().await.unwrap();
            let endereco = format!("{}:{}", ip, porta);

            if let Ok(Ok(mut fluxo)) = timeout(Duration::from_secs(1), TcpStream::connect(&endereco)).await {
                
     		let servico_detectado = detectar_servico(porta, &ip, &mut fluxo).await;

                pb.suspend(|| {
                    let alerta = format!("[+] Porta {} ABERTA | Serviço: {}", porta, servico_detectado);
                    println!("{}", alerta.green().bold());
                });

                let mut dados = lista_resultados.lock().unwrap();
                dados.push(ResultadoPorta {
                    porta,
                    status: "Aberta".to_string(),
                    servico: servico_detectado,
                });
            }

            pb.inc(1);
        });

        tarefas.push(tarefa);
    }

    for t in tarefas {
        let _ = t.await;
    }

    barra_compartilhada.finish_and_clear();

    println!("\n\n{}" ,"Scan finalizado! Gerando relatório...".yellow());

    let dados_finais = resultados_compartilhados.lock().unwrap();
    
    if !dados_finais.is_empty() {
        let arquivo = File::create("relatorio.json").expect("Não foi possível criar o arquivo");
        serde_json::to_writer_pretty(arquivo, &*dados_finais).expect("Erro ao escrever o JSON");
        println!("{}", "💾 Relatório salvo com sucesso em 'relatorio.json'!".green().bold());
    } else {
        println!("{}", "Nenhuma porta aberta encontrada para gerar o relatório.".red());
    }
}

