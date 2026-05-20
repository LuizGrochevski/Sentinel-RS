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
use std::net::IpAddr;
use std::str::FromStr;
use ipnet::IpNet;

async fn verificar_host_ativo (ip: &str) -> bool {
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

        3306 => "MySQL".to_string(),

        6379 => "Redis".to_string(),

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

#[derive(Serialize, Clone)]
struct ResultadoPorta {
    ip: String,
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
    let limite_threads = args.threads;

    let partes_porta: Vec<&str> = args.ports.split('-').collect();
    if partes_porta.len() != 2 {
        eprintln!("{}", "Erro: O formato das portas deve ser INICIO-FIM (ex: -p 1-1000)".red().bold());
        std::process::exit(1);
    }

    let porta_inicial: u16 = partes_porta[0].parse().expect("Porta inicial inválida");
    let porta_final: u16 = partes_porta[1].parse().expect("Porta final inválida");

    let mut lista_ips: Vec<IpAddr> = Vec::new();
    if let Ok(rede) = IpNet::from_str(&args.target) {
        for ip in rede.hosts() {
            lista_ips.push(ip);
        }
    } else if let Ok(ip_unico) = IpAddr::from_str(&args.target) {
        lista_ips.push(ip_unico);
    } else {
        eprintln!("{}", "Erro: Alvo inválido. Use um IP válido ou bloco CIDR (ex: 192.168.0.0/24)".red().bold());
        std::process::exit(1);
    }

    let semaforo = Arc::new(Semaphore::new(limite_threads));
    let resultados_compartilhados = Arc::new(Mutex::new(Vec::new()));

    println!("{}", "🛡 Sentinel-RS iniciado!".blue().bold());
    println!("{} {}", "Alvo especificado:".cyan(), args.target);
    println!("{} {}", "Total de IPs para analisar:".cyan(), lista_ips.len().to_string().yellow());
    println!("{} {} até {}", "Intervalo de portas:".cyan(), porta_inicial, porta_final);
    println!("{} {} conexões simultâneas\n", "Concorrência máxima:".cyan(), limite_threads.to_string().yellow());

    let semaforo_ping = Arc::new(Semaphore::new(64));
    let ips_ativos_compartilhados = Arc::new(Mutex::new(Vec::new()));
    let mut tarefas_ping = vec![];

    let spinner_hosts = ProgressBar::new_spinner();
    spinner_hosts.set_style(
        ProgressStyle::default_spinner()
            .template("{spinner:.cyan} {msg}")
            .unwrap(),
    );
    spinner_hosts.set_message("Mapeando hosts ativos na rede em paralelo...".bright_black().to_string());

    spinner_hosts.enable_steady_tick(Duration::from_millis(100));

    for ip in lista_ips {
        let sem = Arc::clone(&semaforo_ping);
        let ativos_clone = Arc::clone(&ips_ativos_compartilhados);
        let ip_str = ip.to_string();

        tarefas_ping.push(tokio::spawn(async move {
            let _guarda = sem.acquire().await.unwrap();
            if verificar_host_ativo(&ip_str).await {
                let mut ativos = ativos_clone.lock().unwrap();
                ativos.push(ip_str);
            }
        }));
    }
    
    for t in tarefas_ping {
       let _ = t.await;
    }

    let ips_ativos = {
        let guard = ips_ativos_compartilhados.lock().unwrap();
        guard.clone()
    };

    spinner_hosts.finish_and_clear();
    println!("🔍 Mapeamento concluído: {} hosts encontrados.", ips_ativos.len().to_string().green().bold());

    if ips_ativos.is_empty() {
        println!("{}", "Nenhum dispositivo online encontrado. Abortando scan.".yellow());
        std::process::exit(0);
    } 

    let total_portas_por_ip = porta_final - porta_inicial + 1;
    let total_tarefas_globais = (ips_ativos.len() * total_portas_por_ip as usize) as u64;

    let barra = ProgressBar::new(total_tarefas_globais);
    barra.set_style(
       ProgressStyle::default_bar()
          .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} portas ({eta})")
          .unwrap()
          .progress_chars("#>-"),
    );

    let mut tarefas = vec![];
    let barra_compartilhada = Arc::new(barra);

    for ip in ips_ativos{
       for porta in porta_inicial..=porta_final {
           let permissao = Arc::clone(&semaforo);
           let lista_resultados = Arc::clone(&resultados_compartilhados);
           let pb = Arc::clone(&barra_compartilhada);
           let ip_clone = ip.clone();

           let tarefa = tokio::spawn(async move {
              let _guarda = permissao.acquire().await.unwrap();
              let endereco = format!("{}:{}", ip_clone, porta);

              if let Ok(Ok(mut fluxo)) = timeout(Duration::from_secs(1), TcpStream::connect(&endereco)).await {
                
             	   let servico_detectado = detectar_servico(porta, &ip_clone, &mut fluxo).await;

                   pb.suspend(|| {
                       let alerta = format!("[+] Porta {} ABERTA | Serviço: {}", porta, servico_detectado);
                       println!("{}", alerta.green().bold());
                   });

                   let mut dados = lista_resultados.lock().unwrap();
                   dados.push(ResultadoPorta {
                       ip: ip_clone,
                       porta,
                       status: "Aberta".to_string(),
                       servico: servico_detectado,
                   });
               }

               pb.inc(1);
           });

           tarefas.push(tarefa);
       }
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

