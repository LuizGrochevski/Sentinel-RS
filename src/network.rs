use tokio::net::TcpStream;
use tokio::time::{timeout, Duration};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Semaphore;
use tokio::sync::Mutex;
use std::sync::Arc;
use std::net::IpAddr;
use std::str::FromStr;
use ipnet::IpNet;
use colored::*;
use indicatif::{ProgressBar, ProgressStyle};
use anyhow::{Context, Result};

use crate::reports::ResultadoPorta;
use crate::cli::Cli;

pub async fn verificar_host_ativo(ip: &str) -> bool {
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

pub async fn detectar_servico(porta: u16, ip: &str, fluxo: &mut TcpStream) -> String {
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

        3306 => {
            if let Ok(Ok(bytes_lidos)) = timeout(Duration::from_secs(2), fluxo.read(&mut buffer)).await {
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
                if let Ok(Ok(bytes_lidos)) = timeout(Duration::from_secs(1), fluxo.read(&mut buffer)).await {
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

pub async fn executar_scan(args: &Cli) -> Result<Vec<ResultadoPorta>> {
    let limite_threads = args.threads;

    let partes_porta: Vec<&str> = args.ports.split('-').collect();
    if partes_porta.len() != 2 {
        anyhow::bail!("O formato das portas deve ser INICIO-FIM (ex: -p 1-1000)");
    }

    let porta_inicial: u16 = partes_porta[0].parse()
        .context("Falha ao interpretar a porta inicial. Use números válidos.")?;
        
    let porta_final: u16 = partes_porta[1].parse()
        .context("Falha ao interpretar a porta final. Use números válidos.")?;

    if porta_inicial > porta_final {
        anyhow::bail!("A porta inicial não pode ser maior que a porta final!");
    }

    let mut lista_ips: Vec<IpAddr> = Vec::new();
    if let Ok(rede) = IpNet::from_str(&args.target) {
        for ip in rede.hosts() {
            lista_ips.push(ip);
        }
    } else {
        let ip_unico = IpAddr::from_str(&args.target)
            .context("Alvo inválido! Especifique um IP válido ou bloco CIDR.")?;
        lista_ips.push(ip_unico);
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
            if let Ok(_guarda) = sem.acquire().await {
                if verificar_host_ativo(&ip_str).await {
                    let mut ativos = ativos_clone.lock().await;
                    ativos.push(ip_str);
                }
            }
        }));
    }

    for t in tarefas_ping { let _ = t.await; }

    let ips_ativos = {
        let guard = ips_ativos_compartilhados.lock().await;
        guard.clone()
    };

    spinner_hosts.finish_and_clear();
    println!("🔍 Mapeamento concluído: {} hosts encontrados.", ips_ativos.len().to_string().green().bold());

    if ips_ativos.is_empty() {
        println!("{}", "Nenhum dispositivo online encontrado. Abortando scan.".yellow());
        return Ok(Vec::new());
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

    for ip in ips_ativos {
       for porta in porta_inicial..=porta_final {
           let permissao = Arc::clone(&semaforo);
           let lista_resultados = Arc::clone(&resultados_compartilhados);
           let pb = Arc::clone(&barra_compartilhada);
           let ip_clone = ip.clone();

           let tarefa = tokio::spawn(async move {
              if let Ok(_guarda) = permissao.acquire().await {
                  let endereco = format!("{}:{}", ip_clone, porta);

                  if let Ok(Ok(mut fluxo)) = timeout(Duration::from_secs(1), TcpStream::connect(&endereco)).await {
                       let servico_detectado = detectar_servico(porta, &ip_clone, &mut fluxo).await;

                       pb.suspend(|| {
                           let alerta = format!("[+] Porta {} ABERTA | Serviço: {}", porta, servico_detectado);
                           println!("{}", alerta.green().bold());
                       });

                       let mut dados = lista_resultados.lock().await;
                       dados.push(ResultadoPorta {
                           ip: ip_clone,
                           porta,
                           status: "Aberta".to_string(),
                           servico: servico_detectado,
                       });
                   }
                   pb.inc(1);
              }
           });

           tarefas.push(tarefa);
       }
    }
    
    for t in tarefas { let _ = t.await; }
    barra_compartilhada.finish_and_clear();

    let dados_finais = resultados_compartilhados.lock().await;
    Ok(dados_finais.clone())
}