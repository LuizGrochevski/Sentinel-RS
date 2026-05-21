mod cli;
mod network;
mod reports;

use std::sync::Arc;
use std::sync::Mutex;
use std::str::FromStr;
use std::net::IpAddr;
use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use tokio::time::{timeout, Duration};
use ipnet::IpNet;
use clap::Parser;
use colored::*;
use indicatif::{ProgressBar, ProgressStyle};

use cli::Cli;
use network::{verificar_host_ativo, detectar_servico};
use reports::{ResultadoPorta, gerar_relatorios};


#[tokio::main]
async fn main() {
    let args = Cli::parse();
    let limite_threads = args.threads;

    let partes_porta: Vec<&str> = args.ports.split('-').collect();
    if partes_porta.len() != 2 {
        eprintln!("{}", "Erro: O formato das portas deve ser INICIO-FIM (ex: -p 1-1000)".red().bold());
        std::process::exit(1);
    }

    let porta_inicial: u16 = if let Ok(p) = partes_porta[0].parse() {
        p
    } else {
        eprintln!("{}: '{}'", "Erro: A porta inicial deve ser um número válido entre 1 e 65535".red().bold(), partes_porta[0]);
        std::process::exit(1);
    };

    let porta_final: u16 = if let Ok(p) = partes_porta[1].parse() {
        p
    } else {
        eprintln!("{}: '{}'", "Erro: A porta final deve ser um número válido entre 1 e 65535".red().bold(), partes_porta[1]);
        std::process::exit(1);
    };

    if porta_inicial > porta_final || porta_inicial == 0 {
        eprintln!("{}", "Erro: A porta inicial não pode ser maior que a porta final!".red().bold());
        std::process::exit(1);
    }

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
            if let Ok(_guarda) = sem.acquire().await {
                if verificar_host_ativo(&ip_str).await {
                    let mut ativos = ativos_clone.lock().unwrap();
                    ativos.push(ip_str);
                }
            }
        }));
    }
    
    for t in tarefas_ping { let _ = t.await; }

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
            if let Ok(_guarda) = permissao.acquire().await {
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
                }
            });

            tarefas.push(tarefa);
        }
    }
    
    for t in tarefas { let _ = t.await; }
    barra_compartilhada.finish_and_clear();

    println!("\n\n{}" ,"Scan finalizado! Gerando relatório...".yellow());

    if let Err(e) = std::fs::create_dir_all("reports") {
        eprintln!("{} {}", "Erro ao criar diretório de relatórios:".red(), e);
        std::process::exit(1);
    }

    let dados_finais = resultados_compartilhados.lock().unwrap();
    gerar_relatorios(&dados_finais);
    
}

