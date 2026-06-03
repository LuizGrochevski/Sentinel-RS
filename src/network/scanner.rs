use anyhow::{Context, Result};
use colored::*;
use indicatif::{ProgressBar, ProgressStyle};
use ipnet::IpNet;
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio::sync::Semaphore;
use tokio::time::{Duration, timeout};
use tracing::{debug, warn};

use crate::cli::Cli;
use crate::models::{ResultadoPorta, TrabalhoScan};
use crate::network::fingerprint::detectar_servico;
use crate::network::ping::verificar_host_ativo;

pub async fn executar_scan(
    args: &Cli,
    cancelamento: Arc<tokio::sync::Notify>,
) -> Result<Vec<ResultadoPorta>> {
    let limite_threads = args.threads;

    let mut lista_portas: Vec<u16> = Vec::new();

    for parte in args.ports.split(',') {
        let parte_limpa = parte.trim();
        if parte_limpa.is_empty() { continue; }

        if parte_limpa.contains('-') {
            let intervalo: Vec<&str> = parte_limpa.split('-').collect();
            if intervalo.len() != 2 {
                anyhow::bail!("Formato de intervalo de portas inválido: {}", parte_limpa);
            }
            let inicio: u16 = intervalo[0].parse().context("Porta inicial inválida no intervalo")?;
            let fim: u16 = intervalo[1].parse().context("Porta final inválida no intervalo")?;

            if inicio > fim {
                anyhow::bail!("A porta inicial {} não pode ser maior que a final {}!", inicio, fim);
            }
            for p in inicio..=fim {
                lista_portas.push(p);
            }
        } else {
            let porta_unica: u16 = parte_limpa.parse().context("Número de porta inválido")?;
            lista_portas.push(porta_unica);
        }
    }

    lista_portas.sort_unstable();
    lista_portas.dedup();

    if lista_portas.is_empty() {
        anyhow::bail!("Nenhuma porta válida foi especificada!");
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

    let resultados_compartilhados = Arc::new(Mutex::new(Vec::new()));

    let protocolo_texto = if args.udp { "UDP (Datagramas)" } else { "TCP (Conexões)" };

    println!("{}", "🛡 Sentinel-RS iniciado!".blue().bold());
    println!("{} {}", "Protocolo:".cyan(), protocolo_texto.yellow());
    println!("{} {}", "Alvo especificado:".cyan(), args.target);
    println!("{} {}", "Total de IPs para analisar:".cyan(), lista_ips.len().to_string().yellow());
    println!("{} {}", "Total de portas por host:".cyan(), lista_portas.len().to_string().yellow());
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

    let args_proprio: Cli = (*args).clone();
    let args_compartilhado = Arc::new(args_proprio);

    for ip in lista_ips {
        let sem = Arc::clone(&semaforo_ping);
        let ativos_clone = Arc::clone(&ips_ativos_compartilhados);
        let ip_str = ip.to_string();
        let timeout_ms = args_compartilhado.timeout;

        tarefas_ping.push(tokio::spawn(async move {
            if let Ok(_guarda) = sem.acquire().await {
                if verificar_host_ativo(&ip_str, timeout_ms).await {
                    let mut ativos = ativos_clone.lock().await;
                    ativos.push(ip_str);
                }
            }
        }));
    }

        for t in tarefas_ping { let _ = t.await; }

    let ips_encontrados = {
        let guard = ips_ativos_compartilhados.lock().await;
        guard.clone()
    };

    let mut mapeamento_hosts_completo = std::collections::HashMap::new();

    if args_compartilhado.reverse_dns {
        spinner_hosts.set_message(
            "Resolvendo hostnames dos alvos ativos em paralelo..."
                .bright_black()
                .to_string(),
        );

        let mut tarefas_dns = vec![];
        for ip in &ips_encontrados {
            let ip_clone = ip.clone();
            let timeout_ms = args_compartilhado.timeout;
            tarefas_dns.push(tokio::spawn(async move {
                let hostname =
                    crate::network::dns::resolver_hostname_reverso(&ip_clone, timeout_ms).await;
                (ip_clone, hostname)
            }));
        }

        for t in tarefas_dns {
            if let Ok((ip_original, hostname)) = t.await {
                mapeamento_hosts_completo.insert(ip_original, hostname);
            }
        }

        for ip in &ips_encontrados {
            mapeamento_hosts_completo.entry(ip.clone()).or_insert(None);
        }
    } else {
        spinner_hosts.set_message(
            "Reverse DNS desativado; usando IPs puros."
                .bright_black()
                .to_string(),
        );
        for ip in &ips_encontrados {
            mapeamento_hosts_completo.insert(ip.clone(), None);
        }
    }

    spinner_hosts.finish_and_clear();
    println!(
        "🔍 Mapeamento concluído: {} hosts encontrados.",
        mapeamento_hosts_completo.len().to_string().green().bold()
    );

    if ips_encontrados.is_empty() {
        warn!("Nenhum dispositivo online encontrado. Abortando scan.");
        return Ok(Vec::new());
    }

    let total_tarefas_globais = (ips_encontrados.len() * lista_portas.len()) as u64;

    let barra = ProgressBar::new(total_tarefas_globais);
    barra.set_style(
       ProgressStyle::default_bar()
          .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} portas ({eta})")
          .unwrap()
          .progress_chars("#>-"),
    );

    let barra_compartilhada = Arc::new(barra);

    let (tx, rx) = tokio::sync::mpsc::channel::<TrabalhoScan>(10000);
    let rx_compartilhado = Arc::new(Mutex::new(rx));

    let rx_monitor = Arc::clone(&rx_compartilhado);
    tokio::spawn(async move {
        cancelamento.notified().await;
        let mut guard = rx_monitor.lock().await;
        guard.close();
    });

    let mut lista_workers = vec![];

    for _ in 0..limite_threads {
        let rx_clone = Arc::clone(&rx_compartilhado);
        let lista_resultados = Arc::clone(&resultados_compartilhados);
        let pb = Arc::clone(&barra_compartilhada);
        let args_worker_clone = Arc::clone(&args_compartilhado);

        let worker = tokio::spawn(async move {
            while let Some(trabalho) = {
                let mut guard = rx_clone.lock().await;
                guard.recv().await
            } {
                let endereco = format!("{}:{}", trabalho.ip, trabalho.porta);
                let alvo_exibicao = trabalho.display_name.as_deref().unwrap_or(&trabalho.ip);
                debug!("Worker processando alvo: {}", endereco);

                let mut servico_detectado = String::new();
                let mut encontrou = false;

                if args_worker_clone.udp {
                    let resultado_udp = crate::network::udp::escanear_porta_udp(
                        &trabalho.ip,
                        trabalho.porta,
                        args_worker_clone.timeout,
                    )
                    .await;

                    if resultado_udp != "Fechada"
                        && !resultado_udp.contains("Falha")
                        && !resultado_udp.contains("Erro")
                    {
                        encontrou = true;
                        servico_detectado = resultado_udp;
                    }
                } else {
                    let mut conectado = false;
                    let mut fluxo_final = None;

                    for tentativa in 0..args_worker_clone.retries {
                        if let Ok(Ok(fluxo)) = timeout(
                            Duration::from_millis(args_worker_clone.timeout),
                            TcpStream::connect(&endereco),
                        )
                        .await
                        {
                            conectado = true;
                            fluxo_final = Some(fluxo);
                            break;
                        }
                        if tentativa + 1 < args_worker_clone.retries {
                            tokio::time::sleep(Duration::from_millis(100)).await;
                        }
                    }

                    if conectado {
                        encontrou = true;
                        let mut fluxo = fluxo_final.unwrap();
                        servico_detectado = detectar_servico(
                            trabalho.porta,
                            &trabalho.ip,
                            &mut fluxo,
                            args_worker_clone.timeout,
                        )
                        .await;
                    }
                }

                if encontrou {
                    let protocolo_tag = if args_worker_clone.udp { "UDP" } else { "TCP" };

                    pb.suspend(|| {
                        let alerta = format!(
                            "[+] Alvo {} | Porta {}/{} ABERTA | Status/Serviço: {}",
                            alvo_exibicao, trabalho.porta, protocolo_tag, servico_detectado
                        );

                        if args_worker_clone.udp {
                            println!("{}", alerta.magenta().bold());
                        } else {
                            println!("{}", alerta.green().bold());
                        }

                        if let Some(vuln) =
                            crate::models::checar_vulnerabilidades(&servico_detectado)
                        {
                            let msg_vuln = format!(
                                "    ⚠️  [PERIGO - {}] {} -> {}",
                                vuln.severidade, vuln.cve, vuln.descricao
                            );
                            if vuln.severidade == "CRÍTICA" {
                                println!("{}", msg_vuln.red().bold().blink());
                            } else {
                                println!("{}", msg_vuln.yellow().bold());
                            }
                        }
                    });

                    let mut dados = lista_resultados.lock().await;
                    dados.push(ResultadoPorta {
                        ip: trabalho.ip.clone(),
                        hostname: trabalho.display_name.clone(),
                        porta: trabalho.porta,
                        status: format!("Aberta ({})", protocolo_tag),
                        servico: servico_detectado,
                    });
                }
                pb.inc(1);
            }
        });

        lista_workers.push(worker);
    }

    for (ip_original, hostname) in mapeamento_hosts_completo {
        for porta in &lista_portas {
            let trabalho = TrabalhoScan {
                ip: ip_original.clone(),
                display_name: hostname.clone(),
                porta: *porta,
            };
            if tx.send(trabalho).await.is_err() {
                break;
            }
        }
    }

    drop(tx);

    for w in lista_workers {
        let _ = w.await;
    }

    barra_compartilhada.finish_and_clear();

    let dados_finais = match Arc::try_unwrap(resultados_compartilhados) {
        Ok(mutex) => mutex.into_inner(),
        Err(arc) => arc.lock().await.clone(),
    };

    Ok(dados_finais)
}