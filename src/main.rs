use tokio::net::TcpStream;
use tokio::time::{timeout, Duration};
use std::sync::Arc;
use tokio::sync::Semaphore;
use std::io::{self, Write};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use std::fs::File;
use serde::Serialize;
use std::sync::Mutex;
use clap::Parser;

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
        eprintln!("Erro: O formato das portas deve ser INICIO-FIM (ex: -p 1-1000)");
        std::process::exit(1);
    }

    let porta_inicial: u16 = partes_porta[0].parse().expect("Porta inicial inválida");
    let porta_final: u16 = partes_porta[1].parse().expect("Porta final inválida");

    let semaforo = Arc::new(Semaphore::new(limite_threads));
    let resultados_compartilhados = Arc::new(Mutex::new(Vec::new()));

    let portas = porta_inicial..=porta_final;
    let total_portas = porta_final - porta_inicial + 1;
    let mut escaneadas = 0;

    println!("🛡 Sentinel-RS iniciado!");
    println!("Alvo: {}", ip_alvo);
    println!("Intervalo: {} até {}", porta_inicial, porta_final);
    println!("Concorrência máxima: {} conexões simultâneas\n", limite_threads);

    let mut tarefas = vec![];

    for porta in portas {
        let permissao = Arc::clone(&semaforo);
        let ip = ip_alvo.clone();
        let lista_resultados = Arc::clone(&resultados_compartilhados);
        escaneadas += 1;

        println!("\rEscaneando: {}/{} portas...", escaneadas, total_portas);
        io::stdout().flush().unwrap();

        let tarefa = tokio::spawn(async move {
            let _guarda = permissao.acquire().await.unwrap();
            let endereco = format!("{}:{}", ip, porta);

            if let Ok(Ok(mut fluxo)) = timeout(Duration::from_secs(1), TcpStream::connect(&endereco)).await {
                let mut buffer = [0; 128];

                let requisicao = format!("HEAD / HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n", ip);
                let _ = fluxo.write_all(requisicao.as_bytes()).await;

                let servico_detectado = match timeout(Duration::from_secs(2), fluxo.read(&mut buffer)).await {
                    Ok(Ok(bytes_lidos)) if bytes_lidos > 0 => {
                        let banner = String::from_utf8_lossy(&buffer[..bytes_lidos]);
                        banner.lines().next().unwrap_or("").trim().to_string()
                    }
                    _ => "Desconhecido".to_string(),
                };

                println!("\r[+] Porta {} ABERTA | Serviço: {}", porta, servico_detectado);

                let mut dados = lista_resultados.lock().unwrap();
                dados.push(ResultadoPorta {
                    porta,
                    status: "Aberta".to_string(),
                    servico: servico_detectado,
                });
            }
        });

        tarefas.push(tarefa);
    }

    for t in tarefas {
        let _ = t.await;
    }

    println!("Scan finalizado! Gerando relatório...");

    let dados_finais = resultados_compartilhados.lock().unwrap();
    
    if !dados_finais.is_empty() {
        let arquivo = File::create("relatorio.json").expect("Não foi possível criar o arquivo");
        serde_json::to_writer_pretty(arquivo, &*dados_finais).expect("Erro ao escrever o JSON");
        println!("💾 Relatório salvo com sucesso em 'relatorio.json'!");
    } else {
        println!("Nenhuma porta aberta encontrada para gerar o relatório.");
    }
}

