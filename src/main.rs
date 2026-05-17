use tokio::net::TcpStream;
use tokio::time::{timeout, Duration};
use std::sync::Arc;
use tokio::sync::Semaphore;
use std::io::{self, Write};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use std::fs::File;
use serde::Serialize;
use std::sync::Mutex;

#[derive(Serialize, Clone)]
struct ResultadoPorta {
    porta: u16,
    status: String,
    servico: String,
}

#[tokio::main]
async fn main() {
    let mut input_ip_alvo = String::new();
    let mut input_porta_inicio = String::new();
    let mut input_porta_fim = String::new();

    let semaforo = Arc::new(Semaphore::new(50));
    let resultados_compartilhados = Arc::new(Mutex::new(Vec::new()));

    println!("Digite o ip para o scan:");
    io::stdout().flush().unwrap();
    io::stdin().read_line(&mut input_ip_alvo).expect("Falha ao ler o input");
    let ip_alvo = input_ip_alvo.trim().to_string();

    println!("Digite a porta INICIAL:");
    io::stdout().flush().unwrap();
    io::stdin().read_line(&mut input_porta_inicio).expect("Falha ao ler a porta inicial");
    let porta_inicial: u16 = input_porta_inicio.trim().parse().expect("Digite um número válido!");

    println!("Digite a porta FINAL:");
    io::stdout().flush().unwrap();
    io::stdin().read_line(&mut input_porta_fim).expect("Falha ao ler a porta final");
    let porta_final: u16 = input_porta_fim.trim().parse().expect("Digite um número válido");

    let portas = porta_inicial..=porta_final;

    println!("Iniciando scan em {} (Portas {} até {})...", ip_alvo, porta_inicial, porta_final);

    let mut tarefas = vec![];

    let total_portas = porta_final - porta_inicial + 1;
    let mut escaneadas = 0;

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

