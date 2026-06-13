mod cli;
mod network;
mod reports;
mod models;

use clap::Parser;
use cli::Cli;
use std::sync::Arc;
use tokio::sync::Notify;
use std::fs::File;

use tracing::{info, warn, error};
use tracing_subscriber::{fmt, prelude::*, filter::LevelFilter};

#[tokio::main]
async fn main() {
    let args = Cli::parse();

    let _ = std::fs::create_dir_all("logs");
    let arquivo_log = File::create("logs/sentinel.log")
        .expect("Falha ao criar arquivo de auditoria de log");

    let nivel_console = if args.verbose {
        LevelFilter::DEBUG
    } else if args.stdout {
        LevelFilter::OFF
    } else {
        LevelFilter::INFO
    };

    let camada_console = fmt::layer()
        .with_target(false)
        .with_level(true)
        .with_writer(std::io::stderr)
        .with_filter(nivel_console);

    let camada_arquivo = fmt::layer()
        .with_target(true)
        .with_ansi(false)
        .with_writer(arquivo_log)
        .with_filter(LevelFilter::DEBUG);

    tracing_subscriber::registry()
        .with(camada_console)
        .with(camada_arquivo)
        .init();

    info!("Sentinel-RS inicializado com sucesso.");

    let token_cancelamento = Arc::new(Notify::new());
    let token_clone = Arc::clone(&token_cancelamento);

    tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            warn!("Interrupção detectada via Ctrl+C! Iniciando encerramento seguro...");
            token_clone.notify_waiters();
        }
    });

    match network::executar_scan(&args, token_cancelamento).await {
        Ok(resultados) => {
            if resultados.is_empty() {
                warn!("Nenhum resultado capturado para exportar.");
                return;
            }

            if args.stdout {
                match serde_json::to_string(&resultados) {
                    Ok(json) => println!("{}", json),
                    Err(e) => {
                        error!("Erro ao serializar JSON para stdout: {}", e);
                        std::process::exit(1);
                    }
                }
            } else {
                info!("Scan finalizado com sucesso! Passando dados para o motor de relatórios.");
                reports::gerar_relatorios(&resultados);
            }
        }
        Err(erro) => {
            error!("Erro crítico na execução do scanner: {}", erro);
        }
    }
}
