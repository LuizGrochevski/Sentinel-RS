mod cli;
mod network;
mod reports;
mod models;

use clap::Parser;
use cli::Cli;
use colored::Colorize;
use std::sync::Arc;
use tokio::sync::Notify;

#[tokio::main]
async fn main() {
    let args = Cli::parse();

    let token_cancelamento = Arc::new(Notify::new());
    let token_clone = Arc::clone(&token_cancelamento);

    tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            println!(
                "\n\n🛑 {} Interrupção detectada! Iniciando encerramento seguro...",
                "Ctrl+C:".red().bold()
            );
            token_clone.notify_waiters();
        }
    });

    match network::executar_scan(&args, token_cancelamento).await {
        Ok(resultados) => {
            if resultados.is_empty() {
                println!("{}", "Nenhum resultado capturado para exportar.".yellow());
                return;
            }

            println!("\nScan finalizado! Passando dados para o motor de relatórios...");
            
            reports::gerar_relatorios(&resultados);
        }
        Err(erro) => {
            eprintln!("❌ Erro crítico na execução do scanner: {}", erro);
        }
    }
}

