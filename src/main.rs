mod cli;
mod network;
mod reports;

use clap::Parser;
use anyhow::Result;
use colored::*;

use cli::Cli;
use network::executar_scan;
use reports::gerar_relatorios;

#[tokio::main]
async fn main() -> Result<()> {
    let args = Cli::parse();

    let dados_finais = executar_scan(&args).await?;

    if !dados_finais.is_empty() {
        println!("\n\n{}", "Scan finalizado! Gerando relatório...".yellow());
        gerar_relatorios(&dados_finais);
    } else {
        println!("\n{}", "Nenhuma porta aberta encontrada. Relatórios omitidos.".red());
    }

    Ok(())
}