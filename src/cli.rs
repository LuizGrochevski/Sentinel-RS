use clap::Parser;

#[derive(Parser, Debug)]
#[command(
    name = "sentinel-rs",
    author = "Luiz Grochevski",
    version = "0.1.0",
    about = "Scanner de portas assíncron e ultra rápido"
)]

pub struct Cli {
    pub target: String,

    #[arg(short = 'p', long = "ports", default_value = "1-1000")]
    pub ports: String,

    #[arg(short = 't', long = "threads", default_value = "100")]
    pub threads: usize,
}
