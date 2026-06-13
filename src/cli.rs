use clap::Parser;

#[derive(Parser, Debug, Clone)]
#[command(
    name = "sentinel-rs",
    author = "Luiz Grochevski",
    version = "0.1.0",
    about = "Scanner de portas assíncrono e ultra rápido"
)]
pub struct Cli {
    pub target: String,

    #[arg(short = 'p', long = "ports", default_value = "1-1000")]
    pub ports: String,

    #[arg(short = 't', long = "threads", default_value = "100")]
    pub threads: usize,

    #[arg(long, default_value_t = 100)]
    pub timeout: u64,

    #[arg(long, default_value_t = 1)]
    pub retries: usize,

    #[arg(short, long)]
    pub verbose: bool,

    #[arg(short, long)]
    pub udp: bool,

    #[arg(long = "reverse-dns")]
    pub reverse_dns: bool,

    /// Imprime o resultado em JSON no stdout em vez de salvar arquivos
    #[arg(long = "stdout")]
    pub stdout: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn test_args_basicos() {
        let args = Cli::parse_from(["sentinel-rs", "192.168.0.1", "-p", "80,443"]);
        assert_eq!(args.target, "192.168.0.1");
        assert_eq!(args.ports, "80,443");
        assert!(!args.udp);
        assert!(!args.verbose);
        assert!(!args.stdout);
    }

    #[test]
    fn test_flag_udp() {
        let args = Cli::parse_from(["sentinel-rs", "192.168.0.1", "-p", "53", "--udp"]);
        assert!(args.udp);
    }

    #[test]
    fn test_flag_stdout() {
        let args = Cli::parse_from(["sentinel-rs", "192.168.0.1", "-p", "80", "--stdout"]);
        assert!(args.stdout);
    }

    #[test]
    fn test_flag_verbose() {
        let args = Cli::parse_from(["sentinel-rs", "192.168.0.1", "-p", "80", "--verbose"]);
        assert!(args.verbose);
    }

    #[test]
    fn test_flag_reverse_dns() {
        let args = Cli::parse_from(["sentinel-rs", "192.168.0.1", "-p", "80", "--reverse-dns"]);
        assert!(args.reverse_dns);
    }

    #[test]
    fn test_defaults() {
        let args = Cli::parse_from(["sentinel-rs", "10.0.0.1"]);
        assert_eq!(args.threads, 100);
        assert_eq!(args.timeout, 100);
        assert_eq!(args.retries, 1);
        assert!(!args.stdout);
        assert!(!args.udp);
    }

    #[test]
    fn test_threads_customizado() {
        let args = Cli::parse_from(["sentinel-rs", "10.0.0.1", "-t", "50"]);
        assert_eq!(args.threads, 50);
    }
}
