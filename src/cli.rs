use clap::Parser;

#[derive(Parser, Debug, Clone)]
#[command(
    name = "sentinel-rs",
    author = "Luiz Grochevski",
    version = "0.1.0",
    about = "🛡️ Scanner de rede assíncrono de alta performance",
    long_about = "Sentinel-RS é um scanner de rede TCP/UDP/SYN construído em Rust com Tokio.\n\
                  Suporta CIDR, fingerprinting de serviços, TLS, DNS reverso e múltiplos\n\
                  formatos de relatório. Integra-se com a Netwatch-API via --stdout.\n\n\
                  Exemplos:\n  \
                  sentinel-rs 192.168.0.1 -p 22,80,443\n  \
                  sentinel-rs 192.168.0.0/24 -p 1-1000 --reverse-dns\n  \
                  sentinel-rs 192.168.0.1 -p 80,443 --stdout 2>/dev/null\n  \
                  sudo sentinel-rs 192.168.0.1 -p 22,80,443 --syn"
)]
pub struct Cli {
    /// IP, hostname ou bloco CIDR alvo (ex: 192.168.0.1, 192.168.0.0/24)
    pub target: String,

    /// Portas a escanear. Suporta lista e ranges (ex: 22,80,443 ou 1-1000)
    #[arg(short = 'p', long = "ports", default_value = "1-1000")]
    pub ports: String,

    /// Número máximo de conexões simultâneas
    #[arg(short = 't', long = "threads", default_value = "100")]
    pub threads: usize,

    /// Timeout em milissegundos por conexão
    #[arg(long, default_value_t = 100)]
    pub timeout: u64,

    /// Número de tentativas por porta antes de desistir
    #[arg(long, default_value_t = 1)]
    pub retries: usize,

    /// Ativa logs de debug detalhados
    #[arg(short, long)]
    pub verbose: bool,

    /// Usa protocolo UDP em vez de TCP
    #[arg(short, long)]
    pub udp: bool,

    /// Resolve hostnames via DNS reverso (PTR) para cada IP ativo
    #[arg(long = "reverse-dns")]
    pub reverse_dns: bool,

    /// Imprime resultado em JSON no stdout (silencia logs — ideal para pipelines)
    #[arg(long = "stdout")]
    pub stdout: bool,

    /// Usa SYN scan via raw sockets — mais furtivo (requer root ou CAP_NET_RAW)
    #[arg(long = "syn")]
    pub syn: bool,
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
        assert!(!args.syn);
    }

    #[test]
    fn test_threads_customizado() {
        let args = Cli::parse_from(["sentinel-rs", "10.0.0.1", "-t", "50"]);
        assert_eq!(args.threads, 50);
    }
}
