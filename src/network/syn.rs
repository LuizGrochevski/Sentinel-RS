use pnet::datalink;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::tcp::{MutableTcpPacket, TcpFlags, TcpPacket};
use pnet::packet::Packet;
use pnet::transport::{
    self, TransportChannelType, TransportProtocol,
};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicU16, Ordering};
use std::time::Duration;
use tracing::{debug, warn};

const TCP_HEADER_LEN: usize = 20;

/// Contador atômico global para portas de origem do SYN scan.
///
/// Por que isso existe: usar `49152 + (porta_destino % N)` faz duas portas de
/// destino diferentes colidirem na mesma porta de origem sempre que diferem por
/// um múltiplo de N (ex: portas 80 e 16463 com N=16383). Como o scanner roda
/// múltiplos workers concorrentes (ver arquitetura no README), isso causa troca
/// de respostas entre scans simultâneos — um SYN-ACK destinado ao worker da
/// porta 80 pode ser lido pelo worker da porta 16463.
///
/// Um contador atômico garante que cada chamada a `proxima_porta_origem()`
/// recebe uma porta diferente da anterior, mesmo sob alta concorrência,
/// eliminando a colisão determinística. O espaço de portas efêmeras
/// (49152–65535, ~16383 portas) ainda pode dar wrap sob volume extremo de
/// scans simultâneos, mas nesse ponto conexões antigas já tiveram tempo de
/// fechar — o mesmo trade-off que o próprio kernel faz ao reciclar portas
/// efêmeras.
static PROXIMA_PORTA: AtomicU16 = AtomicU16::new(0);

/// Faixa de portas efêmeras usada para origem do SYN scan (IANA dynamic range).
const PORTA_EFEMERA_BASE: u16 = 49152;
const PORTA_EFEMERA_RANGE: u16 = 65535 - PORTA_EFEMERA_BASE; // ~16383

/// Gera a próxima porta de origem de forma atômica e sequencial,
/// evitando colisões entre workers concorrentes do SYN scan.
fn proxima_porta_origem() -> u16 {
    let offset = PROXIMA_PORTA.fetch_add(1, Ordering::Relaxed) % PORTA_EFEMERA_RANGE;
    PORTA_EFEMERA_BASE + offset
}

#[derive(Debug, Clone, PartialEq)]
pub enum EstadoPortaSyn {
    Aberta,
    Fechada,
    Filtrada,
}

pub struct ResultadoSyn {
    pub porta: u16,
    pub estado: EstadoPortaSyn,
}

/// Verifica se o processo tem permissão para raw sockets
pub fn verificar_permissao_raw_socket() -> bool {
    match transport::transport_channel(
        1024,
        TransportChannelType::Layer4(TransportProtocol::Ipv4(
            IpNextHeaderProtocols::Tcp,
        )),
    ) {
        Ok(_) => true,
        Err(_) => false,
    }
}

/// Obtém o IP local da interface padrão
fn obter_ip_local() -> Option<Ipv4Addr> {
    for interface in datalink::interfaces() {
        if interface.is_up() && !interface.is_loopback() {
            for ip in &interface.ips {
                if let IpAddr::V4(ipv4) = ip.ip() {
                    if !ipv4.is_loopback() {
                        return Some(ipv4);
                    }
                }
            }
        }
    }
    None
}

/// Calcula checksum TCP
fn calcular_checksum_tcp(
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    tcp_packet: &[u8],
) -> u16 {
    let src = src_ip.octets();
    let dst = dst_ip.octets();
    let mut soma: u32 = 0;

    // Pseudo-header
    soma += ((src[0] as u32) << 8) | src[1] as u32;
    soma += ((src[2] as u32) << 8) | src[3] as u32;
    soma += ((dst[0] as u32) << 8) | dst[1] as u32;
    soma += ((dst[2] as u32) << 8) | dst[3] as u32;
    soma += 6u32; // protocolo TCP
    soma += tcp_packet.len() as u32;

    // Dados TCP
    let mut i = 0;
    while i + 1 < tcp_packet.len() {
        soma += ((tcp_packet[i] as u32) << 8) | tcp_packet[i + 1] as u32;
        i += 2;
    }
    if i < tcp_packet.len() {
        soma += (tcp_packet[i] as u32) << 8;
    }

    while soma >> 16 != 0 {
        soma = (soma & 0xFFFF) + (soma >> 16);
    }

    !(soma as u16)
}

/// Executa SYN scan em um único target/porta
pub async fn syn_scan_porta(
    dst_ip: Ipv4Addr,
    porta: u16,
    timeout_ms: u64,
) -> ResultadoSyn {
    let src_ip = match obter_ip_local() {
        Some(ip) => ip,
        None => {
            warn!("Não foi possível determinar o IP local para SYN scan.");
            return ResultadoSyn { porta, estado: EstadoPortaSyn::Filtrada };
        }
    };

    // Porta de origem única por chamada — evita colisão entre workers
    // concorrentes escaneando portas de destino diferentes (ver doc do
    // contador PROXIMA_PORTA acima).
    let src_porta: u16 = proxima_porta_origem();

    // Abre canal de transporte raw
    let (mut tx, mut rx) = match transport::transport_channel(
        65535,
        TransportChannelType::Layer4(TransportProtocol::Ipv4(
            IpNextHeaderProtocols::Tcp,
        )),
    ) {
        Ok(c) => c,
        Err(e) => {
            warn!(error = %e, "Falha ao abrir raw socket. Execute como root.");
            return ResultadoSyn { porta, estado: EstadoPortaSyn::Filtrada };
        }
    };

    // Monta pacote TCP SYN
    let mut tcp_buffer = vec![0u8; TCP_HEADER_LEN];
    {
        let mut tcp = MutableTcpPacket::new(&mut tcp_buffer).unwrap();
        tcp.set_source(src_porta);
        tcp.set_destination(porta);
        tcp.set_sequence(rand_seq());
        tcp.set_acknowledgement(0);
        tcp.set_data_offset(5);
        tcp.set_flags(TcpFlags::SYN);
        tcp.set_window(65535);
        tcp.set_urgent_ptr(0);
        let checksum = calcular_checksum_tcp(src_ip, dst_ip, tcp.packet());
        tcp.set_checksum(checksum);
    }

    let dst_addr = IpAddr::V4(dst_ip);
    if let Err(e) = tx.send_to(
        TcpPacket::new(&tcp_buffer).unwrap(),
        dst_addr,
    ) {
        warn!(error = %e, porta, "Falha ao enviar pacote SYN.");
        return ResultadoSyn { porta, estado: EstadoPortaSyn::Filtrada };
    }

    debug!(ip = %dst_ip, porta, src_porta, "Pacote SYN enviado.");

    // Aguarda resposta
    let deadline = std::time::Instant::now() + Duration::from_millis(timeout_ms);
    let mut iter = transport::tcp_packet_iter(&mut rx);

    loop {
        if std::time::Instant::now() > deadline {
            debug!(porta, "Timeout aguardando resposta SYN.");
            return ResultadoSyn { porta, estado: EstadoPortaSyn::Filtrada };
        }

        match iter.next_with_timeout(Duration::from_millis(100)) {
            Ok(Some((packet, addr))) => {
                if let IpAddr::V4(src) = addr {
                    if src != dst_ip {
                        continue;
                    }
                }

                // Filtra pacotes que não são resposta a ESTA porta de origem
                // específica — essencial agora que cada chamada usa uma porta
                // diferente, garante que não processamos resposta de outro worker.
                if packet.get_destination() != src_porta {
                    continue;
                }

                let flags = packet.get_flags();

                // SYN-ACK = porta aberta
                if flags & TcpFlags::SYN != 0 && flags & TcpFlags::ACK != 0 {
                    debug!(porta, "Recebido SYN-ACK — porta aberta.");
                    // Envia RST para fechar a conexão
                    let mut rst_buffer = vec![0u8; TCP_HEADER_LEN];
                    let mut rst = MutableTcpPacket::new(&mut rst_buffer).unwrap();
                    rst.set_source(src_porta);
                    rst.set_destination(porta);
                    rst.set_sequence(packet.get_acknowledgement());
                    rst.set_flags(TcpFlags::RST);
                    rst.set_data_offset(5);
                    rst.set_window(0);
                    let checksum = calcular_checksum_tcp(src_ip, dst_ip, rst.packet());
                    rst.set_checksum(checksum);
                    let _ = tx.send_to(TcpPacket::new(&rst_buffer).unwrap(), IpAddr::V4(dst_ip));
                    return ResultadoSyn { porta, estado: EstadoPortaSyn::Aberta };
                }

                // RST = porta fechada
                if flags & TcpFlags::RST != 0 {
                    debug!(porta, "Recebido RST — porta fechada.");
                    return ResultadoSyn { porta, estado: EstadoPortaSyn::Fechada };
                }
            }
            Ok(None) => continue,
            Err(_) => break,
        }
    }

    ResultadoSyn { porta, estado: EstadoPortaSyn::Filtrada }
}

fn rand_seq() -> u32 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .subsec_nanos()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_estado_porta_syn_eq() {
        assert_eq!(EstadoPortaSyn::Aberta, EstadoPortaSyn::Aberta);
        assert_ne!(EstadoPortaSyn::Aberta, EstadoPortaSyn::Fechada);
        assert_ne!(EstadoPortaSyn::Fechada, EstadoPortaSyn::Filtrada);
    }

    #[test]
    fn test_resultado_syn_struct() {
        let r = ResultadoSyn { porta: 80, estado: EstadoPortaSyn::Aberta };
        assert_eq!(r.porta, 80);
        assert_eq!(r.estado, EstadoPortaSyn::Aberta);
    }

    #[test]
    fn test_calcular_checksum_nao_zero() {
        let src = Ipv4Addr::new(192, 168, 0, 16);
        let dst = Ipv4Addr::new(192, 168, 0, 1);
        let dados = vec![0u8; 20];
        let checksum = calcular_checksum_tcp(src, dst, &dados);
        assert_ne!(checksum, 0);
    }

    #[test]
    fn test_rand_seq_nao_zero_geralmente() {
        let seq = rand_seq();
        // Não pode garantir != 0 mas testa que retorna u32
        let _: u32 = seq;
    }

    #[test]
    fn test_obter_ip_local_retorna_opcao() {
        // Só testa que a função não panica
        let _ip = obter_ip_local();
    }

    #[test]
    fn test_proxima_porta_origem_esta_na_faixa_efemera() {
        let porta = proxima_porta_origem();
        assert!(porta >= PORTA_EFEMERA_BASE);
        assert!(porta < 65535);
    }

    #[test]
    fn test_proxima_porta_origem_e_sequencial_sem_colisao_imediata() {
        // Duas chamadas consecutivas nunca devem repetir a mesma porta,
        // ao contrário do antigo cálculo `49152 + (porta % 16383)` que
        // colidia para portas de destino que diferiam por múltiplos de N.
        let p1 = proxima_porta_origem();
        let p2 = proxima_porta_origem();
        assert_ne!(p1, p2, "portas consecutivas não deveriam colidir");
    }

    #[test]
    fn test_proxima_porta_origem_concorrente_sem_colisao() {
        use std::collections::HashSet;
        use std::thread;

        // Simula concorrência real: várias threads pedindo portas ao mesmo
        // tempo, como os workers do scanner fazem. Coleta todas e garante
        // que não houve nenhuma duplicata.
        let handles: Vec<_> = (0..50)
            .map(|_| thread::spawn(proxima_porta_origem))
            .collect();

        let portas: Vec<u16> = handles
            .into_iter()
            .map(|h| h.join().unwrap())
            .collect();

        let unicas: HashSet<u16> = portas.iter().copied().collect();
        assert_eq!(
            portas.len(),
            unicas.len(),
            "contador atômico deveria garantir portas únicas sob concorrência"
        );
    }

    #[test]
    fn test_velha_formula_colidia_caso_documentado() {
        // Documenta o bug original para referência: com a fórmula antiga
        // `49152 + (porta % 16383)`, as portas de destino 80 e 16463
        // resultavam na MESMA porta de origem. Este teste apenas registra
        // o caso para histórico — a fórmula antiga não é mais usada.
        let formula_antiga = |porta: u16| -> u16 { 49152 + (porta % 16383) };
        assert_eq!(formula_antiga(80), formula_antiga(16463));
    }
}

