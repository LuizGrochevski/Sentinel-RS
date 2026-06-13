use pnet::datalink;
use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::{Ipv4Flags, MutableIpv4Packet};
use pnet::packet::tcp::{MutableTcpPacket, TcpFlags, TcpPacket};
use pnet::packet::{MutablePacket, Packet};
use pnet::transport::{
    self, TransportChannelType, TransportProtocol,
};
use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;
use tracing::{debug, warn};

const TCP_HEADER_LEN: usize = 20;
const IPV4_HEADER_LEN: usize = 20;

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

    let src_porta: u16 = 49152 + (porta % 16383);

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

    debug!(ip = %dst_ip, porta, "Pacote SYN enviado.");

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
}
