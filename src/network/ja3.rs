use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{Duration, timeout};
use tracing::debug;

#[derive(Debug, Clone, PartialEq)]
pub struct Ja3sInfo {
    pub hash: String,
    pub versao_tls: u16,
    pub cipher: u16,
    pub extensoes: Vec<u16>,
}

// Gerador pseudo-aleatório simples (xorshift). Suficiente aqui porque não
// completamos o handshake de verdade — só precisamos de bytes plausíveis
// pra preencher random/key_share do ClientHello.
static SEMENTE: AtomicU64 = AtomicU64::new(0);

fn proximo_byte_pseudo_aleatorio() -> u8 {
    let mut seed = SEMENTE.load(Ordering::Relaxed);
    if seed == 0 {
        seed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64
            | 1;
    }
    seed ^= seed << 13;
    seed ^= seed >> 7;
    seed ^= seed << 17;
    SEMENTE.store(seed, Ordering::Relaxed);
    (seed & 0xff) as u8
}

fn bytes_pseudo_aleatorios(n: usize) -> Vec<u8> {
    (0..n).map(|_| proximo_byte_pseudo_aleatorio()).collect()
}

fn u16be(v: u16) -> [u8; 2] {
    v.to_be_bytes()
}

fn montar_extensao(tipo: u16, dados: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(4 + dados.len());
    buf.extend_from_slice(&u16be(tipo));
    buf.extend_from_slice(&u16be(dados.len() as u16));
    buf.extend_from_slice(dados);
    buf
}

/// Monta um ClientHello genérico com extensões comuns de clientes modernos
/// (SNI, supported_groups, ALPN, supported_versions, key_share, etc.),
/// suficiente para provocar um ServerHello completo de servidores TLS 1.2/1.3.
fn construir_client_hello(sni: &str) -> Vec<u8> {
    let mut corpo = Vec::new();

    corpo.extend_from_slice(&[0x03, 0x03]); // client_version legado
    corpo.extend_from_slice(&bytes_pseudo_aleatorios(32)); // random
    corpo.push(0x00); // session_id vazio

    let cipher_suites: [u16; 14] = [
        0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014,
        0x009c, 0x009d, 0x002f,
    ];
    corpo.extend_from_slice(&u16be((cipher_suites.len() * 2) as u16));
    for cs in cipher_suites {
        corpo.extend_from_slice(&u16be(cs));
    }

    corpo.push(0x01); // compression_methods_length
    corpo.push(0x00); // null

    let mut extensoes = Vec::new();

    // server_name (SNI)
    {
        let nome = sni.as_bytes();
        let mut lista_nomes = vec![0x00];
        lista_nomes.extend_from_slice(&u16be(nome.len() as u16));
        lista_nomes.extend_from_slice(nome);

        let mut dados = Vec::new();
        dados.extend_from_slice(&u16be(lista_nomes.len() as u16));
        dados.extend_from_slice(&lista_nomes);
        extensoes.extend_from_slice(&montar_extensao(0x0000, &dados));
    }

    // supported_groups
    {
        let grupos: [u16; 3] = [0x001d, 0x0017, 0x0018];
        let mut dados = Vec::new();
        dados.extend_from_slice(&u16be((grupos.len() * 2) as u16));
        for g in grupos {
            dados.extend_from_slice(&u16be(g));
        }
        extensoes.extend_from_slice(&montar_extensao(0x000a, &dados));
    }

    // ec_point_formats
    extensoes.extend_from_slice(&montar_extensao(0x000b, &[0x01, 0x00]));

    // signature_algorithms
    {
        let algos: [u16; 6] = [0x0403, 0x0503, 0x0603, 0x0804, 0x0805, 0x0806];
        let mut dados = Vec::new();
        dados.extend_from_slice(&u16be((algos.len() * 2) as u16));
        for a in algos {
            dados.extend_from_slice(&u16be(a));
        }
        extensoes.extend_from_slice(&montar_extensao(0x000d, &dados));
    }

    // ALPN
    {
        let protocolos: [&[u8]; 2] = [b"h2", b"http/1.1"];
        let mut lista = Vec::new();
        for p in protocolos {
            lista.push(p.len() as u8);
            lista.extend_from_slice(p);
        }
        let mut dados = Vec::new();
        dados.extend_from_slice(&u16be(lista.len() as u16));
        dados.extend_from_slice(&lista);
        extensoes.extend_from_slice(&montar_extensao(0x0010, &dados));
    }

    // supported_versions
    {
        let versoes: [u16; 2] = [0x0304, 0x0303];
        let mut dados = vec![(versoes.len() * 2) as u8];
        for v in versoes {
            dados.extend_from_slice(&u16be(v));
        }
        extensoes.extend_from_slice(&montar_extensao(0x002b, &dados));
    }

    // key_share (x25519)
    {
        let chave_publica = bytes_pseudo_aleatorios(32);
        let mut entrada = Vec::new();
        entrada.extend_from_slice(&u16be(0x001d));
        entrada.extend_from_slice(&u16be(chave_publica.len() as u16));
        entrada.extend_from_slice(&chave_publica);

        let mut dados = Vec::new();
        dados.extend_from_slice(&u16be(entrada.len() as u16));
        dados.extend_from_slice(&entrada);
        extensoes.extend_from_slice(&montar_extensao(0x0033, &dados));
    }

    // psk_key_exchange_modes
    extensoes.extend_from_slice(&montar_extensao(0x002d, &[0x01, 0x01]));

    corpo.extend_from_slice(&u16be(extensoes.len() as u16));
    corpo.extend_from_slice(&extensoes);

    let mut handshake = Vec::with_capacity(4 + corpo.len());
    handshake.push(0x01); // ClientHello
    let tam = corpo.len();
    handshake.push(((tam >> 16) & 0xff) as u8);
    handshake.push(((tam >> 8) & 0xff) as u8);
    handshake.push((tam & 0xff) as u8);
    handshake.extend_from_slice(&corpo);

    let mut record = Vec::with_capacity(5 + handshake.len());
    record.push(0x16); // handshake
    record.push(0x03);
    record.push(0x01);
    record.extend_from_slice(&u16be(handshake.len() as u16));
    record.extend_from_slice(&handshake);

    record
}

/// Extrai versão, cipher e extensões (na ordem recebida) do corpo de um
/// ServerHello, já sem o header de handshake (tipo + tamanho de 3 bytes).
fn parsear_server_hello(corpo: &[u8]) -> Option<(u16, u16, Vec<u16>)> {
    if corpo.len() < 2 + 32 + 1 {
        return None;
    }
    let mut pos = 0;

    let versao = u16::from_be_bytes([corpo[pos], corpo[pos + 1]]);
    pos += 2;
    pos += 32; // random

    let session_id_len = *corpo.get(pos)? as usize;
    pos += 1 + session_id_len;

    if corpo.len() < pos + 2 {
        return None;
    }
    let cipher = u16::from_be_bytes([corpo[pos], corpo[pos + 1]]);
    pos += 2;
    pos += 1; // compression_method

    let mut extensoes = Vec::new();

    if corpo.len() >= pos + 2 {
        let extensoes_len = u16::from_be_bytes([corpo[pos], corpo[pos + 1]]) as usize;
        pos += 2;
        let fim_extensoes = (pos + extensoes_len).min(corpo.len());

        while pos + 4 <= fim_extensoes {
            let tipo_ext = u16::from_be_bytes([corpo[pos], corpo[pos + 1]]);
            let tam_ext = u16::from_be_bytes([corpo[pos + 2], corpo[pos + 3]]) as usize;
            extensoes.push(tipo_ext);
            pos += 4 + tam_ext;
        }
    }

    Some((versao, cipher, extensoes))
}

fn montar_hash_ja3s(versao: u16, cipher: u16, extensoes: &[u16]) -> String {
    let ext_str = extensoes
        .iter()
        .map(|e| e.to_string())
        .collect::<Vec<_>>()
        .join("-");

    let ja3s_string = format!("{},{},{}", versao, cipher, ext_str);
    format!("{:x}", md5::compute(ja3s_string.as_bytes()))
}

pub async fn fingerprint_ja3s(ip: &str, porta: u16, timeout_ms: u64) -> Option<Ja3sInfo> {
    let endereco = format!("{}:{}", ip, porta);
    let d_timeout = Duration::from_millis(timeout_ms);

    let mut fluxo = match timeout(d_timeout, TcpStream::connect(&endereco)).await {
        Ok(Ok(f)) => f,
        _ => {
            debug!(ip, porta, "Falha ao conectar para JA3S fingerprint.");
            return None;
        }
    };

    let client_hello = construir_client_hello(ip);

    if timeout(d_timeout, fluxo.write_all(&client_hello))
        .await
        .is_err()
    {
        debug!(ip, porta, "Falha ao enviar ClientHello para JA3S.");
        return None;
    }

    let mut header_record = [0u8; 5];
    if timeout(d_timeout, fluxo.read_exact(&mut header_record))
        .await
        .is_err()
    {
        debug!(ip, porta, "Sem resposta ao ClientHello (JA3S).");
        return None;
    }

    if header_record[0] != 0x16 {
        debug!(ip, porta, "Resposta não é um handshake TLS (JA3S).");
        return None;
    }

    let tam_record = u16::from_be_bytes([header_record[3], header_record[4]]) as usize;
    let mut corpo_record = vec![0u8; tam_record];
    if timeout(d_timeout, fluxo.read_exact(&mut corpo_record))
        .await
        .is_err()
    {
        debug!(ip, porta, "Corpo do ServerHello incompleto (JA3S).");
        return None;
    }

    if corpo_record.len() < 4 || corpo_record[0] != 0x02 {
        debug!(ip, porta, "Handshake recebido não é ServerHello (JA3S).");
        return None;
    }

    let tam_handshake = ((corpo_record[1] as usize) << 16)
        | ((corpo_record[2] as usize) << 8)
        | corpo_record[3] as usize;
    let fim = (4 + tam_handshake).min(corpo_record.len());
    let corpo_handshake = &corpo_record[4..fim];

    let (versao, cipher, extensoes) = parsear_server_hello(corpo_handshake)?;
    let hash = montar_hash_ja3s(versao, cipher, &extensoes);

    debug!(ip, porta, hash = %hash, "JA3S calculado com sucesso.");

    Some(Ja3sInfo {
        hash,
        versao_tls: versao,
        cipher,
        extensoes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_hello_comeca_com_record_handshake() {
        let ch = construir_client_hello("example.com");
        assert_eq!(ch[0], 0x16);
        assert_eq!(ch[5], 0x01);
    }

    #[test]
    fn test_client_hello_contem_sni() {
        let ch = construir_client_hello("meusite.com");
        let texto = String::from_utf8_lossy(&ch);
        assert!(texto.contains("meusite.com"));
    }

    #[test]
    fn test_parsear_server_hello_basico() {
        let mut corpo = Vec::new();
        corpo.extend_from_slice(&[0x03, 0x03]);
        corpo.extend_from_slice(&[0u8; 32]);
        corpo.push(0x00);
        corpo.extend_from_slice(&[0xc0, 0x2f]);
        corpo.push(0x00);
        corpo.extend_from_slice(&[0x00, 0x00]);

        let (versao, cipher, extensoes) = parsear_server_hello(&corpo).unwrap();
        assert_eq!(versao, 0x0303);
        assert_eq!(cipher, 0xc02f);
        assert!(extensoes.is_empty());
    }

    #[test]
    fn test_parsear_server_hello_com_extensoes() {
        let mut corpo = Vec::new();
        corpo.extend_from_slice(&[0x03, 0x04]);
        corpo.extend_from_slice(&[0u8; 32]);
        corpo.push(0x00);
        corpo.extend_from_slice(&[0x13, 0x01]);
        corpo.push(0x00);

        let mut ext = vec![0x00, 0x2b, 0x00, 0x02, 0x03, 0x04];
        ext.extend_from_slice(&[0x00, 0x33, 0x00, 0x00]);

        corpo.extend_from_slice(&u16be(ext.len() as u16));
        corpo.extend_from_slice(&ext);

        let (versao, cipher, extensoes) = parsear_server_hello(&corpo).unwrap();
        assert_eq!(versao, 0x0304);
        assert_eq!(cipher, 0x1301);
        assert_eq!(extensoes, vec![0x002b, 0x0033]);
    }

    #[test]
    fn test_hash_ja3s_deterministico() {
        let h1 = montar_hash_ja3s(0x0303, 0xc02f, &[0x002b, 0x0033]);
        let h2 = montar_hash_ja3s(0x0303, 0xc02f, &[0x002b, 0x0033]);
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 32);
    }

    #[test]
    fn test_hash_ja3s_muda_com_ordem_diferente() {
        let h1 = montar_hash_ja3s(0x0303, 0xc02f, &[0x002b, 0x0033]);
        let h2 = montar_hash_ja3s(0x0303, 0xc02f, &[0x0033, 0x002b]);
        assert_ne!(h1, h2);
    }
}
