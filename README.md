# Sentinel-RS 🛡️🦀

![Rust](https://img.shields.io/badge/Rust-000000?style=for-the-badge&logo=rust&logoColor=white)
![Tokio](https://img.shields.io/badge/Tokio-async-blue?style=for-the-badge)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Android%20(Termux)-green?style=for-the-badge)
![Tests](https://img.shields.io/badge/Tests-34%20passing-brightgreen?style=for-the-badge)
![License](https://img.shields.io/badge/License-Educational-orange?style=for-the-badge)

Sentinel-RS é uma ferramenta de network scanning desenvolvida em **Rust** com foco em concorrência assíncrona, performance e segurança. Arquitetada para rodar de forma eficiente inclusive em ambientes móveis via **Termux (Android/ARM)**, utilizando o runtime assíncrono do Tokio para gerenciar centenas de conexões simultâneas.

Integra-se nativamente com a **[Netwatch-API](https://github.com/LuizGrochevski/netwatch-api)** — uma REST API em Python/FastAPI que utiliza o Sentinel-RS como engine de scanning.

---

## 🚀 Funcionalidades

- 🔍 Scanner híbrido **TCP + UDP**
- ⚡ **SYN Scan** via raw sockets (requer root/CAP_NET_RAW)
- 🌐 Suporte a **ranges e parsing dinâmico de portas**
- 📡 Scanner **CIDR** para sub-redes inteiras
- 🖥️ Descoberta de hosts ativos
- 🔎 DNS reverso real via PTR (`--reverse-dns`)
- 🛠️ Fingerprinting de serviços com **base de 40+ assinaturas**
- 🔒 **TLS fingerprinting** — versão, cipher suite e informações de certificado
- ⚙️ Controle de concorrência com workers e semáforos
- ⏱️ Timeout configurável
- 📝 **Structured logging** com campos contextuais (`tracing`)
- 📊 Exportação de relatórios em **6 formatos**:
  - JSON, CSV, YAML, XML, Markdown
  - **Nmap XML** *(compatível com Metasploit, Burp Suite e outras ferramentas)*
- 🖨️ **Output JSON via `--stdout`** para integração com pipelines

---

## 🧠 Arquitetura

```
CIDR/IP
   ↓
Host Discovery (ping paralelo)
   ↓
Queue de Scanning (mpsc)
   ↓
Workers Concorrentes (Tokio)
   ├── TCP Connect Scan
   ├── SYN Scan (raw sockets)
   ├── UDP Scan
   ├── Service Fingerprinting (40+ assinaturas)
   └── TLS Fingerprinting (versão, cipher, certificado)
   ↓
Structured Logging (tracing)
   ↓
Exportação de Relatórios (JSON, CSV, YAML, XML, MD, Nmap XML)
```

---

## 🔗 Integração com Netwatch-API

O Sentinel-RS é usado como engine de scanning da **[Netwatch-API](https://github.com/LuizGrochevski/netwatch-api)**, uma REST API com autenticação JWT que expõe os resultados via HTTP.

```
POST /scan (Netwatch-API)
    │
    ▼
sentinel-rs --stdout (JSON limpo no stdout)
    │
    ▼
Resposta da API
```

```bash
# Uso direto com --stdout
./sentinel-rs 192.168.0.1 -p 22,80,443 --stdout 2>/dev/null
# Saída: [{"ip":"192.168.0.1","porta":80,"status":"Aberta (TCP)","servico":"HTTP"}]
```

---

## 🛠️ Tecnologias

| Tecnologia | Uso |
|---|---|
| Rust | Linguagem principal |
| Tokio | Runtime assíncrono |
| Tokio-Rustls | TLS assíncrono |
| pnet | Raw sockets para SYN scan |
| x509-parser | Parsing de certificados TLS |
| libc | DNS reverso via `getnameinfo` |
| serde / serde_json | Serialização JSON |
| serde_yaml | Serialização YAML |
| quick-xml | Serialização XML e Nmap XML |
| clap | CLI arguments |
| tracing | Structured logging |
| indicatif | Barra de progresso |

---

## 📦 Instalação

### Linux
```bash
git clone https://github.com/LuizGrochevski/Sentinel-RS.git
cd Sentinel-RS
cargo build --release
```

### Termux (Android/ARM)
```bash
pkg update && pkg upgrade
pkg install rust clang make git
git clone https://github.com/LuizGrochevski/Sentinel-RS.git
cd Sentinel-RS
ANDROID_API_LEVEL=24 cargo build --release
```

---

## 📄 Exemplos de uso

**TCP Scan**
```bash
./sentinel-rs 192.168.0.0/24 -p 22,80,443
```

**SYN Scan (requer root)**
```bash
sudo ./sentinel-rs 192.168.0.1 -p 22,80,443 --syn
```

**UDP Scan**
```bash
./sentinel-rs 192.168.0.1 --udp -p 53,1900
```

**Com Reverse DNS**
```bash
./sentinel-rs 192.168.0.0/24 -p 22,80,443 --reverse-dns
```

**Output JSON para pipelines**
```bash
./sentinel-rs 192.168.0.1 -p 80,443 --stdout 2>/dev/null | jq .
```

**Verbose Debug**
```bash
./sentinel-rs 192.168.0.1 -p 21-25,80,443 --verbose
```

---

## 📊 Exemplo de saída

```
INFO Sentinel-RS inicializado. version="0.1.0" target=192.168.0.1 protocol="tcp" stdout_mode=false
DEBUG Configuração carregada. ports=80,443,22 threads=100 timeout_ms=100 retries=1

🛡 Sentinel-RS iniciado!
Protocolo: TCP (Conexões)
Alvo especificado: 192.168.0.1
Total de IPs para analisar: 1
Total de portas por host: 3

🔍 Mapeamento concluído: 1 hosts encontrados.
[+] Alvo 192.168.0.1 | Porta 80/TCP ABERTA | Status/Serviço: HTTP
[+] Alvo 192.168.0.1 | Porta 443/TCP ABERTA | Status/Serviço: HTTPS | TLS/1.3 | cipher=TLS_AES_256_GCM_SHA384 | CN=router.local

INFO Scan finalizado. target=192.168.0.1 total_portas_abertas=2

💾 Relatório JSON salvo em 'reports/relatorio.json'!
📊 Tabela em Markdown gerada em 'reports/relatorio.md'!
📈 CSV gerado em 'reports/relatorio.csv'!
💾 Relatório YAML salvo em 'reports/relatorio.yaml'!
🔮 Relatório XML gerado em 'reports/relatorio.xml'!
🗺  Relatório Nmap XML gerado em 'reports/relatorio_nmap.xml'!
```

---

## 🔬 Service Signature Database

O Sentinel-RS identifica serviços por banner com uma base de **40+ assinaturas** incluindo:

| Categoria | Exemplos |
|---|---|
| Web Servers | Apache, Nginx, IIS, Caddy, LiteSpeed |
| SSH | OpenSSH, Dropbear, libssh |
| FTP | vsftpd, ProFTPD, Pure-FTPd |
| Mail | Postfix, Exim, Dovecot |
| Databases | MySQL, PostgreSQL, MongoDB, Redis |
| Proxy | Squid, HAProxy, Varnish |
| Runtimes | Node.js, Python, Ruby, ASP.NET |

---

## 🔒 TLS Fingerprinting

Em portas 443/8443, o Sentinel-RS extrai automaticamente:
- Versão do protocolo TLS (1.2, 1.3)
- Cipher suite negociada
- CN e SANs do certificado
- Emissor do certificado
- Data de expiração e status (expirado/válido)

---

## ⚡ SYN Scan

O SYN Scan (`--syn`) usa raw sockets para enviar pacotes TCP SYN sem completar o handshake:

```
Cliente → SYN →        Servidor
Cliente ← SYN-ACK ←   Servidor (porta ABERTA)
Cliente → RST →        Servidor (encerra sem logar)
```

**Vantagens:** mais furtivo que TCP connect scan, não gera logs na aplicação alvo.
**Requisito:** `root` ou `CAP_NET_RAW` no Linux.

---

## 🧪 Testes

```bash
cargo test
```

```
test cli::tests                    7 testes  — argumentos CLI
test models::tests                 6 testes  — vulnerabilidades e serialização
test network::fingerprint::tests   3 testes  — detecção de serviços
test network::signatures::tests    9 testes  — signature database
test network::syn::tests           5 testes  — SYN scan
test network::tls::tests           3 testes  — TLS fingerprinting
────────────────────────────────────────────
Total: 34 passed
```

---

## 🛣️ Roadmap

- [x] Scanner TCP + UDP
- [x] CIDR scanning
- [x] Fingerprinting de serviços (40+ assinaturas)
- [x] DNS reverso via PTR
- [x] Exportação JSON, CSV, YAML, XML, Markdown
- [x] **Nmap XML** compatível
- [x] Structured logging (`tracing`)
- [x] **Output `--stdout` para pipelines**
- [x] **SYN Scan** (raw sockets)
- [x] **TLS fingerprinting**
- [x] 34 testes automatizados
- [ ] Fingerprinting avançado (UDP signatures)
- [ ] Service signature database expandida
- [ ] TLS fingerprinting JA3/JA4

---

## 👨‍💻 Autor

**Luiz Felipe Grochevski** — [LinkedIn](https://www.linkedin.com/in/luiz-felipe-grochevski) | [GitHub](https://github.com/LuizGrochevski)

---

## ⚠️ Aviso

Este projeto é destinado exclusivamente para fins educacionais, laboratoriais e auditorias autorizadas em ambientes controlados.

