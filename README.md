# Sentinel-RS 🛡️🦀

![Rust](https://img.shields.io/badge/Rust-000000?style=for-the-badge&logo=rust&logoColor=white)
![Tokio](https://img.shields.io/badge/Tokio-async-blue?style=for-the-badge)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Android%20(Termux)-green?style=for-the-badge)
![License](https://img.shields.io/badge/License-Educational-orange?style=for-the-badge)

Sentinel-RS é uma ferramenta de network scanning desenvolvida em **Rust** com foco em concorrência assíncrona, performance e segurança. Arquitetada para rodar de forma eficiente inclusive em ambientes móveis via **Termux (Android/ARM)**, utilizando o runtime assíncrono do Tokio para gerenciar centenas de conexões simultâneas.

Integra-se nativamente com a **[Netwatch-API](https://github.com/LuizGrochevski/netwatch-api)** — uma REST API em Python/FastAPI que utiliza o Sentinel-RS como engine de scanning.

---

## 🚀 Funcionalidades

- 🔍 Scanner híbrido **TCP + UDP**
- 🌐 Suporte a **ranges e parsing dinâmico de portas**
- 📡 Scanner **CIDR** para sub-redes inteiras
- 🖥️ Descoberta de hosts ativos
- 🔎 DNS reverso real via PTR, opcional com `--reverse-dns`
- 🛠️ Fingerprinting básico de serviços
- 🔒 Parsing HTTP/HTTPS
- ⚡ Controle de concorrência com workers e semáforos
- ⏱️ Timeout configurável
- 📝 Logs verbose/debug
- 📊 Exportação de relatórios em **6 formatos**:
  - JSON
  - CSV
  - YAML
  - XML
  - Markdown
  - **Nmap XML** *(compatível com Metasploit, Burp Suite e outras ferramentas)*

---

## 🧠 Arquitetura

O Sentinel-RS utiliza uma arquitetura assíncrona baseada em:

- Tokio Runtime
- Workers concorrentes
- Queue de tarefas (`mpsc`)
- Controle de throttling via `Semaphore`
- Timeout handling
- Probing TCP/UDP paralelo

Fluxo simplificado:

```
CIDR/IP
   ↓
Host Discovery
   ↓
Queue de Scanning
   ↓
Workers Concorrentes
   ↓
Fingerprinting
   ↓
Exportação de Relatórios (JSON, CSV, YAML, XML, Markdown, Nmap XML)
```

---

## 🔗 Integração com Netwatch-API

O Sentinel-RS pode ser usado como engine de scanning da **[Netwatch-API](https://github.com/LuizGrochevski/netwatch-api)**, uma REST API com autenticação JWT que expõe os resultados via HTTP.

```
POST /scan (Netwatch-API)
    │
    ▼
sentinel-rs (binário)
    │
    ▼
JSON report → resposta da API
```

```bash
# Exemplo via Netwatch-API
curl -X POST http://localhost:8000/scan \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"targets": ["192.168.0.1"], "ports": "22,80,443", "protocol": "tcp"}'
```

---

## 🛠️ Tecnologias

| Tecnologia | Uso |
|---|---|
| Rust | Linguagem principal |
| Tokio | Runtime assíncrono |
| Tokio-Rustls | TLS assíncrono |
| libc | DNS reverso via `getnameinfo` |
| serde / serde_json | Serialização JSON |
| serde_yaml | Serialização YAML |
| quick-xml | Serialização XML e Nmap XML |
| clap | CLI arguments |
| tracing | Logs estruturados |
| indicatif | Barra de progresso |

---

## 📦 Instalação no Termux (Android)

```bash
pkg update && pkg upgrade
pkg install rust clang make git
```

```bash
git clone https://github.com/LuizGrochevski/Sentinel-RS.git
cd Sentinel-RS
cargo build --release
```

---

## 📄 Exemplos de uso

**TCP Scan**
```bash
cargo run --release -- 192.168.0.0/24 -p 22,80,443
```

**TCP Scan com Reverse DNS**
```bash
cargo run --release -- 192.168.0.0/24 -p 22,80,443 --reverse-dns
```

**UDP Scan**
```bash
cargo run --release -- 192.168.0.1 -udp -p 53,80,1900
```

**Verbose Debug**
```bash
cargo run --release -- 192.168.0.1 -p 21-25,53,80,1900 --verbose
```

---

## 📊 Exemplo de saída

```
🛡 Sentinel-RS iniciado!
Protocolo: TCP (Conexões)
Alvo especificado: 192.168.0.1
Total de IPs para analisar: 1
Total de portas por host: 3
Concorrência máxima: 100 conexões simultâneas

🔍 Mapeamento concluído: 1 hosts encontrados.
[+] Alvo 192.168.0.1 | Porta 80/TCP ABERTA | Status/Serviço: HTTP

💾 Relatório JSON salvo com sucesso em 'reports/relatorio.json'!
📊 Tabela em Markdown gerada em 'reports/relatorio.md'!
📈 CSV gerado com sucesso em 'reports/relatorio.csv'!
💾 Relatório YAML salvo com sucesso em 'reports/relatorio.yaml'!
🔮 Relatório XML gerado com sucesso em 'reports/relatorio.xml'!
🗺  Relatório Nmap XML gerado em 'reports/relatorio_nmap.xml'!
```

**Exemplo de Nmap XML gerado:**
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="sentinel-rs" version="0.1.0" xmloutputversion="1.04">
  <host>
    <status state="up" reason="syn-ack"/>
    <address addr="192.168.0.1" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open" reason="syn-ack"/>
        <service name="http" method="table" conf="3"/>
      </port>
    </ports>
  </host>
</nmaprun>
```

---

## 📌 Reverse DNS

Por padrão, o scanner usa apenas o IP para conectar aos alvos. Para consultar registros PTR reais e preencher o campo hostname nos relatórios:

```bash
cargo run --release -- 192.168.0.0/24 -p 22,80,443 --reverse-dns
```

Os relatórios exportados separam `ip` e `hostname`. Quando o hostname não é resolvido, o campo fica vazio ou marcado como `-` no Markdown.

---

## 🧪 Objetivos do Projeto

O Sentinel-RS foi criado como laboratório prático para estudo de:

- Programação assíncrona em Rust
- Concorrência segura
- Networking de baixo nível
- Scanning de rede e fingerprinting
- Arquitetura de ferramentas de infraestrutura
- Otimização para ambientes ARM/mobile
- Compatibilidade com ecossistema de segurança (Nmap XML)

---

## 🛣️ Roadmap

- [x] Scanner TCP + UDP
- [x] CIDR scanning
- [x] Fingerprinting básico de serviços
- [x] DNS reverso via PTR
- [x] Exportação JSON, CSV, YAML, XML, Markdown
- [x] **Compatibilidade Nmap XML**
- [x] Structured logging (`tracing`)
- [ ] SYN Scan (raw sockets)
- [ ] Fingerprinting avançado
- [ ] TLS fingerprinting
- [ ] Service signature database
- [ ] UDP improvements

---

## 👨‍💻 Autor

**Luiz Felipe Grochevski** — [LinkedIn](https://www.linkedin.com/in/luiz-felipe-grochevski) | [GitHub](https://github.com/LuizGrochevski)

---

## ⚠️ Aviso

Este projeto é destinado exclusivamente para fins educacionais, laboratoriais e auditorias autorizadas em ambientes controlados.

