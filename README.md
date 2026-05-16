# Sentinel-RS 🛡️

O **Sentinel-RS** é um scanner de portas de rede local (Port Scanner) de alta performance, desenvolvido em **Rust** utilizando programação assíncrona. Ele foi projetado e otimizado para rodar diretamente em ambientes móveis via **Termux** (arquitetura ARM), permitindo auditorias rápidas de segurança em qualquer lugar.

## 🚀 Funcionalidades
- **Scan Assíncrono Dinâmico:** Utiliza a biblioteca `Tokio` para realizar centenas de varreduras simultâneas sem travar o sistema.
- **Controle de Fluxo (Throttling):** Implementação de um `Semaphore` (Semáforo) para limitar conexões simultâneas, evitando estouro de memória no Android/Termux.
- **Input Interativo:** Permite que o usuário defina o IP alvo e o intervalo exato de portas (ex: 1 a 1000) em tempo real.

## 🛠️ Tecnologias Utilizadas
- **Rust** (Linguagem principal)
- **Tokio Runtime** (Gerenciamento de tarefas assíncronas/futuras)
- **Std::net::TcpStream** (Manipulação de sockets TCP de baixo nível)

## 📦 Como rodar no Termux (Android)

1. Instale os pacotes necessários no Termux:
```bash
pkg update && pkg upgrade
pkg install rust clang make git
```

2. Clone este repositórii e entre na pasta:
```bash
git clone https://github.com/LuizGrochevski/Sentinel-RS.git
cd Sentinel-RS
```

3. Compile e execute o projeto:
```bash
cargo run --release
```

## 🧠 Aprendizados técnicos neste projeto
​
Desenvolver o Sentinel-RS me permitiu dominar conceitos fundamentais de Rust e Redes:

1. **​Ownership e Concorrência:** Como gerenciar referências de memória seguras entre múltiplas threads usando Arc (Atomic Reference Counting).
2. **​Modelo de Rede Assíncrono:** Entendimento prático do TCP Three-Way Handshake e tratamento de timeouts de rede.
​3. **Otimização para Mobile:** Ajuste de limites de conexões para respeitar o hardware restrito de smartphones.
