use tokio::net::TcpStream;
use tokio::time::{timeout, Duration};
use std::sync::Arc;
use tokio::sync::Semaphore;
use std::io::{self, Write};

#[tokio::main]
async fn main() {
   let mut input_ip_alvo = String::new();
   let mut input_porta_inicio = String::new();
   let mut input_porta_fim = String::new();

   let semaforo = Arc::new(Semaphore::new(50));   

   println!("Digite o ip para o scan:");
   io::stdout().flush().unwrap();
   io::stdin().read_line(&mut input_ip_alvo).expect("Falha ao ler o input");
   let ip_alvo = input_ip_alvo.trim().to_string();

   println!("Digite a porta INICIAL:");
   io::stdout().flush().unwrap();
   io::stdin().read_line(&mut input_porta_inicio).expect("Falha ao ler a porta inicial");
   let porta_inicial: u16 = input_porta_inicio.trim().parse().expect("Digite um número válido!");

   println!("Digite a porta FINAL:");
   io::stdout().flush().unwrap();
   io::stdin().read_line(&mut input_porta_fim).expect("Falha ao ler a porta final");
   let porta_final: u16 = input_porta_fim.trim().parse().expect("Digite um número válido");
   
   let portas = porta_inicial..=porta_final;

   println!("Iniciando scan em {} (Portas {} até {})...", ip_alvo, porta_inicial, porta_final);

   let mut tarefas = vec![];

   let total_portas = porta_final - porta_inicial + 1;
   let mut escaneadas = 0;

   for porta in portas {
     let permissao = Arc::clone(&semaforo);
     let ip = ip_alvo.clone();

     escaneadas += 1;

     println!("\rEscaneando: {}/{} portas...", escaneadas, total_portas);
     io::stdout().flush().unwrap();

     let tarefa = tokio::spawn(async move {
       let _guarda = permissao.acquire().await.unwrap();

       let endereco = format!("{}:{}", ip, porta);

       match timeout(Duration::from_secs(1), TcpStream::connect(&endereco)).await {
         Ok(Ok(_)) => println!("Porta {} ABERTA", porta), _ => {}
           }
         });

         tarefas.push(tarefa);
      }
    
    for t in tarefas {
      let _ = t.await;
    }    
    
    println!("Scan finalizado!");
 }
