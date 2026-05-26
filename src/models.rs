use serde::Serialize;

#[derive(Serialize, Clone, Debug)]
pub struct ResultadoPorta {
    pub ip: String,
    pub porta: u16,
    pub status: String,
    pub servico: String,
}

pub struct TrabalhoScan {
    pub ip: String,
    pub porta: u16,
}

