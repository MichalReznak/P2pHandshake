use fehler::throws;

use crate::Error;

mod auth;
mod ping;

pub struct Prot {
    addr: String,
    port: u16,
}

impl Prot {
    pub fn new(addr: &str, port: u16) -> Self {
        Self {
            addr: addr.to_string(),
            port,
        }
    }

    #[throws]
    pub async fn auth(&self) {
        auth::auth(&self.addr, self.port).await?;
    }

    #[throws]
    pub async fn ping(&self) {
        ping::ping(&self.addr, self.port).await?;
    }
}
