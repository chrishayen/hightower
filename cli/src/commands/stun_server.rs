use anyhow::Result;
use stun::server::StunServer;

pub fn run_stun(bind: &str) -> Result<()> {
    println!("Starting STUN server on {}...", bind);
    let server = StunServer::bind(bind)?;
    println!("STUN server listening on {}", server.local_addr()?);
    server.run()?;
    Ok(())
}
