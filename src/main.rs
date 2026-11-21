use anyhow::{Result, bail};

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    match args.as_slice() {
        [] => gateway::run().await,
        [command, sender] if command == "keygen" => {
            let Some(sender) = sender.to_str() else {
                bail!("sender must be valid UTF-8");
            };
            gateway::keygen(sender)
        }
        _ => bail!("usage: gateway [keygen <sender>]"),
    }
}
