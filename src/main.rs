use anyhow::Result;

#[tokio::main]
async fn main() -> Result<()> {
    gateway::run().await
}
