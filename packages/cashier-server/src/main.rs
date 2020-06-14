use std::error::Error;
use cashier_server::{config::Config, services};

#[actix_rt::main]
async fn main() -> Result<(), Box<dyn Error>> {
    env_logger::init();
    let config = Config::from_env()?;
    match config {
        Config::Init(init_config) => services::init::init(&init_config).await?,
        Config::Start(start_config) => services::start::start(&start_config).await?,
    }
    Ok(())
}
