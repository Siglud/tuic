use crate::config::{Config, ConfigError};
use env_logger::Builder as LoggerBuilder;
use forwarder::Forwarder;
use std::{env, process};

mod config;
mod forwarder;

#[tokio::main]
async fn main() {
    let cfg = match Config::parse(env::args_os()) {
        Ok(cfg) => cfg,
        Err(ConfigError::Version(msg) | ConfigError::Help(msg)) => {
            println!("{msg}");
            return;
        }
        Err(err) => {
            eprintln!("{err}");
            process::exit(1);
        }
    };

    LoggerBuilder::new()
        .filter_level(cfg.log_level)
        .format_module_path(false)
        .format_target(false)
        .init();

    let result = async {
        let forwarder = Forwarder::bind(&cfg).await?;
        log::warn!(
            "UDP forwarder started, listening on {} upstream {}",
            forwarder.local_addr()?,
            forwarder.upstream(),
        );
        forwarder.run().await
    }
    .await;

    if let Err(err) = result {
        eprintln!("{err}");
        process::exit(1);
    }
}
