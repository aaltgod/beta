pub mod cache;
pub mod config;
pub mod errors;
pub mod handlers;
pub mod helpers;
pub mod metrics;
pub mod metrics_server;
pub mod server;
mod server_tests;
mod traits;

use std::sync::Arc;

use futures::future;
use mobc_redis::mobc::Pool;
use mobc_redis::RedisConnectionManager;

extern crate redis;

#[macro_use]
extern crate log;

fn print_logo() {
    println!(
        r"
    ____  _______________
   / __ )/ ____/_  __/   |
  / __  / __/   / / / /| |
 / /_/ / /___  / / / ___ |
/_____/_____/ /_/ /_/  |_|


        Launching!
    "
    );
}

#[tokio::main]
async fn main() -> () {
    print_logo();

    env_logger::init();

    let proxy_settings_config = match config::ProxySettingsConfig::new() {
        Ok(res) => res,
        Err(e) => {
            error!("couldn't build proxy settings config: {e}");
            return;
        }
    };

    let secrets_config = match config::build_secrets_config() {
        Ok(res) => res,
        Err(e) => {
            error!("couldn't build secrets config: {e}");
            return;
        }
    };

    let redis_client = match redis::Client::open(format!(
        "redis://:{}@{}",
        secrets_config.redis_password, secrets_config.redis_addr
    )) {
        Ok(res) => res,
        Err(e) => {
            error!("couldn't build redis client: {e}");
            return;
        }
    };

    match redis_client.get_connection() {
        Ok(_) => warn!(
            "successfully connected to redis on address: {}",
            redis_client.get_connection_info().addr
        ),
        Err(e) => {
            error!("couldn't connect to redis, probably redis is not running: {e}");
            return;
        }
    }

    future::join_all(vec![
        tokio::spawn(async move { metrics_server::run(secrets_config.metrics_addr).await }),
        tokio::spawn(async move {
            server::run(
                secrets_config.proxy_addr,
                Arc::new(proxy_settings_config),
                Arc::new(cache::Cache::new(
                    Pool::builder()
                        .max_open(20)
                        .build(RedisConnectionManager::new(redis_client)),
                )),
            )
            .await
        }),
    ])
    .await;
}
