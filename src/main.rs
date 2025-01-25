pub mod cache;
pub mod config;
pub mod errors;
pub mod handlers;
pub mod helpers;
pub mod iptables_manager;
pub mod metrics;
pub mod metrics_server;
pub mod server;

use futures::future;
use mobc_redis::mobc::Pool;
use mobc_redis::RedisConnectionManager;

extern crate redis;

#[macro_use]
extern crate log;

fn print_logo() {
    println!(
        r"
        ██╗      █████╗ ███████╗████████╗ ██████╗  ██████╗██╗  ██╗██╗  ██╗ █████╗
        ██║     ██╔══██╗██╔════╝╚══██╔══╝██╔═══██╗██╔════╝██║  ██║██║ ██╔╝██╔══██╗
        ██║     ███████║███████╗   ██║   ██║   ██║██║     ███████║█████╔╝ ███████║
        ██║     ██╔══██║╚════██║   ██║   ██║   ██║██║     ██╔══██║██╔═██╗ ██╔══██║
        ███████╗██║  ██║███████║   ██║   ╚██████╔╝╚██████╗██║  ██║██║  ██╗██║  ██║
        ╚══════╝╚═╝  ╚═╝╚══════╝   ╚═╝    ╚═════╝  ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝


        Launching!
    "
    );
}

#[tokio::main]
async fn main() -> () {
    print_logo();

    env_logger::init();

    let flags: Vec<String> = std::env::args().collect();

    let iptables_manager = match iptables_manager::Manager::new() {
        Ok(res) => res,
        Err(e) => {
            error!("couldn't build iptables_manager: {e}");
            return;
        }
    };

    if flags.contains(&"--flush-iptables".to_string()) {
        match iptables_manager.flush() {
            Ok(_) => warn!("successfully flushed iptables"),
            Err(e) => error!("couldn't flush iptables: {e}"),
        }
        return;
    }

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

    match iptables_manager
        .watch_for_proxy_settings(secrets_config.proxy_port, proxy_settings_config.clone())
    {
        Ok(_) => (),
        Err(e) => {
            error!("couldn't start to watch for proxy settings: {e}");
            return;
        }
    }

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
                proxy_settings_config,
                cache::Cache::new(
                    Pool::builder()
                        .max_open(20)
                        .build(RedisConnectionManager::new(redis_client)),
                ),
            )
            .await
        }),
    ])
    .await;
}
