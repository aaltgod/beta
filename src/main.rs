pub mod config;
pub mod helpers;
pub mod cache;
pub mod proxy;
pub mod metrics;
pub mod handlers;
pub mod server;

use futures::future;

use config::Config;

extern crate redis;

#[tokio::main]
async fn main() {
    let config_file = std::fs::File::open("config.yaml").expect("couldn't open config file");
    let config: Config = serde_yaml::from_reader(config_file).expect("couldn't read config values");
    let c = config.clone();

    let tasks = vec![
        tokio::spawn(async move {
            server::run_server(config).await
        }),
        tokio::spawn(async move {
            proxy::run_proxy(c).await
        })
    ];

    future::join_all(tasks).await;
}