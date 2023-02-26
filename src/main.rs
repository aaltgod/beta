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

    let redis_client = redis::Client::open("redis://:SUP3RS3CRET@127.0.0.1:2138".to_string())
        .expect("couldn't create redis client");

    let cache = cache::Cache::new(redis_client);

    future::join_all(
        vec![
            tokio::spawn(async move {
                server::run_server(config).await
            }),
            tokio::spawn(async move {
                proxy::run_proxy(c, cache).await
            })
    ]).await;
}