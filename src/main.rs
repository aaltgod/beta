pub mod config;
pub mod helpers;
pub mod cache;
pub mod proxy;
pub mod metrics;
pub mod handlers;
pub mod server;

use futures::future;
use mobc_redis::RedisConnectionManager;
use mobc_redis::mobc::Pool;

use config::Config;

extern crate redis;

#[tokio::main]
async fn main() {
    let config_file = std::fs::File::open("config.yaml").expect("couldn't open config file");
    let config: Config = serde_yaml::from_reader(config_file).expect("couldn't read config values");
    let c = config.clone();

    let redis_client = redis::Client::open("redis://:SUP3RS3CRET@127.0.0.1:2138".to_string())
        .expect("couldn't create redis client");

    let pool = Pool::builder()
        .max_open(20)
        .build(RedisConnectionManager::new(redis_client));

    let cache = cache::Cache::new(pool);

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