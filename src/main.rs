pub mod cache;
pub mod config;
pub mod handlers;
pub mod helpers;
pub mod metrics;
pub mod proxy;
pub mod server;

use futures::future;
use mobc_redis::mobc::Pool;
use mobc_redis::RedisConnectionManager;

use config::Config;

extern crate redis;

#[macro_use]
extern crate log;

#[tokio::main]
async fn main() {
    let redis_client = redis::Client::open("redis://:SUP3RS3CRET@127.0.0.1:2138".to_string())
        .expect("couldn't create redis client");

    let pool = Pool::builder()
        .max_open(20)
        .build(RedisConnectionManager::new(redis_client));

    let cache = cache::Cache::new(pool);
    let config = Config::build();
    let c = config.clone();

    env_logger::init();

    future::join_all(vec![
        tokio::spawn(async move { server::run(config).await }),
        tokio::spawn(async move { proxy::run(c, cache).await }),
    ])
    .await;
}
