pub mod cache;
pub mod config;
pub mod errors;
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
async fn main() -> () {
    env_logger::init();

    let redis_client = match redis::Client::open("redis://:SUP3RS3CRET@127.0.0.1:2139".to_string())
    {
        Ok(res) => res,
        Err(e) => {
            error!("couldn't create redis client: {}", e);
            return;
        }
    };

    match redis_client.get_connection() {
        Ok(_) => warn!(
            "successfully connected to redis on address: {}",
            redis_client.get_connection_info().addr
        ),
        Err(e) => {
            error!(
                "couldn't connect to redis, probably redis is not running: {}",
                e
            );
            return;
        }
    }

    let pool = Pool::builder()
        .max_open(20)
        .build(RedisConnectionManager::new(redis_client));

    let cache = cache::Cache::new(pool);
    let config = match Config::build() {
        Ok(res) => res,
        Err(e) => {
            error!("couldn't parse `config.yaml`: {}", e.to_string());
            return;
        }
    };
    let c = config.clone();

    future::join_all(vec![
        tokio::spawn(async move { server::run(config).await }),
        tokio::spawn(async move { proxy::run(c, cache).await }),
    ])
    .await;
}
