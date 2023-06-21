use crate::config;
use crate::handlers;
use crate::metrics;

use std::net::SocketAddr;

use warp::Filter;

pub async fn run(config: config::Config) {
    metrics::register_metrics();

    let addr: SocketAddr = config
        .metrics_addr
        .parse()
        .expect("couldn't parse metrics address");

    let metrics_route = warp::path!("metrics").and_then(handlers::metrics_handler);

    warn!("start server on address: {}", addr);

    warp::serve(metrics_route).run(addr).await
}
