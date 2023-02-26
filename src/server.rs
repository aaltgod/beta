use crate::handlers;
use crate::config;
use crate::metrics;

use std::net::SocketAddr;

use warp::Filter;

pub async fn run_server(config: config::Config) {
    metrics::register_metrics();

    let addr: SocketAddr = match &config.metrics_addr {
        Some(addr) => addr.parse().unwrap(),
        None => return eprintln!("metrics address is not set"),
    };

    let metrics_route = warp::path!("metrics").and_then(handlers::metrics_handler);
    
    println!("START SERVER ON ADDRESS: {}", addr);
    
    warp::serve(metrics_route)
        .run(addr)
        .await
}