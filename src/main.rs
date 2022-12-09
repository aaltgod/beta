pub mod config;
pub mod helpers;
pub mod cache;
pub mod proxy;
pub mod metrics;
pub mod handlers;

use std::net::SocketAddr;

use config::Config;

use hyper::{Request, Response, Body};
use hyper::Server;
use hyper::service::{make_service_fn, service_fn};
use warp::Filter;

use crate::metrics::register_metrics;

extern crate redis;


async fn lastochka(server: proxy::LastochkaServer, req: Request<Body>) -> Result<Response<Body>, hyper::Error> {
    server.do_request(req).await
}

async fn run_server(config: Config) {
    register_metrics();

    let addr: SocketAddr = match &config.metrics_addr {
        Some(addr) => addr.parse().unwrap(),
        None => return eprintln!("metrics address is not set"),
    };

    let metrics_route = warp::path!("metrics").and_then(handlers::metrics_handler);
    
    println!("START SERVER");
    
    warp::serve(metrics_route)
        .run(addr)
        .await
}

async fn run_proxy(config: Config) {
    let addr = match &config.proxy_addr {
        Some(addr) => addr.parse().unwrap(),
        None => return eprintln!("proxy address is not set"),
    };

    if config.service_ports.len() == 0 {
        return eprintln!("service ports are not set") ;
    }

    if config.team_ips.len() == 0 {
        return eprintln!("team ips are no set");
    }

    let redis_client = cache::create_client("redis://:VsemPrivet@127.0.0.1:2138".to_string()).await.expect("couldn't create redis client");
    let lastochka_server = proxy::LastochkaServer::new(redis_client, config.clone());
    
    let make_service = make_service_fn(move |_| { 
        let s = lastochka_server.clone();
        async move {
             Ok::<_, hyper::Error>(service_fn(move |req| lastochka(s.clone(), req)))
        }
    });

    let server = Server::bind(&addr).serve(make_service);

    if let Err(e) = server.await {
        eprintln!("Fatal err {}", e)
    }
}

#[tokio::main]
async fn main() {
    let config_file = std::fs::File::open("config.yaml").expect("couldn't open config file");
    let config: Config = serde_yaml::from_reader(config_file).expect("couldn't read config values");
    let c = config.clone();

    tokio::spawn(async move {
        let c = config.clone();
        run_server(c).await
    });


    run_proxy(c.clone()).await;
}