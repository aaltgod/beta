pub mod config;
pub mod helpers;
pub mod cache;
pub mod proxy;
pub mod metrics;
pub mod hendlers;

use config::Config;

use hyper::{Request, Response, Body};
use hyper::Server;
use hyper::service::{make_service_fn, service_fn};
use warp::Filter;

use crate::metrics::register_metrics;

extern crate redis;


async fn lastochka(config: Config, server: proxy::LastochkaServer, req: Request<Body>) -> Result<Response<Body>, hyper::Error> {
    server.do_request(config, req).await
}

async fn run_server() {
    register_metrics();

    let metrics_route = warp::path!("metrics").and_then(hendlers::metrics_handler);
    
    println!("START SERVER");
    
    warp::serve(metrics_route)
        .run(([0, 0, 0, 0], 8081))
        .await
}

async fn run_proxy(config: Config) {
    let addr = match &config.proxy_addr {
        Some(addr) => addr.parse().unwrap(),
        None => return eprintln!("Proxy address is not set"),
    };

    if config.service_ports.len() == 0 {
        return eprintln!("service ports are not set") ;
    }

    if config.team_ips.len() == 0 {
        return eprintln!("team ips are no set");
    }

    let redis_client = cache::create_client("redis://:VsemPrivet@127.0.0.1:2138".to_string()).await.expect("couldn't create redis client");
    let lastochka_server = proxy::LastochkaServer::new(redis_client);
    
    let make_service = make_service_fn(move |_| { 
        let c = config.clone();
        let s = lastochka_server.clone();
        async move {
             Ok::<_, hyper::Error>(service_fn(move |req| lastochka(c.clone(), s.clone(), req)))
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
    let config = serde_yaml::from_reader(config_file).expect("couldn't read config values");

    tokio::spawn(async move {
        run_server().await
    });

    run_proxy(config).await;
}