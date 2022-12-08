pub mod config;
pub mod helpers;
pub mod cache;
pub mod server;

use config::Config;

use hyper::{Request, Response, Body};
use hyper::Server;
use hyper::service::{make_service_fn, service_fn};

extern crate redis;

async fn lastocka(config: Config, server: server::LastochkaServer, req: Request<Body>) -> Result<Response<Body>, hyper::Error> {
    server.do_request(config, req).await
}

async fn run_server(config: Config) {
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

    let redis_client = cache::create_client("redis://:VsemPrivet@127.0.0.1:2138".to_string()).await.expect("Couldn't create redis client");
    let lastochka_server = server::LastochkaServer::new(redis_client);
    
    let make_service = make_service_fn(move |_| { 
        let c = config.clone();
        let s = lastochka_server.clone();
        async move {
             Ok::<_, hyper::Error>(service_fn(move |req| lastocka(c.clone(), s.clone(), req)))
        }
    });

    let server = Server::bind(&addr).serve(make_service);

    if let Err(e) = server.await {
        eprintln!("Fatal err {}", e)
    }
}

#[tokio::main]
async fn main() {
    let config_file = std::fs::File::open("config.yaml").expect("Couldn't open config file");
    let config = serde_yaml::from_reader(config_file).expect("Couldn't read config values");

    run_server(config).await;
}