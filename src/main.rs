pub mod config;
use config::Config;

use bytes::Bytes;
use regex::Regex;

use hyper::{Server, Client, Request, Response, Body, Uri};
use hyper::service::{make_service_fn, service_fn};


async fn change_body(body_bytes: Bytes) -> Result<Body, hyper::Error> {
    let re = Regex::new("([A-Z0-9]{31})%3D").unwrap();
    if !body_bytes.is_empty(){
        let text_body = std::str::from_utf8(&body_bytes).unwrap();
        // TODO: add flag on flag replacing
        // probably do it in also url query, json;

        let body = Body::from(re.replace(text_body, "FLAG").into_owned());
        println!("{:?}", body);
        Ok(body)
    } else {
        Ok(Body::empty())
    }
}

async fn change_request(req: Request<Body>) -> Result<Request<Body>, hyper::http::Error> {
   let (parts, body) = req.into_parts();
   let new_host = parts.headers.get("host").unwrap();
   let new_uri = Uri::builder().
        scheme("http").
        authority(new_host.to_str().unwrap()).
        path_and_query(parts.uri.path_and_query().unwrap().to_string()).
        build().
        expect("build new uri");
   
   let body_bytes = hyper::body::to_bytes(body).await.expect("body to bytes");
   println!("body: {:?}\n{}", body_bytes, new_uri);

   let changed_request = Request::builder().
        uri(new_uri).
        body(change_body(body_bytes).await.unwrap());

    changed_request
}

async fn upstream_request(req: Request<Body>) -> Result<Response<Body>, hyper::Error> {
    println!("{:?}", req.uri());

    let filtered_req = change_request(req).await.unwrap();
    let upstream_resp = Client::new().request(filtered_req).await.map_err(|e| {
        eprintln!("{:?}", e);
        hyper::Error::from(e)
    });

    let mut resp = upstream_resp.unwrap();
    let _res = resp.headers_mut().insert("Privet", "ww".parse().unwrap()).is_none();
    
    Ok(resp)  
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

    let make_service = make_service_fn(move |_| { 
        async move {
             Ok::<_, hyper::Error>(service_fn(move |req| upstream_request(req)))
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