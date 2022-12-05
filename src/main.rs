pub mod config;
pub mod helpers;
pub mod redis;

use config::Config;
use bytes::Bytes;
use regex::Regex;

use hyper::http::HeaderValue;
use hyper::{Server, Client, Request, Response, Body, Uri};
use hyper::service::{make_service_fn, service_fn};


async fn change_uri(uri: Uri, host: &HeaderValue) -> Uri {
    let re = Regex::new("([A-Z0-9]{31}=)").unwrap();
    let path = uri.path_and_query().unwrap().as_str();
    println!("{:?}", re.captures(path));

    let changed_uri = Uri::builder().
        scheme("http").
        authority(host.to_str().unwrap());

    // TODO: add flags replacement when its more 1
    if re.captures(path).unwrap().len() == 1 {
        let changed_path = re.replace_all(path, helpers::build_flag(true)).to_string();
        println!("{:?}", changed_path);
        
        changed_uri.
            path_and_query(changed_path).
            build().
            expect("build new uri")
    } else {
        changed_uri.
            path_and_query(path).
            build().
            expect("build default uri")
    }
}

async fn change_body(body_bytes: Bytes) -> Result<Body, hyper::Error> {
    let re = Regex::new("[A-Z0-9]{31}%3D").unwrap();
    if !body_bytes.is_empty(){
        let text_body = std::str::from_utf8(&body_bytes).unwrap();
        // TODO: add flag on flag replacing
        // probably do it in also url query, json;

        let body = Body::from(re.replace(text_body, helpers::build_flag(true)).into_owned());
        println!("{:?}", body);
        Ok(body)
    } else {
        Ok(Body::empty())
    }
}

async fn change_request(req: Request<Body>) -> Result<Request<Body>, hyper::http::Error> {
   let (parts, body) = req.into_parts();
   let new_host = parts.headers.get("host").unwrap();
   let new_uri = change_uri(parts.uri, new_host).await;
   
   let body_bytes = hyper::body::to_bytes(body).await.expect("body to bytes");
   println!("body: {:?}\n{}", body_bytes, new_uri);

   let changed_request = Request::builder().
        uri(new_uri).
        body(change_body(body_bytes).await.unwrap());

    changed_request
}

async fn do_request(_config: Config, req: Request<Body>) -> Result<Response<Body>, hyper::Error> {
    println!("{:?}", req.uri());

    let changed_req = change_request(req).await.unwrap();
    let service_resp = Client::new().
        request(changed_req).await.map_err(|e| {
        eprintln!("{:?}", e);
        hyper::Error::from(e)
    });

    let resp = service_resp.unwrap();
    let (parts, body) = resp.into_parts();
    let new_body = Body::from(
        change_body(
            hyper::body::to_bytes(body)
                .await.expect("body to bytes"))
            .await.unwrap());
    let mut changed_resp = Response::from_parts(parts, new_body);

    let _res = changed_resp.headers_mut().
        insert("Privet", "ww".parse().unwrap()).is_none();
    
    Ok(changed_resp)  
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
        let c = config.clone();
        async move {
             Ok::<_, hyper::Error>(service_fn(move |req| do_request(c.clone(), req)))
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