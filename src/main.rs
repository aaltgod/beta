use std::convert::Infallible;
use std::net::SocketAddr;
use std::str::FromStr;

use hyper::{Server, Client, Request, Response, Body, Uri};
use hyper::service::{make_service_fn, service_fn};


async fn handler(mut req: Request<Body>) -> Result<Response<Body>, Infallible> {
    println!("{:?} {}", req.headers(), req.uri().path());

    let client = Client::new();
    
    let forwarded_uri = String::from("http://127.0.0.1:4554/");

    match Uri::from_str(forwarded_uri.as_str()) {
        Ok(uri) => *req.uri_mut() = uri,
        // TODO: never PANIC
        Err(e) => panic!("{}", e)
    };

    let result: Response<Body>;

    match client.request(req).await {
        Ok(resp) => result = resp,
        // TODO: never PANIC
        Err(e) => panic!("{}", e) 
    };
    
    Ok(Response::from(result))
}

#[tokio::main]
async fn main() {
    let addr = SocketAddr::from(([0, 0, 0, 0], 1337));

    let make_service = make_service_fn(|_conn| async {
        Ok::<_, Infallible>(service_fn(handler))
    });

    let server = Server::bind(&addr).serve(make_service);

    if let Err(e) = server.await {
        eprintln!("Fatal err {}", e)
    }
}