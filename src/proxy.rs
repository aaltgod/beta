use bytes::Bytes;

use hyper::http::HeaderValue;
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Client, Request, Response, Server as HTTPServer, Uri};

use crate::cache::Cache;
use crate::helpers;
use crate::helpers::FLAG_REGEX;
use crate::metrics::{
    INCOMING_REQUEST_COUNTER, PROCESSED_REQUEST_COUNTER, PROCESSED_RESPONSE_COUNTER,
    TARGET_SERVICE_ERROR_COUNTER,
};
use crate::Config;

#[derive(Clone)]
pub struct Proxy {
    config: Config,
    cache: Cache,
}

impl Proxy {
    pub fn new(config: Config, cache: Cache) -> Self {
        Proxy { config, cache }
    }

    async fn change_uri(&self, uri: Uri, host: &HeaderValue) -> Uri {
        let host = match host.to_str() {
            Ok(res) => res,
            Err(_) => return uri,
        };

        let mut changed_uri = Uri::builder().scheme("http").authority(host);

        let split: Vec<&str> = host.split(":").collect();
        let port: u32 = match split[1].trim().parse() {
            Ok(res) => res,
            Err(_) => return uri,
        };

        for target in self.config.targets.iter() {
            let target_port = match target.port {
                Some(p) => p,
                None => 0,
            };

            if port == target_port {
                let target_team_ip = match target.team_ip.clone() {
                    Some(ip) => ip,
                    None => split[0].to_string(),
                };

                changed_uri = changed_uri.authority(target_team_ip + ":" + split[1]);
            }
        }

        let path = match uri.path_and_query() {
            Some(res) => res.as_str(),
            None => return uri,
        };

        if helpers::contains_flag(path) {
            println!("TO CHANGE URI:  {:?}", FLAG_REGEX.clone().captures(path));

            // safely unwrap
            let captures = FLAG_REGEX.clone().captures(path).unwrap();

            // TODO: add flags replacement when its more 1
            if captures.len() == 1 {
                // FIXME: extra trip to redis if f == ""
                let flag = captures.get(0).map_or("", |f| f.as_str());
                let new_flag = helpers::build_flag(false);
                let flag_from_cache = match self.cache.get_flag(flag.to_string()).await {
                    Ok(f) => f,
                    Err(_) => return uri,
                };

                println!("GOT FLAG IN URI {:?}", flag);

                let mut changed_path: String = "".to_string();

                if flag_from_cache.len() == 0 {
                    let _result = match self
                        .cache
                        .set_flag(flag.to_string(), new_flag.clone())
                        .await
                    {
                        Ok(()) => println!("OK set: flag - new_flag"),
                        Err(e) => {
                            eprintln!("FAIL set flag - new_flag: {:?}", e);
                            return uri;
                        }
                    };

                    let _result = match self
                        .cache
                        .set_flag(new_flag.clone(), flag.to_string())
                        .await
                    {
                        Ok(()) => eprintln!("OK set new_flag - flag"),
                        Err(e) => {
                            eprintln!("FAIL set new_flag - flag: {:?}", e);
                            return uri;
                        }
                    };

                    changed_path = FLAG_REGEX.clone().replace_all(path, new_flag).to_string();
                } else {
                    changed_path = FLAG_REGEX
                        .clone()
                        .replace_all(path, flag_from_cache)
                        .to_string();
                }

                println!("CHANGED URI:  {:?}", changed_path);

                let result = match changed_uri.path_and_query(changed_path).build() {
                    Ok(res) => res,
                    Err(e) => {
                        eprintln!("fail build changed_uri with changed_path: {:?}", e);
                        uri
                    }
                };

                return result;
            };
        };

        let result = match changed_uri.path_and_query(path).build() {
            Ok(res) => res,
            Err(e) => {
                eprintln!("fail build changed_uri with path: {:?}", e);
                uri
            }
        };

        result
    }

    async fn change_request_body(&self, body_bytes: Bytes) -> Result<Body, hyper::Error> {
        if !body_bytes.is_empty() {
            let text_body = std::str::from_utf8(&body_bytes).unwrap();

            if helpers::contains_flag(text_body) {
                println!("TO CHANGE REQUEST BODY: {:?}", text_body);

                let mut result_body = text_body.to_string();

                for flag in FLAG_REGEX.clone().find_iter(text_body) {
                    let flag_from_cache = match self.cache.get_flag(flag.as_str().to_string()).await
                    {
                        Ok(f) => f,
                        Err(_) => return Ok(Body::from(body_bytes.clone())),
                    };

                    if flag_from_cache.len() == 0 {
                        let new_flag = helpers::build_flag(false);

                        let _result = match self
                            .cache
                            .set_flag(flag.as_str().to_string(), new_flag.clone())
                            .await
                        {
                            Ok(()) => println!("ok flag - new_flag"),
                            Err(e) => println!("{:?}", e),
                        };

                        let _result = match self
                            .cache
                            .set_flag(new_flag.clone(), flag.as_str().to_string())
                            .await
                        {
                            Ok(()) => println!("ok new_flag - flag"),
                            Err(e) => println!("{:?}", e),
                        };

                        result_body = result_body
                            .replace(flag.as_str(), new_flag.as_str())
                            .to_string();
                    } else {
                        result_body = result_body
                            .replace(flag.as_str(), flag_from_cache.as_str())
                            .to_string();
                    }
                }

                // TODO: add Full, Empty, Stream
                let chunks: Vec<Result<_, std::io::Error>> = vec![Ok(result_body.clone())];
                let stream = futures::stream::iter(chunks);

                println!("CHANGED REQUEST BODY: {:?}", result_body);

                return Ok(Body::wrap_stream(stream));
            }

            Ok(Body::from(body_bytes.clone()))
        } else {
            Ok(Body::empty())
        }
    }

    async fn change_response_body(&self, body_bytes: Bytes) -> (Result<Body, hyper::Error>, usize) {
        if !body_bytes.is_empty() {
            let text_body = std::str::from_utf8(&body_bytes).unwrap();
            let body_bytes_length = body_bytes.clone().len();

            if helpers::contains_flag(text_body) {
                println!("TO CHANGE RESPONSE BODY: {:?}", text_body);

                let mut result_body = text_body.to_string();

                for flag in FLAG_REGEX.clone().find_iter(text_body) {
                    let flag_from_cache = match self.cache.get_flag(flag.as_str().to_string()).await
                    {
                        Ok(f) => f,
                        Err(_) => return (Ok(Body::from(body_bytes)), body_bytes_length),
                    };

                    if flag_from_cache.len() != 0 {
                        result_body = result_body
                            .replace(flag.as_str(), flag_from_cache.as_str())
                            .to_string();
                    } else {
                        println!("couldn't find flag: {:?}", flag)
                    }
                }

                println!("CHANGED RESPONE BODY: {:?}", result_body);

                // TODO: add Full, Empty, Stream
                return (Ok(Body::from(result_body.clone())), result_body.len());
            }

            (Ok(Body::from(body_bytes)), body_bytes_length)
        } else {
            (Ok(Body::empty()), 0)
        }
    }

    async fn change_request(&self, req: Request<Body>) -> Request<Body> {
        dbg!("REQ", &req);

        let mut req = req;
        let headers = req.headers().clone();
        let uri = req.uri().clone();
        let body = req.body_mut();

        let body_bytes = match hyper::body::to_bytes(body).await {
            Ok(res) => res,
            Err(_) => return req,
        };

        let changed_request_body = match self.change_request_body(body_bytes).await {
            Ok(res) => res,
            Err(_) => return req,
        };

        let host = match headers.get("host") {
            Some(res) => res,
            None => return req,
        };

        // TODO: add error returning to change_uri
        let changed_uri = self.change_uri(uri, host).await;

        *req.body_mut() = changed_request_body;
        *req.uri_mut() = changed_uri;

        dbg!("CHANGED RESP", &req);

        return req;
    }

    async fn change_response(&self, resp: Response<Body>) -> Response<Body> {
        dbg!("RESP", &resp);

        let mut resp = resp;
        let mut headers = resp.headers().clone();
        let body = match hyper::body::to_bytes(resp.body_mut()).await {
            Ok(res) => res,
            Err(_) => return resp,
        };

        let (new_body, new_body_length) = self.change_response_body(body).await;

        let new_body = match new_body {
            Ok(res) => res,
            Err(_) => return resp,
        };
        let new_body_length = match new_body_length.to_string().parse() {
            Ok(res) => res,
            Err(_) => return resp,
        };

        headers.insert(hyper::header::CONTENT_LENGTH, new_body_length);

        *resp.body_mut() = new_body;
        *resp.headers_mut() = headers;

        dbg!("CHANGED RESP", &resp);

        resp
    }

    pub async fn handle_request(&self, req: Request<Body>) -> Result<Response<Body>, hyper::Error> {
        INCOMING_REQUEST_COUNTER.inc();

        println!("{:?}", req.uri());

        let changed_req = self.change_request(req).await;
        let changed_req_headers = changed_req.headers().clone();
        let target_service_resp = Client::new().request(changed_req).await.map_err(|e| {
            let host = changed_req_headers.get("host").unwrap();

            eprintln!("Service with host: `{:?}` returns {:?}", host, e);

            TARGET_SERVICE_ERROR_COUNTER
                .with_label_values(&[host.to_str().unwrap()])
                .inc();

            hyper::Error::from(e)
        });

        Ok(self.change_response(target_service_resp.unwrap()).await)
    }
}

async fn proccess(proxy: Proxy, req: Request<Body>) -> Result<Response<Body>, hyper::Error> {
    proxy.handle_request(req).await
}

pub async fn run(config: Config, cache: Cache) {
    let addr = config.clone().proxy_addr.unwrap().parse().unwrap();

    let proxy = Proxy::new(config.clone(), cache);

    let make_service = make_service_fn(move |_| {
        let p = proxy.clone();
        async move { Ok::<_, hyper::Error>(service_fn(move |req| proccess(p.clone(), req))) }
    });

    let server = HTTPServer::bind(&addr).serve(make_service);

    println!("START PROXY ON ADDRESS: {}", addr);

    if let Err(e) = server.await {
        eprintln!("Fatal err {}", e)
    }
}
