use bytes::Bytes;

use hyper::http::HeaderValue;
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Client, Request, Response, Server as HTTPServer, Uri};

use crate::cache::Cache;
use crate::helpers;
use crate::metrics::INCOMING_REQUESTS;
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
        let mut changed_uri = Uri::builder()
            .scheme("http")
            .authority(host.to_str().unwrap());

        let split: Vec<&str> = host.to_str().unwrap().split(":").collect();
        let port: u32 = split[1].trim().parse().expect("couldn't parse port");

        for s in self.config.settings.iter() {
            let s_port = match s.port {
                Some(p) => p,
                None => 0,
            };

            if port == s_port {
                let s_team_ip = match s.team_ip.clone() {
                    Some(ip) => ip,
                    None => split[0].to_string(),
                };

                changed_uri = changed_uri.authority(s_team_ip + ":" + split[1]);
            }
        }

        let path = uri.path_and_query().unwrap().as_str();

        if !helpers::FLAG_REGEX.captures(path).is_none() {
            println!("TO CHANGE URI:  {:?}", helpers::FLAG_REGEX.captures(path));

            // TODO: add flags replacement when its more 1
            if helpers::FLAG_REGEX.captures(path).unwrap().len() == 1 {
                let flag = helpers::FLAG_REGEX
                    .captures(path)
                    .unwrap()
                    .get(0)
                    .map_or("", |f| f.as_str());
                let new_flag = helpers::build_flag(false);

                let flag_from_cache = match self.cache.get_flag(flag.to_string()).await {
                    Ok(f) => f,
                    Err(_) => {
                        return changed_uri
                            .path_and_query(path)
                            .build()
                            .expect("build default uri")
                    }
                };
                println!("GOT FLAG IN URI {:?}", flag);

                let mut changed_path: String = "".to_string();

                if flag_from_cache.len() == 0 {
                    let _result = match self
                        .cache
                        .set_flag(flag.to_string(), new_flag.clone())
                        .await
                    {
                        Ok(()) => println!("ok flag - new_flag"),
                        Err(e) => println!("{:?}", e),
                    };

                    let _result = match self
                        .cache
                        .set_flag(new_flag.clone(), flag.to_string())
                        .await
                    {
                        Ok(()) => println!("ok new_flag - flag"),
                        Err(e) => println!("{:?}", e),
                    };

                    changed_path = helpers::FLAG_REGEX.replace_all(path, new_flag).to_string();
                } else {
                    changed_path = helpers::FLAG_REGEX
                        .replace_all(path, flag_from_cache)
                        .to_string();
                }

                println!("CHANGED URI:  {:?}", changed_path);

                return changed_uri
                    .path_and_query(changed_path)
                    .build()
                    .expect("build new uri");
            };
        }

        changed_uri
            .path_and_query(path)
            .build()
            .expect("build default uri")
    }

    async fn change_request_body(&self, body_bytes: Bytes) -> Result<Body, hyper::Error> {
        if !body_bytes.is_empty() {
            let text_body = std::str::from_utf8(&body_bytes).unwrap();
            // TODO: add flag on flag replacing
            // probably do it in also url query, json;

            if !helpers::ENCODED_FLAG_REGEX.captures(text_body).is_none() {
                println!("TO CHANGE REQUEST BODY: {:?}", text_body);

                // TODO: add flags replacement when its more 1
                if helpers::ENCODED_FLAG_REGEX
                    .captures(text_body)
                    .unwrap()
                    .len()
                    == 1
                {
                    let flag = helpers::ENCODED_FLAG_REGEX
                        .captures(text_body)
                        .unwrap()
                        .get(0)
                        .map_or("", |f| f.as_str());
                    let new_flag = helpers::build_flag(true);

                    let flag_from_cache = match self.cache.get_flag(flag.to_string()).await {
                        Ok(f) => f,
                        Err(_) => return Ok(Body::from(body_bytes)),
                    };

                    let mut changed_text_body: String = "".to_string();

                    if flag_from_cache.len() == 0 {
                        let _result = match self
                            .cache
                            .set_flag(flag.to_string(), new_flag.clone())
                            .await
                        {
                            Ok(()) => println!("ok flag - new_flag"),
                            Err(e) => println!("{:?}", e),
                        };

                        let _result = match self
                            .cache
                            .set_flag(new_flag.clone(), flag.to_string())
                            .await
                        {
                            Ok(()) => println!("ok new_flag - flag"),
                            Err(e) => println!("{:?}", e),
                        };

                        changed_text_body = helpers::ENCODED_FLAG_REGEX
                            .replace(text_body, new_flag)
                            .to_string();
                    } else {
                        changed_text_body = helpers::ENCODED_FLAG_REGEX
                            .replace(text_body, flag_from_cache)
                            .to_string();
                    }

                    let chunks: Vec<Result<_, std::io::Error>> =
                        vec![Ok(changed_text_body.clone())];
                    let stream = futures::stream::iter(chunks);

                    println!("CHANGED REQUEST BODY: {:?}", changed_text_body);

                    return Ok(Body::wrap_stream(stream));
                }
            }

            Ok(Body::from(body_bytes))
        } else {
            Ok(Body::empty())
        }
    }

    async fn change_response_body(&self, body_bytes: Bytes) -> (Result<Body, hyper::Error>, usize) {
        if !body_bytes.is_empty() {
            let text_body = std::str::from_utf8(&body_bytes).unwrap();
            let body_bytes_length = body_bytes.clone().len();

            // TODO: add flag on flag replacing
            // probably do it in also url query, json;

            if !helpers::FLAG_REGEX.captures(text_body).is_none() {
                println!("TO CHANGE RESPONSE BODY: {:?}", text_body);

                // TODO: add flags replacement when its more 1
                if helpers::FLAG_REGEX.captures(text_body).unwrap().len() == 1 {
                    let flag = helpers::FLAG_REGEX
                        .captures(text_body)
                        .unwrap()
                        .get(0)
                        .map_or("", |f| f.as_str());

                    let flag_from_cache = match self.cache.get_flag(flag.to_string()).await {
                        Ok(f) => f,
                        Err(_) => return (Ok(Body::from(body_bytes)), body_bytes_length),
                    };

                    if flag_from_cache != "".to_string() {
                        let changed_text_body = helpers::FLAG_REGEX
                            .replace(text_body, flag_from_cache)
                            .to_string();

                        println!("CHANGED RESPONE BODY: {:?}", changed_text_body);

                        return (
                            Ok(Body::from(changed_text_body.to_owned())),
                            changed_text_body.len(),
                        );
                    }
                }
            }

            (Ok(Body::from(body_bytes)), body_bytes_length)
        } else {
            (Ok(Body::empty()), 0)
        }
    }

    async fn change_request(
        &self,
        req: Request<Body>,
    ) -> Result<Request<Body>, hyper::http::Error> {
        dbg!(&req.body());
        let mut req = req;
        let headers = req.headers().clone();
        let uri = req.uri().clone();
        let body = req.body_mut();

        let body_bytes = hyper::body::to_bytes(body)
            .await
            .expect("change request body bytes");

        *req.body_mut() = self.change_request_body(body_bytes.clone()).await.unwrap();
        *req.uri_mut() = self.change_uri(uri, headers.get("host").unwrap()).await;

        dbg!(&req);

        Ok(req)
    }

    async fn change_response(
        &self,
        resp: Response<Body>,
    ) -> Result<Response<Body>, hyper::http::Error> {
        let mut resp = resp;
        let mut headers = resp.headers().clone();
        let body = resp.body_mut();

        let (new_body, new_body_length) = self
            .change_response_body(hyper::body::to_bytes(body).await.expect("body to bytes"))
            .await;

        headers.insert(
            hyper::header::CONTENT_LENGTH,
            new_body_length.to_string().parse().unwrap(),
        );

        *resp.headers_mut() = headers;
        *resp.body_mut() = new_body.unwrap();

        Ok(resp)
    }

    pub async fn handle_request(&self, req: Request<Body>) -> Result<Response<Body>, hyper::Error> {
        INCOMING_REQUESTS.inc();

        println!("{:?}", req.uri());

        let changed_req = self.change_request(req).await.unwrap();
        let service_resp = Client::new().request(changed_req).await.map_err(|e| {
            eprintln!("{:?}", e);
            hyper::Error::from(e)
        });

        Ok(self.change_response(service_resp.unwrap()).await.unwrap())
    }
}

async fn proccess(proxy: Proxy, req: Request<Body>) -> Result<Response<Body>, hyper::Error> {
    proxy.handle_request(req).await
}

pub async fn run(config: Config, cache: Cache) {
    let addr = match &config.proxy_addr {
        Some(addr) => addr.parse().unwrap(),
        None => return eprintln!("proxy address is not set"),
    };

    if config.service_ports.len() == 0 {
        return eprintln!("service ports are not set");
    }

    if config.team_ips.len() == 0 {
        return eprintln!("team ips are no set");
    }

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
