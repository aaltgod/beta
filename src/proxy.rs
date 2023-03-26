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
            Err(e) => {
                error!("parse host error: {}", e);
                return uri;
            }
        };

        let mut changed_uri = Uri::builder().scheme("http").authority(host);

        let split: Vec<&str> = host.split(":").collect();
        let port: u32 = match split[1].trim().parse() {
            Ok(res) => res,
            Err(e) => {
                error!("parse port error: {}", e);
                return uri;
            }
        };

        for target in self.config.targets.iter() {
            if port == target.port {
                changed_uri = changed_uri.authority(target.team_ip.clone() + ":" + split[1]);
            }
        }

        let path = match uri.path_and_query() {
            Some(res) => res.as_str(),
            None => return uri,
        };

        if helpers::contains_flag(path) {
            info!("TO CHANGE URI:  {:?}", FLAG_REGEX.clone().captures(path));

            let captures = match FLAG_REGEX.clone().captures(path) {
                Some(res) => res,
                None => {
                    warn!("change_uri couldn't capture with path: {}", path);

                    return uri;
                }
            };

            // TODO: add flags replacement when its more 1
            if captures.len() == 1 {
                // FIXME: extra trip to redis if f == ""
                let flag = captures.get(0).map_or("", |f| f.as_str());
                let new_flag = helpers::build_flag(false);
                let flag_from_cache = match self.cache.get_flag(flag.to_string()).await {
                    Ok(f) => f,
                    Err(e) => {
                        error!("change_uri get_flag error: {}", e);
                        return uri;
                    }
                };

                info!("GOT FLAG IN URI {:?}", flag);

                let mut changed_path: String = "".to_string();

                if flag_from_cache.len() == 0 {
                    let _result = match self
                        .cache
                        .set_flag(flag.to_string(), new_flag.clone())
                        .await
                    {
                        Ok(()) => info!("OK set: flag - new_flag"),
                        Err(e) => {
                            error!("change_uri set_flag flag - new_flag error: {}", e);
                            return uri;
                        }
                    };

                    let _result = match self
                        .cache
                        .set_flag(new_flag.clone(), flag.to_string())
                        .await
                    {
                        Ok(()) => info!("OK set new_flag - flag"),
                        Err(e) => {
                            error!("change_uri set_flag new_flag - flag error: {}", e);
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

                info!("CHANGED URI:  {:?}", changed_path);

                let result = match changed_uri.path_and_query(changed_path).build() {
                    Ok(res) => res,
                    Err(e) => {
                        error!(
                            "change_uri build changed_uri with changed_path error: {}",
                            e
                        );
                        return uri;
                    }
                };

                return result;
            };
        };

        let result = match changed_uri.path_and_query(path).build() {
            Ok(res) => res,
            Err(e) => {
                error!("change_uri build changed_uri with path error: {}", e);
                return uri;
            }
        };

        result
    }

    async fn change_request_body(&self, body_bytes: Bytes) -> Result<Body, hyper::Error> {
        if !body_bytes.is_empty() {
            let text_body = match std::str::from_utf8(&body_bytes) {
                Ok(res) => res,
                Err(e) => {
                    error!("change_request_body from_utf8 error: {}", e);
                    return Ok(Body::from(body_bytes));
                }
            };

            if helpers::contains_flag(text_body) {
                info!("TO CHANGE REQUEST BODY: {:?}", text_body);

                let mut result_body = text_body.to_string();

                for flag in FLAG_REGEX.clone().find_iter(text_body) {
                    let flag_from_cache = match self.cache.get_flag(flag.as_str().to_string()).await
                    {
                        Ok(f) => f,
                        Err(e) => {
                            error!("change_request_body get_flag flag_from_cache error: {}", e);
                            return Ok(Body::from(body_bytes));
                        }
                    };

                    if flag_from_cache.len() == 0 {
                        let new_flag = helpers::build_flag(false);

                        let _result = match self
                            .cache
                            .set_flag(flag.as_str().to_string(), new_flag.clone())
                            .await
                        {
                            Ok(()) => info!("ok flag - new_flag"),
                            Err(e) => {
                                error!("change_request_body set_flag flag - new_flag error: {}", e);
                                return Ok(Body::from(body_bytes));
                            }
                        };

                        let _result = match self
                            .cache
                            .set_flag(new_flag.clone(), flag.as_str().to_string())
                            .await
                        {
                            Ok(()) => info!("ok new_flag - flag"),
                            Err(e) => {
                                error!("change_request_body set_flag new_flag - flag error: {}", e);
                                return Ok(Body::from(body_bytes));
                            }
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

                info!("CHANGED REQUEST BODY: {:?}", result_body);

                return Ok(Body::wrap_stream(stream));
            }

            Ok(Body::from(body_bytes.clone()))
        } else {
            Ok(Body::empty())
        }
    }

    async fn change_response_body(&self, body_bytes: Bytes) -> (Result<Body, hyper::Error>, usize) {
        if !body_bytes.is_empty() {
            let body_bytes_length = body_bytes.clone().len();
            let text_body = match std::str::from_utf8(&body_bytes) {
                Ok(res) => res,
                Err(e) => {
                    error!("change_response_body from_utf8 error: {}", e);
                    return (Ok(Body::from(body_bytes)), body_bytes_length);
                }
            };

            if helpers::contains_flag(text_body) {
                info!("TO CHANGE RESPONSE BODY: {:?}", text_body);

                let mut result_body = text_body.to_string();

                for flag in FLAG_REGEX.clone().find_iter(text_body) {
                    let flag_from_cache = match self.cache.get_flag(flag.as_str().to_string()).await
                    {
                        Ok(f) => f,
                        Err(e) => {
                            error!("change_response_body get_flag flag_from_cache error: {}", e);
                            return (Ok(Body::from(body_bytes)), body_bytes_length);
                        }
                    };

                    if flag_from_cache.len() != 0 {
                        result_body = result_body
                            .replace(flag.as_str(), flag_from_cache.as_str())
                            .to_string();
                    } else {
                        warn!("couldn't find flag: {:?}", flag)
                    }
                }

                info!("CHANGED RESPONE BODY: {:?}", result_body);

                // TODO: add Full, Empty, Stream
                return (Ok(Body::from(result_body.clone())), result_body.len());
            }

            (Ok(Body::from(body_bytes)), body_bytes_length)
        } else {
            (Ok(Body::empty()), 0)
        }
    }

    async fn change_request(&self, req: Request<Body>) -> Request<Body> {
        info!("REQ {:?}", &req);

        let mut req = req;
        let headers = req.headers().clone();
        let uri = req.uri().clone();
        let body = req.body_mut();

        let body_bytes = match hyper::body::to_bytes(body).await {
            Ok(res) => res,
            Err(e) => {
                error!("change_request to_bytes error: {}", e);
                return req;
            }
        };

        let changed_request_body = match self.change_request_body(body_bytes).await {
            Ok(res) => res,
            Err(e) => {
                error!("change_request.change_request_body error: {}", e);
                return req;
            }
        };

        let host = match headers.get("host") {
            Some(res) => res,
            None => {
                warn!("change_request couldn't get host: {:?}", &headers);
                return req;
            }
        };

        // TODO: add error returning to change_uri
        let changed_uri = self.change_uri(uri, host).await;

        *req.body_mut() = changed_request_body;
        *req.uri_mut() = changed_uri;

        info!("CHANGED RESP {:?}", &req);

        PROCESSED_REQUEST_COUNTER.with_label_values(&["OK"]).inc();

        return req;
    }

    async fn change_response(&self, resp: Response<Body>) -> Response<Body> {
        info!("RESP {:?}", &resp);

        let mut resp = resp;
        let mut headers = resp.headers().clone();
        let body = match hyper::body::to_bytes(resp.body_mut()).await {
            Ok(res) => res,
            Err(e) => {
                error!("change_response to_bytes error: {}", e);
                return resp;
            }
        };

        let (new_body, new_body_length) = self.change_response_body(body).await;

        let new_body = match new_body {
            Ok(res) => res,
            Err(e) => {
                error!("change_response.chabnge_response_body error: {}", e);
                return resp;
            }
        };
        let new_body_length = match new_body_length.to_string().parse() {
            Ok(res) => res,
            Err(e) => {
                error!("change_response new_body_length parse error: {}", e);
                return resp;
            }
        };

        headers.insert(hyper::header::CONTENT_LENGTH, new_body_length);

        *resp.body_mut() = new_body;
        *resp.headers_mut() = headers;

        info!("CHANGED RESP {:?}", &resp);

        PROCESSED_RESPONSE_COUNTER.with_label_values(&["OK"]).inc();

        resp
    }

    pub async fn handle_request(&self, req: Request<Body>) -> Result<Response<Body>, hyper::Error> {
        INCOMING_REQUEST_COUNTER.inc();

        info!("{:?}", req.uri());

        let changed_req = self.change_request(req).await;
        let changed_req_headers = changed_req.headers().clone();
        let target_service_resp = match Client::new().request(changed_req).await {
            Ok(res) => res,
            Err(e) => {
                let host = match changed_req_headers.get("host") {
                    // FIXME: handle it
                    Some(res) => res.to_str().unwrap(),
                    None => {
                        error!("handle_request get host error: {:?}", changed_req_headers);

                        "error host"
                    }
                };

                error!("Service with host: `{}` returns {:?}", host, e);

                TARGET_SERVICE_ERROR_COUNTER
                    .with_label_values(&[host])
                    .inc();

                return Ok(Response::default());
            }
        };

        Ok(self.change_response(target_service_resp).await)
    }
}

async fn proccess(proxy: Proxy, req: Request<Body>) -> Result<Response<Body>, hyper::Error> {
    proxy.handle_request(req).await
}

pub async fn run(config: Config, cache: Cache) {
    let addr = config
        .clone()
        .proxy_addr
        .parse()
        .expect("couldn't parse proxy address");

    let proxy = Proxy::new(config.clone(), cache);

    let make_service = make_service_fn(move |_| {
        let p = proxy.clone();
        async move { Ok::<_, hyper::Error>(service_fn(move |req| proccess(p.clone(), req))) }
    });

    let server = HTTPServer::bind(&addr).serve(make_service);

    info!("START PROXY ON ADDRESS: {}", addr);

    if let Err(e) = server.await {
        error!("Fatal err {}", e);
    }
}
