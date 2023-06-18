use std::fmt::Error as fmtError;
use std::time::Duration;

use hyper::http::HeaderValue;
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Client, Request, Response, Server as HTTPServer, Uri};

use crate::cache::Cache;
use crate::errors::Error;
use crate::helpers;
use crate::helpers::FLAG_REGEX;
use crate::metrics::{
    CHANGED_REQUEST_COUNTER, CHANGED_RESPONSE_COUNTER, HANDLED_REQUEST_COUNTER,
    INCOMING_REQUEST_COUNTER, TARGET_SERVICE_STATUS_COUNTER,
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

    async fn change_uri(&self, uri: Uri, host: HeaderValue) -> Result<Uri, Error> {
        let host = match host.to_str() {
            Ok(res) => res,
            Err(e) => {
                return Err(Error::Changer {
                    method_name: "host.to_str".to_string(),
                    description: "couldn't parse host".to_string(),
                    error_text: e.to_string(),
                });
            }
        };

        info!("HOST {}", host);

        let split: Vec<&str> = host.split(":").collect();
        if split.len() != 2 {
            return Err(Error::Changer {
                method_name: "host.split".to_string(),
                description: "host is invalid".to_string(),
                error_text: fmtError::default().to_string(),
            });
        }

        let port: u32 = match split[1].trim().parse() {
            Ok(res) => res,
            Err(e) => {
                return Err(Error::Changer {
                    method_name: "split.parse".to_string(),
                    description: "couldn't parse port".to_string(),
                    error_text: e.to_string(),
                });
            }
        };

        let mut changed_uri = Uri::builder().scheme("http").authority(host);

        for target in self.config.targets.iter() {
            if port == target.port {
                changed_uri = changed_uri.authority(target.team_ip.clone() + ":" + split[1]);

                break;
            }
        }

        let path = match uri.path_and_query() {
            Some(res) => res.as_str(),
            None => {
                return Err(Error::Changer {
                    method_name: "uri.path_and_query".to_string(),
                    description: "path is None".to_string(),
                    error_text: fmtError::default().to_string(),
                })
            }
        };

        if helpers::contains_flag(path) {
            info!("TO CHANGE PATH:  {:?}", FLAG_REGEX.clone().captures(path));

            let captures = match FLAG_REGEX.clone().captures(path) {
                Some(res) => res,
                None => {
                    return Err(Error::Changer {
                        method_name: "FLAG_REGEX.captures".to_string(),
                        description: format!("couldn't capture with path: {}", path),
                        error_text: fmtError::default().to_string(),
                    });
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
                        return Err(Error::Changer {
                            method_name: "cache.get_flag".to_string(),
                            description: "couldn't get flag from cache".to_string(),
                            error_text: e.to_string(),
                        });
                    }
                };

                info!("GOT FLAG IN PATH {:?}", flag);

                let changed_path: String;

                if flag_from_cache.len() == 0 {
                    let _result = match self
                        .cache
                        .set_flag(flag.to_string(), new_flag.clone())
                        .await
                    {
                        Ok(()) => info!("OK set: flag - new_flag"),
                        Err(e) => {
                            return Err(Error::Changer {
                                method_name: "cache.set_flag".to_string(),
                                description: "couldn't set `flag: new_flag` in cache".to_string(),
                                error_text: e.to_string(),
                            });
                        }
                    };

                    let _result = match self
                        .cache
                        .set_flag(new_flag.clone(), flag.to_string())
                        .await
                    {
                        Ok(()) => info!("OK set new_flag - flag"),
                        Err(e) => {
                            return Err(Error::Changer {
                                method_name: "cache.set_flag".to_string(),
                                description: "couldn't set `new_flag: flag` in cache".to_string(),
                                error_text: e.to_string(),
                            });
                        }
                    };

                    changed_path = FLAG_REGEX.clone().replace_all(path, new_flag).to_string();
                } else {
                    changed_path = FLAG_REGEX
                        .clone()
                        .replace_all(path, flag_from_cache)
                        .to_string();
                }

                info!("CHANGED PATH:  {:?}", changed_path);

                let result = match changed_uri.path_and_query(changed_path).build() {
                    Ok(res) => res,
                    Err(e) => {
                        return Err(Error::Changer {
                            method_name: "changed_uri.build".to_string(),
                            description: "couldn't build changed_uri with changed_path".to_string(),
                            error_text: e.to_string(),
                        });
                    }
                };

                return Ok(result);
            };
        };

        let result = match changed_uri.path_and_query(path).build() {
            Ok(res) => res,
            Err(e) => {
                error!("change_uri build chnaged_uri error: {}", e);
                return Err(Error::Changer {
                    method_name: "changed_uri.build".to_string(),
                    description: "couldn't build changed_uri with path".to_string(),
                    error_text: e.to_string(),
                });
            }
        };

        Ok(result)
    }

    async fn change_request_body(&self, body: &mut Body) -> Result<Body, Error> {
        let body_bytes = match hyper::body::to_bytes(body).await {
            Ok(res) => res,
            Err(e) => {
                return Err(Error::Changer {
                    method_name: "to_bytes".to_string(),
                    description: "couldn't make body to bytes".to_string(),
                    error_text: e.to_string(),
                });
            }
        };

        if !body_bytes.is_empty() {
            let text_body = match std::str::from_utf8(&body_bytes) {
                Ok(res) => res,
                Err(e) => {
                    return Err(Error::Changer {
                        method_name: "from_utf8".to_string(),
                        description: "couldn't make body_bytes to str".to_string(),
                        error_text: e.to_string(),
                    });
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
                            return Err(Error::Changer {
                                method_name: "cache.get_flag".to_string(),
                                description: "couldn't get flag from cache".to_string(),
                                error_text: e.to_string(),
                            });
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
                                return Err(Error::Changer {
                                    method_name: "cache.set_flag".to_string(),
                                    description: "couldn't set `flag: new_flag` in cache"
                                        .to_string(),
                                    error_text: e.to_string(),
                                });
                            }
                        };

                        let _result = match self
                            .cache
                            .set_flag(new_flag.clone(), flag.as_str().to_string())
                            .await
                        {
                            Ok(()) => info!("ok new_flag - flag"),
                            Err(e) => {
                                return Err(Error::Changer {
                                    method_name: "cache.set_flag".to_string(),
                                    description: "couldn't set `new_flag: flag` in cache"
                                        .to_string(),
                                    error_text: e.to_string(),
                                });
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

            Ok(Body::from(body_bytes))
        } else {
            Ok(Body::empty())
        }
    }

    async fn change_response_body(&self, body: &mut Body) -> (Result<Body, Error>, usize) {
        let body_bytes = match hyper::body::to_bytes(body).await {
            Ok(res) => res,
            Err(e) => {
                return (
                    Err(Error::Changer {
                        method_name: "to_bytes".to_string(),
                        description: "couldn't make body to bytes".to_string(),
                        error_text: e.to_string(),
                    }),
                    0,
                );
            }
        };

        if !body_bytes.is_empty() {
            let body_bytes_length = body_bytes.clone().len();
            let text_body = match std::str::from_utf8(&body_bytes) {
                Ok(res) => res,
                Err(e) => {
                    return (
                        Err(Error::Changer {
                            method_name: "from_utf8".to_string(),
                            description: "couldn't make body_bytes to str".to_string(),
                            error_text: e.to_string(),
                        }),
                        0,
                    );
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
                            return (
                                Err(Error::Changer {
                                    method_name: "cache.get_flag".to_string(),
                                    description: "couldn't get flag from cache".to_string(),
                                    error_text: e.to_string(),
                                }),
                                0,
                            );
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

                let chunks: Vec<Result<_, std::io::Error>> = vec![Ok(result_body.clone())];

                let stream = futures_util::stream::iter(chunks);

                // TODO: add Full, Empty, Stream
                return (Ok(Body::wrap_stream(stream)), result_body.len());
            }

            (Ok(Body::from(body_bytes)), body_bytes_length)
        } else {
            (Ok(Body::empty()), 0)
        }
    }

    async fn change_request(&self, req: &mut Request<Body>) -> Result<(), Error> {
        info!("REQ {:?}", req);

        let mut headers = req.headers().clone();
        let uri = req.uri().clone();
        let body = req.body_mut();

        let changed_request_body = match self.change_request_body(body).await {
            Ok(res) => res,
            Err(e) => {
                return Err(Error::Changer {
                    method_name: "change_request_body".to_string(),
                    description: "coudn't change request body".to_string(),
                    error_text: e.to_string(),
                });
            }
        };

        let host = match headers.get("host") {
            Some(res) => res,
            None => {
                return Err(Error::Changer {
                    method_name: "headers.get".to_string(),
                    description: "couldn't get host".to_string(),
                    error_text: "None".to_string(),
                });
            }
        };

        let changed_uri = match self.change_uri(uri, host.clone()).await {
            Ok(res) => res,
            Err(e) => {
                return Err(Error::Changer {
                    method_name: "change_uri".to_string(),
                    description: "couldn't change uri".to_string(),
                    error_text: e.to_string(),
                });
            }
        };

        info!("CHANGED URI {:?}", changed_uri);

        let mut changed_host = changed_uri.host().unwrap().to_string();
        changed_host.push_str(":");
        changed_host.push_str(changed_uri.port().unwrap().as_str());

        headers.insert(
            "host",
            HeaderValue::from_str(changed_host.as_str()).unwrap(),
        );

        *req.body_mut() = changed_request_body;
        *req.uri_mut() = changed_uri;
        *req.headers_mut() = headers;

        info!("CHANGED REQ {:?}", req);

        return Ok(());
    }

    async fn change_response(&self, resp: &mut Response<Body>) -> Result<(), Error> {
        info!("RESP {:?}", resp);

        let mut headers = resp.headers().clone();
        let (new_body, new_body_length) = self.change_response_body(resp.body_mut()).await;

        let new_body = match new_body {
            Ok(res) => res,
            Err(e) => {
                return Err(Error::Changer {
                    method_name: "change_response_body".to_string(),
                    description: "couldn't get new_body".to_string(),
                    error_text: e.to_string(),
                });
            }
        };

        headers.insert(
            hyper::header::CONTENT_LENGTH,
            // TODO: add error handling(probably)
            HeaderValue::from_str(new_body_length.to_string().as_str()).unwrap(),
        );

        *resp.body_mut() = new_body;
        *resp.headers_mut() = headers;

        info!("CHANGED RESP {:?}", &resp);

        Ok(())
    }

    pub async fn handle_request(&self, req: Request<Body>) -> Result<Response<Body>, Error> {
        INCOMING_REQUEST_COUNTER.inc();

        info!("handle_request URI {:?}", req.uri());

        let mut req = req;

        // TODO: if change_request returns, need to skip (original) request above maybe 
        let changed_req = match self.change_request(&mut req).await {
            Ok(_) => {
                CHANGED_REQUEST_COUNTER.with_label_values(&["OK"]).inc();

                req
            }
            Err(e) => {
                CHANGED_REQUEST_COUNTER.with_label_values(&["FAIL"]).inc();

                return Err(Error::Changer {
                    method_name: "change_request".to_string(),
                    description: "couldn't change request ".to_string(),
                    error_text: e.to_string(),
                });
            }
        };

        let changed_req_headers = changed_req.headers().clone();

        let host = match changed_req_headers.get("host") {
            // FIXME: handle it
            Some(res) => res.to_str().unwrap(),
            None => {
                return Err(Error::Changer {
                    method_name: "changed_req_headers.get".to_string(),
                    description: format!(
                        "couldn't get host from changed_req_headers: `{:?}`",
                        changed_req_headers
                    ),
                    error_text: fmtError::default().to_string(),
                });
            }
        };

        info!("TARGET HOST {}", host);

        let mut target_service_resp = match Client::builder()
            .pool_idle_timeout(Duration::from_secs(10))
            .build_http()
            .request(changed_req)
            .await
        {
            Ok(res) => {
                TARGET_SERVICE_STATUS_COUNTER
                    .with_label_values(&[host, "OK"])
                    .inc();

                res
            }
            Err(e) => {
                TARGET_SERVICE_STATUS_COUNTER
                    .with_label_values(&[host, "ERROR"])
                    .inc();

                return Err(Error::Changer {
                    method_name: "request".to_string(),
                    description: format!("target service with host `{}` returned `{:?}`", host, e),
                    error_text: e.to_string(),
                });
            }
        };

        match self.change_response(&mut target_service_resp).await {
            Ok(_) => {
                CHANGED_RESPONSE_COUNTER.with_label_values(&["OK"]).inc();

                Ok(target_service_resp)
            }
            Err(e) => {
                error!("couldn't change response {}", e);

                CHANGED_RESPONSE_COUNTER.with_label_values(&["FAIL"]).inc();

                return Ok(target_service_resp);
            }
        }
    }
}

async fn proccess(proxy: Proxy, req: Request<Body>) -> Result<Response<Body>, hyper::Error> {
    match proxy.handle_request(req).await {
        Ok(res) => {
            HANDLED_REQUEST_COUNTER.with_label_values(&["OK"]).inc();

            Ok(res)
        }
        Err(e) => {
            error!("couldn't handle request: {}", e);

            HANDLED_REQUEST_COUNTER.with_label_values(&["ERROR"]).inc();

            Ok(hyper::Response::default())
        }
    }
}

pub async fn run(config: Config, cache: Cache) {
    let addr = config
        .clone()
        .proxy_addr
        .parse()
        .expect("couldn't parse proxy address");

    let proxy = Proxy::new(config, cache);

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
