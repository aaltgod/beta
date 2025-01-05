use std::num::ParseIntError;
use std::sync::Arc;
use std::time::Duration;

use anyhow::anyhow;
use http::uri::Scheme;
use hyper::http::HeaderValue;
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Client, Request, Response, Server as HTTPServer, Uri};
use lazy_static::lazy_static;

use crate::errors::ServerError;
use crate::helpers;
use crate::helpers::FLAG_REGEX;
use crate::metrics::{
    CHANGED_REQUEST_COUNTER, CHANGED_RESPONSE_COUNTER, HANDLED_REQUEST_COUNTER,
    INCOMING_REQUEST_COUNTER, TARGET_SERVICE_STATUS_COUNTER,
};
use crate::traits::{Storage, TargetsProvider};

lazy_static! {
    pub static ref HEADER_VALUE_URL_ENCODED: HeaderValue =
        HeaderValue::from_str("application/x-www-form-urlencoded")
            .expect("invalid HEADER_VALUE_URL_ENCODED");
}

pub struct Server {
    config: Arc<dyn TargetsProvider + Send + Sync>,
    cache: Arc<dyn Storage + Send + Sync>,
}

impl Server {
    pub fn new(
        config: Arc<dyn TargetsProvider + Send + Sync>,
        cache: Arc<dyn Storage + Send + Sync>,
    ) -> Self {
        Server { config, cache }
    }

    async fn process_flag_pair(&self, flag: &str, new_flag: &str) -> Result<(), ServerError> {
        self.cache
            .set_flag(flag.to_string(), new_flag.to_string())
            .await
            .map_err(|e| ServerError::Changer {
                method_name: "cache.set_flag".to_string(),
                description: "couldn't set `flag: new_flag` in cache".to_string(),
                error: e.into(),
            })?;

        info!("ok flag - new_flag");

        self.cache
            .set_flag(new_flag.to_string(), flag.to_string())
            .await
            .map_err(|e| ServerError::Changer {
                method_name: "cache.set_flag".to_string(),
                description: "couldn't set `new_flag: flag` in cache".to_string(),
                error: e.into(),
            })?;

        info!("ok new_flag - flag");

        Ok(())
    }

    async fn change_uri(
        &self,
        uri: &mut Uri,
        host: &str,
        scheme: Scheme,
    ) -> Result<(), ServerError> {
        info!("HOST {}", host);

        let changed_uri_builder = Uri::builder().scheme(scheme).authority(host);

        let path = match uri.path_and_query() {
            Some(res) => res.as_str(),
            None => {
                return Err(ServerError::Changer {
                    method_name: "uri.path_and_query".to_string(),
                    description: "path is None".to_string(),
                    error: anyhow!("Path is None"),
                })
            }
        };

        if helpers::contains_flag(path) {
            info!("TO CHANGE PATH:  {:?}", FLAG_REGEX.clone().captures(path));

            let mut changed_path = path.to_string();

            for flag in FLAG_REGEX.clone().find_iter(path) {
                let flag_from_cache = match self.cache.get_flag(flag.as_str().to_string()).await {
                    Ok(f) => f,
                    Err(e) => {
                        return Err(ServerError::Changer {
                            method_name: "cache.get_flag".to_string(),
                            description: "couldn't get flag from cache".to_string(),
                            error: e.into(),
                        });
                    }
                };

                info!("GOT FLAG IN PATH {:?}", flag);

                if flag_from_cache.len() == 0 {
                    let new_flag = helpers::build_flag(false);

                    self.process_flag_pair(flag.as_str(), new_flag.as_str())
                        .await
                        .map_err(|e| ServerError::Changer {
                            method_name: "process_flag_pair".to_string(),
                            description: "couldn't process flag pair".to_string(),
                            error: e.into(),
                        })?;

                    changed_path = FLAG_REGEX.clone().replace(path, new_flag).to_string();
                } else {
                    changed_path = FLAG_REGEX
                        .clone()
                        .replace(path, flag_from_cache)
                        .to_string();
                }

                info!("CHANGED PATH:  {:?}", changed_path);
            }

            *uri = changed_uri_builder
                .path_and_query(changed_path)
                .build()
                .map_err(|e| ServerError::Changer {
                    method_name: "changed_uri.build".to_string(),
                    description: "couldn't build changed_uri with changed_path".to_string(),
                    error: e.into(),
                })?;

            return Ok(());
        };

        *uri = changed_uri_builder
            .path_and_query(path)
            .build()
            .map_err(|e| ServerError::Changer {
                method_name: "changed_uri.build".to_string(),
                description: "couldn't build changed_uri with path".to_string(),
                error: e.into(),
            })?;

        Ok(())
    }

    async fn change_request_body(
        &self,
        body: &mut Body,
        encoded: bool,
    ) -> Result<Body, ServerError> {
        warn!("{encoded} {:?}", body);

        let body_bytes = hyper::body::to_bytes(body)
            .await
            .map_err(|e| ServerError::Changer {
                method_name: "to_bytes".to_string(),
                description: "couldn't make body to bytes".to_string(),
                error: e.into(),
            })?;

        if !body_bytes.is_empty() {
            let text_body = std::str::from_utf8(&body_bytes).map_err(|e| ServerError::Changer {
                method_name: "from_utf8".to_string(),
                description: "couldn't make body_bytes to str".to_string(),
                error: e.into(),
            })?;

            warn!("TEXT_BODY: {:?}", text_body);

            // TODO: add Full, Empty, Stream
            let mut chunks: Vec<Result<String, std::io::Error>> = vec![];

            if encoded {
                let pairs = url::form_urlencoded::parse(&body_bytes);

                for (i, (key, value)) in pairs.into_iter().enumerate() {
                    let mut changed_value = value.to_string();

                    for flag in FLAG_REGEX.clone().find_iter(value.as_ref()) {
                        let flag_from_cache = self
                            .cache
                            .get_flag(flag.as_str().to_string())
                            .await
                            .map_err(|e| ServerError::Changer {
                                method_name: "cache.get_flag".to_string(),
                                description: "couldn't get flag from cache".to_string(),
                                error: e.into(),
                            })?;

                        warn!("FLAG : {:?}", flag_from_cache);

                        if flag_from_cache.len() == 0 {
                            let new_flag = helpers::build_flag(false);

                            self.process_flag_pair(flag.as_str(), new_flag.as_str())
                                .await
                                .map_err(|e| ServerError::Changer {
                                    method_name: "process_flag_pair".to_string(),
                                    description: "couldn't process flag pair".to_string(),
                                    error: e.into(),
                                })?;

                            changed_value = changed_value.replace(flag.as_str(), new_flag.as_str());
                        } else {
                            changed_value = changed_value
                                .replace(flag.as_str(), flag_from_cache.as_str())
                                .to_string();
                        }
                    }

                    let mut pair = format!("{key}={changed_value}");
                    if i != pairs.count() - 1 {
                        pair += "="
                    }

                    chunks.push(Ok(url::form_urlencoded::byte_serialize(pair.as_bytes())
                        .into_iter()
                        .map(|v| v.to_string())
                        .collect::<Vec<String>>()
                        .join("")
                        .to_string()));
                }
            } else {
                let mut result_body = text_body.to_string();

                for flag in FLAG_REGEX.clone().find_iter(text_body) {
                    let flag_from_cache = self
                        .cache
                        .get_flag(flag.as_str().to_string())
                        .await
                        .map_err(|e| ServerError::Changer {
                            method_name: "cache.get_flag".to_string(),
                            description: "couldn't get flag from cache".to_string(),
                            error: e.into(),
                        })?;

                    if flag_from_cache.len() == 0 {
                        let new_flag = helpers::build_flag(false);

                        self.process_flag_pair(flag.as_str(), new_flag.as_str())
                            .await
                            .map_err(|e| ServerError::Changer {
                                method_name: "process_flag_pair".to_string(),
                                description: "couldn't process flag pair".to_string(),
                                error: e.into(),
                            })?;

                        result_body = result_body
                            .replace(flag.as_str(), new_flag.as_str())
                            .to_string();
                    } else {
                        result_body = result_body
                            .replace(flag.as_str(), flag_from_cache.as_str())
                            .to_string();
                    }

                    info!("CHANGED REQUEST BODY: {:?}", result_body);
                }

                chunks.push(Ok(result_body));
            }

            warn!("CHUNKS {:?}", chunks);

            let stream = futures::stream::iter(chunks);

            warn!("{:?}", stream);

            Ok(Body::wrap_stream(stream))
        } else {
            Ok(Body::empty())
        }
    }

    async fn change_response_body(&self, body: &mut Body) -> (Result<Body, ServerError>, usize) {
        let body_bytes = match hyper::body::to_bytes(body).await {
            Ok(res) => res,
            Err(e) => {
                return (
                    Err(ServerError::Changer {
                        method_name: "to_bytes".to_string(),
                        description: "couldn't make body to bytes".to_string(),
                        error: e.into(),
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
                        Err(ServerError::Changer {
                            method_name: "from_utf8".to_string(),
                            description: "couldn't make body_bytes to str".to_string(),
                            error: e.into(),
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
                                Err(ServerError::Changer {
                                    method_name: "cache.get_flag".to_string(),
                                    description: "couldn't get flag from cache".to_string(),
                                    error: e.into(),
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

                info!("CHANGED RESPONSE BODY: {:?}", result_body);

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

    async fn change_request(&self, req: &mut Request<Body>) -> Result<(), ServerError> {
        info!("REQ {:?}", req);

        let mut headers = req.headers().clone();
        let mut uri = req.uri().clone();
        let body = req.body_mut();

        let encoded = headers
            .get("Content-Type")
            .is_some_and(|h| h == *HEADER_VALUE_URL_ENCODED);

        let changed_request_body =
            self.change_request_body(body, encoded)
                .await
                .map_err(|e| ServerError::Changer {
                    method_name: "change_request_body".to_string(),
                    description: "couldn't change request body".to_string(),
                    error: e.into(),
                })?;

        warn!("{:?}", changed_request_body);

        let host = match headers.get("host") {
            Some(res) => res.to_str().map_err(|e| ServerError::Changer {
                method_name: "res.to_str".to_string(),
                description: "couldn't convert header `host` to str".to_string(),
                error: e.into(),
            })?,
            None => {
                return Err(ServerError::Changer {
                    method_name: "headers.get".to_string(),
                    description: "couldn't get host".to_string(),
                    error: anyhow!("Host is None"),
                });
            }
        };

        info!("HOST {}", host);

        // try to parse host(ip) with port
        let (changed_host, scheme) = if host.contains(&":") {
            let split: Vec<&str> = host.split(":").collect();

            if split.len() != 2 {
                return Err(ServerError::Changer {
                    method_name: "host.split".to_string(),
                    description: "host is invalid".to_string(),
                    error: anyhow!("Host is invalid: {:?}", host),
                });
            }

            let port: u32 =
                split[1]
                    .trim()
                    .parse()
                    .map_err(|e: ParseIntError| ServerError::Changer {
                        method_name: "split.parse".to_string(),
                        description: "couldn't parse port".to_string(),
                        error: e.into(),
                    })?;

            let mut host = String::default();

            for target in self
                .config
                .targets()
                .map_err(|e| ServerError::Changer {
                    method_name: "config.targets".to_string(),
                    description: "couldn't get targets".to_string(),
                    error: e.into(),
                })?
                .iter()
            {
                if port == target.port {
                    host = target.team_host.clone() + ":" + split[1];

                    break;
                }
            }

            if host.len() == 0 {
                return Err(ServerError::Changer {
                    method_name: "targets".to_string(),
                    description: format!(
                        "couldn't find target when parsing host: {:?}",
                        uri.host()
                    ),
                    error: anyhow!("no host with port {:?} in config", port),
                });
            }

            (host, Scheme::HTTP)
        } else {
            return Err(ServerError::Changer {
                method_name: "host.contains".to_string(),
                description: "unexpected host".to_string(),
                error: anyhow!("unexpected host: {:?}", uri.host()),
            });
        };

        self.change_uri(&mut uri, changed_host.as_str(), scheme)
            .await
            .map_err(|e| ServerError::Changer {
                method_name: "change_uri".to_string(),
                description: "couldn't change uri".to_string(),
                error: e.into(),
            })?;

        info!("CHANGED URI {:?}", uri);

        headers.insert(
            "host",
            match HeaderValue::from_str(changed_host.as_str()) {
                Ok(res) => res,
                Err(e) => {
                    return Err(ServerError::Changer {
                        method_name: "HeaderValue::from_str".to_string(),
                        description: "couldn't convert header value for header `host`".to_string(),
                        error: e.into(),
                    })
                }
            },
        );

        *req.body_mut() = changed_request_body;
        *req.uri_mut() = uri;
        *req.headers_mut() = headers;

        info!("CHANGED REQ {:?}", req);

        return Ok(());
    }

    async fn change_response(&self, resp: &mut Response<Body>) -> Result<(), ServerError> {
        info!("RESP {:?}", resp);

        let mut headers = resp.headers().clone();
        let (new_body, new_body_length) = self.change_response_body(resp.body_mut()).await;
        let new_body = new_body.map_err(|e| ServerError::Changer {
            method_name: "change_response_body".to_string(),
            description: "couldn't get new_body".to_string(),
            error: e.into(),
        })?;

        headers.insert(
            hyper::header::CONTENT_LENGTH,
            match HeaderValue::from_str(new_body_length.to_string().as_str()) {
                Ok(res) => res,
                Err(e) => {
                    return Err(ServerError::Changer {
                        method_name: "HeaderValue::from_str".to_string(),
                        description: "couldn't convert header value for header `content-length`"
                            .to_string(),
                        error: e.into(),
                    })
                }
            },
        );

        *resp.body_mut() = new_body;
        *resp.headers_mut() = headers;

        info!("CHANGED RESP {:?}", &resp);

        Ok(())
    }

    pub async fn handle_request(&self, req: Request<Body>) -> Result<Response<Body>, ServerError> {
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
                CHANGED_REQUEST_COUNTER.with_label_values(&["ERROR"]).inc();

                return Err(ServerError::Changer {
                    method_name: "change_request".to_string(),
                    description: "couldn't change request ".to_string(),
                    error: e.into(),
                });
            }
        };

        let changed_req_headers = changed_req.headers().clone();

        let host = match changed_req_headers.get("host") {
            Some(res) => res.to_str().map_err(|e| ServerError::Changer {
                method_name: "res.to_str".to_string(),
                description: format!("couldn't parse host: `{:?}`", res),
                error: e.into(),
            })?,
            None => {
                return Err(ServerError::Changer {
                    method_name: "changed_req_headers.get".to_string(),
                    description: format!(
                        "couldn't get host from changed_req_headers: `{:?}`",
                        changed_req_headers
                    ),
                    error: anyhow!("Host is None"),
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

                return Err(ServerError::Changer {
                    method_name: "request".to_string(),
                    description: format!("target service with host `{}` returned `{:?}`", host, e),
                    error: e.into(),
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

                CHANGED_RESPONSE_COUNTER.with_label_values(&["ERROR"]).inc();

                return Ok(target_service_resp);
            }
        }
    }

    async fn process(&self, req: Request<Body>) -> Result<Response<Body>, hyper::Error> {
        match self.handle_request(req).await {
            Ok(res) => {
                HANDLED_REQUEST_COUNTER.with_label_values(&["OK"]).inc();

                Ok(res)
            }
            Err(e) => {
                error!("couldn't handle request: {}", e);

                HANDLED_REQUEST_COUNTER.with_label_values(&["ERROR"]).inc();

                Ok(Response::default())
            }
        }
    }
}

pub async fn run(
    proxy_addr: String,
    config: Arc<dyn TargetsProvider + Send + Sync>,
    cache: Arc<dyn Storage + Send + Sync>,
) {
    let proxy = Arc::new(Server::new(config, cache));

    let make_service = make_service_fn({
        let proxy = Arc::clone(&proxy);

        move |_conn| {
            let p = Arc::clone(&proxy);

            async move {
                Ok::<_, hyper::Error>(service_fn(move |req| {
                    let p = Arc::clone(&p);
                    async move { p.process(req).await }
                }))
            }
        }
    });

    let addr = proxy_addr.parse().expect("couldn't parse proxy address");
    let server = HTTPServer::bind(&addr).serve(make_service);

    warn!("start proxy on address: {addr}");

    if let Err(e) = server.await {
        error!("Fatal proxy error: {e}");
    }
}
