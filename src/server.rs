use std::num::ParseIntError;
use std::str;
use std::sync::{Arc, RwLock};

use anyhow::anyhow;
use http::uri::Scheme;
use hyper::http::HeaderValue;
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Request, Response, Server as HTTPServer, Uri};
use lazy_static::lazy_static;
use url::form_urlencoded;

use crate::config::ProxySettingsConfig;
use crate::errors::ServerError;
use crate::metrics::{
    CHANGED_REQUEST_COUNTER, CHANGED_RESPONSE_COUNTER, HANDLED_REQUEST_COUNTER,
    INCOMING_REQUEST_COUNTER, TARGET_SERVICE_STATUS_COUNTER,
};
use crate::traits::{FlagsProvider, Sender, Storage};

lazy_static! {
    pub static ref HEADER_VALUE_URL_ENCODED: HeaderValue =
        HeaderValue::from_str("application/x-www-form-urlencoded")
            .expect("invalid HEADER_VALUE_URL_ENCODED");
}

pub struct Server {
    config: Arc<RwLock<ProxySettingsConfig>>,

    cache: Arc<dyn Storage + Send + Sync>,
    client: Arc<dyn Sender + Send + Sync>,
    flags_provider: Arc<dyn FlagsProvider + Send + Sync>,
}

impl Server {
    pub fn new(
        config: Arc<RwLock<ProxySettingsConfig>>,
        cache: Arc<dyn Storage + Send + Sync>,
        client: Arc<dyn Sender + Send + Sync>,
        flags_provider: Arc<dyn FlagsProvider + Send + Sync>,
    ) -> Self {
        Server {
            config,
            cache,
            client,
            flags_provider,
        }
    }

    async fn process_flag_pair(&self, flag: &str, new_flag: &str) -> Result<(), ServerError> {
        self.cache
            .set_flag(flag, new_flag)
            .await
            .map_err(|e| ServerError::Changer {
                method_name: "cache.set_flag".to_string(),
                description: "couldn't set `flag: new_flag` in cache".to_string(),
                error: e.into(),
            })?;

        self.cache
            .set_flag(new_flag, flag)
            .await
            .map_err(|e| ServerError::Changer {
                method_name: "cache.set_flag".to_string(),
                description: "couldn't set `new_flag: flag` in cache".to_string(),
                error: e.into(),
            })?;

        Ok(())
    }

    async fn change_uri(
        &self,
        uri: &mut Uri,
        host: &str,
        scheme: Scheme,
    ) -> Result<(), ServerError> {
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

        let mut changed_path = path.to_string();

        let config = self
            .config
            .read()
            .map_err(|e| ServerError::Changer {
                method_name: "config.read".to_string(),
                description: "couldn't read config".to_string(),
                error: anyhow!("{e}"),
            })?
            .clone();

        for flag in config.flag_regexp.find_iter(path) {
            let flag_from_cache =
                self.cache
                    .get_flag(flag.as_str())
                    .await
                    .map_err(|e| ServerError::Changer {
                        method_name: "cache.get_flag".to_string(),
                        description: "couldn't get flag from cache".to_string(),
                        error: e.into(),
                    })?;

            let pair_flag = if flag_from_cache.len() == 0 {
                let new_flag = self.flags_provider.build_flag(
                    &config.flag_alphabet,
                    flag.len(),
                    &config.flag_postfix,
                );

                self.process_flag_pair(flag.as_str(), new_flag.as_str())
                    .await
                    .map_err(|e| ServerError::Changer {
                        method_name: "process_flag_pair".to_string(),
                        description: "couldn't process flag pair".to_string(),
                        error: e.into(),
                    })?;

                new_flag
            } else {
                flag_from_cache
            };

            changed_path = config.flag_regexp.replace(path, pair_flag).to_string();
        }

        *uri = changed_uri_builder
            .path_and_query(changed_path)
            .build()
            .map_err(|e| ServerError::Changer {
                method_name: "changed_uri.build".to_string(),
                description: "couldn't build changed_uri with changed_path".to_string(),
                error: e.into(),
            })?;

        Ok(())
    }

    async fn change_request_body(
        &self,
        body: &mut Body,
        encoded: bool,
    ) -> Result<Body, ServerError> {
        // No check for body length, because it's not necessary for CTF events. kekw
        let body_bytes = hyper::body::to_bytes(body)
            .await
            .map_err(|e| ServerError::Changer {
                method_name: "to_bytes".to_string(),
                description: "couldn't make body to bytes".to_string(),
                error: e.into(),
            })?;

        if body_bytes.is_empty() {
            return Ok(Body::empty());
        };

        let text_body = std::str::from_utf8(&body_bytes).map_err(|e| ServerError::Changer {
            method_name: "from_utf8".to_string(),
            description: "couldn't make body_bytes to str".to_string(),
            error: e.into(),
        })?;

        let mut result_body = text_body.to_string();

        let config = self
            .config
            .read()
            .map_err(|e| ServerError::Changer {
                method_name: "config.read".to_string(),
                description: "couldn't read config".to_string(),
                error: anyhow!("{e}"),
            })?
            .clone();

        if encoded {
            let pairs = url::form_urlencoded::parse(&body_bytes);

            for (_i, (_key, value)) in pairs.into_iter().enumerate() {
                for flag in config.flag_regexp.find_iter(&value) {
                    let flag_from_cache =
                        self.cache.get_flag(flag.as_str()).await.map_err(|e| {
                            ServerError::Changer {
                                method_name: "cache.get_flag".to_string(),
                                description: "couldn't get flag from cache".to_string(),
                                error: e.into(),
                            }
                        })?;

                    let pair_flag = if flag_from_cache.len() == 0 {
                        let new_flag = self.flags_provider.build_flag(
                            &config.flag_alphabet,
                            flag.len(),
                            &config.flag_postfix,
                        );

                        self.process_flag_pair(flag.as_str(), new_flag.as_str())
                            .await
                            .map_err(|e| ServerError::Changer {
                                method_name: "process_flag_pair".to_string(),
                                description: "couldn't process flag pair".to_string(),
                                error: e.into(),
                            })?;

                        new_flag
                    } else {
                        flag_from_cache
                    };

                    let encoded_flag_from: String =
                        form_urlencoded::byte_serialize(flag.as_str().as_bytes()).collect();
                    let encoded_flag_to: String =
                        form_urlencoded::byte_serialize(pair_flag.as_bytes()).collect();

                    result_body =
                        result_body.replace(encoded_flag_from.as_str(), encoded_flag_to.as_str());
                }
            }
        } else {
            for flag in config.flag_regexp.find_iter(text_body) {
                let flag_from_cache =
                    self.cache
                        .get_flag(flag.as_str())
                        .await
                        .map_err(|e| ServerError::Changer {
                            method_name: "cache.get_flag".to_string(),
                            description: "couldn't get flag from cache".to_string(),
                            error: e.into(),
                        })?;

                let pair_flag = if flag_from_cache.len() == 0 {
                    let new_flag = self.flags_provider.build_flag(
                        &config.flag_alphabet,
                        flag.len(),
                        &config.flag_postfix,
                    );

                    self.process_flag_pair(flag.as_str(), new_flag.as_str())
                        .await
                        .map_err(|e| ServerError::Changer {
                            method_name: "process_flag_pair".to_string(),
                            description: "couldn't process flag pair".to_string(),
                            error: e.into(),
                        })?;

                    new_flag
                } else {
                    flag_from_cache
                };

                result_body = result_body
                    .replace(flag.as_str(), pair_flag.as_str())
                    .to_string();
            }
        }

        Ok(Body::from(result_body))
    }

    async fn change_response_body(
        &self,
        body: &mut Body,
        encoded: bool,
    ) -> Result<Body, ServerError> {
        let body_bytes = hyper::body::to_bytes(body)
            .await
            .map_err(|e| ServerError::Changer {
                method_name: "to_bytes".to_string(),
                description: "couldn't make body to bytes".to_string(),
                error: e.into(),
            })?;

        if body_bytes.is_empty() {
            return Ok(Body::empty());
        }

        let text_body = std::str::from_utf8(&body_bytes).map_err(|e| ServerError::Changer {
            method_name: "from_utf8".to_string(),
            description: "couldn't make body_bytes to str".to_string(),
            error: e.into(),
        })?;

        let mut result_body = text_body.to_string();

        let config = self
            .config
            .read()
            .map_err(|e| ServerError::Changer {
                method_name: "config.read".to_string(),
                description: "couldn't read config".to_string(),
                error: anyhow!("{e}"),
            })?
            .clone();

        if encoded {
            let pairs = url::form_urlencoded::parse(&body_bytes);

            for (_i, (_key, value)) in pairs.into_iter().enumerate() {
                for flag in config.flag_regexp.find_iter(&value) {
                    let flag_from_cache =
                        self.cache.get_flag(flag.as_str()).await.map_err(|e| {
                            ServerError::Changer {
                                method_name: "cache.get_flag".to_string(),
                                description: "couldn't get flag from cache".to_string(),
                                error: e.into(),
                            }
                        })?;

                    let encoded_flag_from: String =
                        form_urlencoded::byte_serialize(flag.as_str().as_bytes()).collect();
                    let encoded_flag_to: String =
                        form_urlencoded::byte_serialize(flag_from_cache.as_bytes()).collect();

                    result_body =
                        result_body.replace(encoded_flag_from.as_str(), encoded_flag_to.as_str());
                }
            }
        } else {
            for flag in config.flag_regexp.find_iter(text_body) {
                let flag_from_cache =
                    self.cache
                        .get_flag(flag.as_str())
                        .await
                        .map_err(|e| ServerError::Changer {
                            method_name: "cache.get_flag".to_string(),
                            description: "couldn't get flag from cache".to_string(),
                            error: e.into(),
                        })?;

                if flag_from_cache.len() != 0 {
                    result_body = result_body.replace(flag.as_str(), flag_from_cache.as_str())
                } else {
                    warn!("couldn't find pair flag for flag: {:?}", flag)
                }
            }
        }

        Ok(Body::from(result_body))
    }

    async fn change_request(&self, req: &mut Request<Body>) -> Result<(), ServerError> {
        let mut headers = req.headers().clone();
        let mut uri = req.uri().clone();
        let body = req.body_mut();

        debug!("change_request: headers {:?}; URI {uri}", &headers);

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

        let config = self
            .config
            .read()
            .map_err(|e| ServerError::Changer {
                method_name: "config.read".to_string(),
                description: "couldn't read config".to_string(),
                error: anyhow!("{e}"),
            })?
            .clone();

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

            for target in config.targets.iter() {
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
            // TODO: add domain processing
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

        let encoded = headers
            .get("content-Type")
            .is_some_and(|h| h == *HEADER_VALUE_URL_ENCODED);

        let changed_request_body =
            self.change_request_body(body, encoded)
                .await
                .map_err(|e| ServerError::Changer {
                    method_name: "change_request_body".to_string(),
                    description: "couldn't change request body".to_string(),
                    error: e.into(),
                })?;

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

        return Ok(());
    }

    async fn change_response(&self, resp: &mut Response<Body>) -> Result<(), ServerError> {
        let headers = resp.headers().clone();

        let encoded = headers
            .get("Content-Type")
            .is_some_and(|h| h == *HEADER_VALUE_URL_ENCODED);

        let changed_response_body = self
            .change_response_body(resp.body_mut(), encoded)
            .await
            .map_err(|e| ServerError::Changer {
                method_name: "change_response_body".to_string(),
                description: "couldn't get changed response body".to_string(),
                error: e.into(),
            })?;

        *resp.body_mut() = changed_response_body;
        *resp.headers_mut() = headers;

        Ok(())
    }

    pub async fn handle_request(&self, req: Request<Body>) -> Result<Response<Body>, ServerError> {
        INCOMING_REQUEST_COUNTER.inc();

        let mut req = req;

        // TODO: if change_request returns error, need to skip (original) request above maybe.
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

        let mut target_service_resp = match self.client.send(changed_req).await {
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
                    description: format!("target service with host `{host}` returned error `{e}`"),
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
                error!("couldn't change response {e}");

                CHANGED_RESPONSE_COUNTER.with_label_values(&["ERROR"]).inc();

                return Ok(target_service_resp);
            }
        }
    }

    async fn process(&self, req: Request<Body>) -> Result<Response<Body>, hyper::Error> {
        match self.handle_request(req).await {
            Ok(res) => {
                HANDLED_REQUEST_COUNTER.with_label_values(&["OK"]).inc();

                debug!("request handled successfully");

                Ok(res)
            }
            Err(e) => {
                error!("couldn't handle request: {e}");

                HANDLED_REQUEST_COUNTER.with_label_values(&["ERROR"]).inc();

                Ok(Response::default())
            }
        }
    }
}

pub async fn run(
    proxy_addr: String,
    config: Arc<RwLock<ProxySettingsConfig>>,
    cache: Arc<dyn Storage + Send + Sync>,
    client: Arc<dyn Sender + Send + Sync>,
    flags_provider: Arc<dyn FlagsProvider + Send + Sync>,
) {
    let server = Arc::new(Server::new(config, cache, client, flags_provider));

    let make_service = make_service_fn({
        let server = Arc::clone(&server);

        move |_conn| {
            let server: Arc<Server> = Arc::clone(&server);

            async move {
                Ok::<_, hyper::Error>(service_fn(move |req| {
                    let server = Arc::clone(&server);
                    async move { server.process(req).await }
                }))
            }
        }
    });

    let addr = proxy_addr.parse().expect("couldn't parse proxy address");
    let server = HTTPServer::bind(&addr).serve(make_service);

    warn!("start `beta` on address: {addr}");

    if let Err(e) = server.await {
        error!("Fatal proxy error: {e}");
    }
}
