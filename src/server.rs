use protobuf::reflect::MessageDescriptor;
use regex::Regex;
use std::io::{Read, Write};
use std::num::ParseIntError;
use std::str;
use std::sync::{Arc, RwLock};

use anyhow::anyhow;
use bytes::Bytes;
use http::uri::Scheme;
use http::HeaderMap;
use hyper::http::HeaderValue;
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Request, Response, Server as HTTPServer, Uri};
use lazy_static::lazy_static;
use url::form_urlencoded;

use crate::config::{ProxySettingsConfig, Target};
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

    async fn process_flag_pair(
        &self,
        flag: &str,
        new_flag: &str,
        ttl: usize,
    ) -> Result<(), ServerError> {
        self.cache
            .set_flag(flag, new_flag, ttl)
            .await
            .map_err(|e| ServerError::Changer {
                method_name: "cache.set_flag".to_string(),
                description: "couldn't set `flag: new_flag` in cache".to_string(),
                error: e.into(),
            })?;

        self.cache
            .set_flag(new_flag, flag, ttl)
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
        ctx: &Ctx,
        uri: &mut Uri,
        host: &str,
        scheme: Scheme,
    ) -> Result<(), ServerError> {
        let changed_uri_builder = Uri::builder().scheme(scheme).authority(host);

        let path = uri
            .path_and_query()
            .ok_or_else(|| ServerError::Changer {
                method_name: "uri.path_and_query".to_string(),
                description: "path is None".to_string(),
                error: anyhow!("Path is None"),
            })?
            .as_str();

        let mut changed_path = path.to_string();

        let flag_regexp = &ctx.config.flag_regexp;

        for flag in flag_regexp.find_iter(path) {
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
                    &ctx.config.flag_alphabet,
                    flag.len(),
                    &ctx.config.flag_postfix,
                );

                self.process_flag_pair(flag.as_str(), new_flag.as_str(), ctx.config.flag_ttl)
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

            changed_path = ctx.config.flag_regexp.replace(path, pair_flag).to_string();
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
        ctx: &Ctx,
        body: &mut Body,
        headers: &HeaderMap,
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

        let body_type = {
            match &ctx.config.target {
                Target::Text(_) => BodyType::Default,
                Target::Protobuf(t) => BodyType::Protobuf {
                    protobuf_request_message_descriptor: t
                        .protobuf_request_message_descriptor
                        .clone(),
                    protobuf_response_message_descriptor: t
                        .protobuf_response_message_descriptor
                        .clone(),
                },
            }
        };

        let unpacked_body = self
            .unpack_request_body_bytes(headers, body_type, body_bytes.clone())
            .map_err(|e| ServerError::Changer {
                method_name: "unpack_request_body_bytes".to_string(),
                description: "couldn't unpack request body bytes".to_string(),
                error: e.into(),
            })?;

        let mut result_body = unpacked_body.clone();

        if headers
            .get("Content-Type")
            .is_some_and(|h| h == *HEADER_VALUE_URL_ENCODED)
        {
            let pairs = url::form_urlencoded::parse(&body_bytes);

            for (_i, (_key, value)) in pairs.into_iter().enumerate() {
                for flag in ctx.config.flag_regexp.find_iter(&value) {
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
                            &ctx.config.flag_alphabet,
                            flag.len(),
                            &ctx.config.flag_postfix,
                        );

                        self.process_flag_pair(
                            flag.as_str(),
                            new_flag.as_str(),
                            ctx.config.flag_ttl,
                        )
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
            for flag in ctx.config.flag_regexp.find_iter(unpacked_body.as_str()) {
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
                        &ctx.config.flag_alphabet,
                        flag.len(),
                        &ctx.config.flag_postfix,
                    );

                    self.process_flag_pair(flag.as_str(), new_flag.as_str(), ctx.config.flag_ttl)
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

    fn unpack_request_body_bytes(
        &self,
        headers: &HeaderMap,
        body_type: BodyType,
        body_bytes: Bytes,
    ) -> Result<String, ServerError> {
        let req_body = match body_type {
            BodyType::Default => std::str::from_utf8(&body_bytes)
                .map_err(|e| ServerError::Changer {
                    method_name: "from_utf8".to_string(),
                    description: "couldn't make body_bytes to str".to_string(),
                    error: e.into(),
                })?
                .to_string(),
            BodyType::Protobuf {
                protobuf_request_message_descriptor: protobuf_request_file_descriptor,
                protobuf_response_message_descriptor: _,
            } => {
                let content_coding = headers.get("Content-Coding");

                self.unpack_protobuf_body_bytes(
                    protobuf_request_file_descriptor,
                    content_coding,
                    body_bytes,
                )
                .map_err(|e| ServerError::Changer {
                    method_name: "unpack_protobuf_body_bytes".to_string(),
                    description: "couldn't unpack protobuf body bytes".to_string(),
                    error: e.into(),
                })?
            }
        };

        Ok(req_body)
    }

    fn unpack_response_body_bytes(
        &self,
        headers: &HeaderMap,
        body_type: BodyType,
        body_bytes: Bytes,
    ) -> Result<String, ServerError> {
        let res_body = match body_type {
            BodyType::Default => {
                let content_encoding = headers.get("Content-Encoding");

                self.unpack_text_body_bytes(content_encoding, body_bytes)
                    .map_err(|e| ServerError::Changer {
                        method_name: String::from("unpack_text_body_bytes"),
                        description: String::from("couldn't unpack text body bytes"),
                        error: e.into(),
                    })?
            }
            BodyType::Protobuf {
                protobuf_request_message_descriptor: _,
                protobuf_response_message_descriptor,
            } => {
                let content_coding = headers.get("Content-Coding");

                self.unpack_protobuf_body_bytes(
                    protobuf_response_message_descriptor,
                    content_coding,
                    body_bytes,
                )
                .map_err(|e| ServerError::Changer {
                    method_name: String::from("unpack_protobuf_body_bytes"),
                    description: String::from("couldn't unpack protobuf body bytes"),
                    error: e.into(),
                })?
            }
        };

        Ok(res_body)
    }

    fn unpack_text_body_bytes(
        &self,
        content_encoding_hv: Option<&HeaderValue>,
        body_bytes: Bytes,
    ) -> Result<String, ServerError> {
        let res = match content_encoding_hv {
            Some(res) => {
                let header_str = res.to_str().map_err(|e| ServerError::Changer {
                    method_name: "res.to_str".to_string(),
                    description: "couldn't convert header `Content-Encoding` to str".to_string(),
                    error: e.into(),
                })?;

                self.decode_body(header_str, body_bytes)
                    .map_err(|e| ServerError::Changer {
                        method_name: "decode_body".to_string(),
                        description: "couldn't decode body".to_string(),
                        error: e.into(),
                    })?
            }
            None => std::str::from_utf8(&body_bytes)
                .map_err(|e| ServerError::Changer {
                    method_name: "from_utf8".to_string(),
                    description: "couldn't make body_bytes to str".to_string(),
                    error: e.into(),
                })?
                .to_string(),
        };

        Ok(res)
    }

    fn unpack_protobuf_body_bytes(
        &self,
        message_descriptor: MessageDescriptor,
        content_coding: Option<&HeaderValue>,
        body_bytes: Bytes,
    ) -> Result<String, ServerError> {
        let bytes_to_merge = match content_coding {
            Some(res) => {
                let header_str = res.to_str().map_err(|e| ServerError::Changer {
                    method_name: "res.to_str".to_string(),
                    description: "couldn't convert header `Content-Encoding` to str".to_string(),
                    error: e.into(),
                })?;

                self.decode_body(header_str, body_bytes)
                    .map_err(|e| ServerError::Changer {
                        method_name: "decode_body".to_string(),
                        description: "couldn't decode body".to_string(),
                        error: e.into(),
                    })?
                    .into_bytes()
            }
            None => body_bytes.to_vec(),
        };

        let mut message = message_descriptor.new_instance();
        message
            .merge_from_bytes_dyn(&bytes_to_merge)
            .map_err(|e| ServerError::Changer {
                method_name: "merge_from_bytes_dyn".to_string(),
                description: "couldn't merge from bytes".to_string(),
                error: e.into(),
            })?;

        Ok(String::from_utf8_lossy(
            message
                .write_to_bytes_dyn()
                .map_err(|e| ServerError::Changer {
                    method_name: "write_to_bytes_dyn".to_string(),
                    description: "couldn't write message to bytes".to_string(),
                    error: e.into(),
                })?
                .as_slice(),
        )
        .to_string())
    }

    fn pack_response_body_bytes(
        &self,
        body_type: BodyType,
        body_bytes: Bytes,
        headers: &HeaderMap,
    ) -> Result<Bytes, ServerError> {
        let res = match body_type {
            BodyType::Default => {
                let content_encoding_hv = headers.get("Content-Encoding");

                self.pack_text_response_body_bytes(content_encoding_hv, body_bytes)
                    .map_err(|e| ServerError::Changer {
                        method_name: "pack_text_response_body_bytes".to_string(),
                        description: "couldn't pack text response".to_string(),
                        error: e.into(),
                    })?
            }
            BodyType::Protobuf {
                protobuf_request_message_descriptor: _,
                protobuf_response_message_descriptor,
            } => {
                let content_coding_hv = headers.get("Content-Coding");

                self.pack_protobuf_response_body_bytes(
                    protobuf_response_message_descriptor,
                    content_coding_hv,
                    body_bytes,
                )
                .map_err(|e| ServerError::Changer {
                    method_name: "pack_protobuf_response_body_bytes".to_string(),
                    description: "couldn't pack protobuf response".to_string(),
                    error: e.into(),
                })?
            }
        };

        Ok(res)
    }

    fn pack_text_response_body_bytes(
        &self,
        content_encoding_hv: Option<&HeaderValue>,
        body: Bytes,
    ) -> Result<Bytes, ServerError> {
        let res = match content_encoding_hv {
            Some(res) => {
                let header_str = res.to_str().map_err(|e| ServerError::Changer {
                    method_name: "res.to_str".to_string(),
                    description: "couldn't convert header `Content-Encoding` to str".to_string(),
                    error: e.into(),
                })?;

                self.encode_body(header_str, body)
                    .map_err(|e| ServerError::Changer {
                        method_name: "encode_body".to_string(),
                        description: "couldn't encode body".to_string(),
                        error: e.into(),
                    })?
            }
            None => body,
        };

        Ok(res)
    }

    fn pack_protobuf_response_body_bytes(
        &self,
        message_descriptor: MessageDescriptor,
        content_coding_hv: Option<&HeaderValue>,
        body_bytes: Bytes,
    ) -> Result<Bytes, ServerError> {
        let mut message = message_descriptor.new_instance();
        message
            .merge_from_bytes_dyn(&body_bytes)
            .map_err(|e| ServerError::Changer {
                method_name: "merge_from_bytes_dyn".to_string(),
                description: "couldn't merge from bytes".to_string(),
                error: e.into(),
            })?;

        let message_bytes =
            Bytes::from(
                message
                    .write_to_bytes_dyn()
                    .map_err(|e| ServerError::Changer {
                        method_name: "write_to_bytes_dyn".to_string(),
                        description: "couldn't write message to bytes".to_string(),
                        error: e.into(),
                    })?,
            );

        let res = match content_coding_hv {
            Some(res) => {
                let header_str = res.to_str().map_err(|e| ServerError::Changer {
                    method_name: "res.to_str".to_string(),
                    description: "couldn't convert header `Content-Encoding` to str".to_string(),
                    error: e.into(),
                })?;

                self.encode_body(header_str, message_bytes)
                    .map_err(|e| ServerError::Changer {
                        method_name: "encode_body".to_string(),
                        description: "couldn't encode body".to_string(),
                        error: e.into(),
                    })?
            }
            None => message_bytes,
        };

        Ok(res)
    }

    fn encode_body(&self, content_encoding: &str, body_bytes: Bytes) -> Result<Bytes, ServerError> {
        let res = match content_encoding {
            _ if content_encoding.contains("gzip") => {
                let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::best());

                e.write_all(body_bytes.as_ref())
                    .map_err(|e| ServerError::Changer {
                        method_name: "write_all".to_string(),
                        description: "couldn't write body to gzip encoder".to_string(),
                        error: e.into(),
                    })?;

                e.finish().map_err(|e| ServerError::Changer {
                    method_name: "finish".to_string(),
                    description: "couldn't finish gzip encoder".to_string(),
                    error: e.into(),
                })?
            }
            _ if content_encoding.contains("deflate") => {
                let mut e =
                    flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::best());

                e.write_all(body_bytes.as_ref())
                    .map_err(|e| ServerError::Changer {
                        method_name: "write_all".to_string(),
                        description: "couldn't write body to deflate encoder".to_string(),
                        error: e.into(),
                    })?;

                e.finish().map_err(|e| ServerError::Changer {
                    method_name: "finish".to_string(),
                    description: "couldn't finish deflate encoder".to_string(),
                    error: e.into(),
                })?
            }
            _ => {
                return Err(ServerError::Changer {
                    method_name: "res.to_str".to_string(),
                    description: "unsupported content encoding".to_string(),
                    error: anyhow!("unsupported content encoding: {content_encoding}"),
                })
            }
        };

        Ok(Bytes::from(res))
    }

    fn decode_body(&self, content_encoding: &str, body: Bytes) -> Result<String, ServerError> {
        let res = match content_encoding {
            _ if content_encoding.contains("gzip") => {
                let mut d = flate2::read::GzDecoder::new(body.as_ref());
                let mut s = String::new();

                d.read_to_string(&mut s).map_err(|e| ServerError::Changer {
                    method_name: "read_to_string".to_string(),
                    description: "couldn't read `gzip` body to string".to_string(),
                    error: e.into(),
                })?;

                s
            }
            _ if content_encoding.contains("deflate") => {
                let mut d = flate2::read::DeflateDecoder::new(body.as_ref());
                let mut s = String::new();

                d.read_to_string(&mut s).map_err(|e| ServerError::Changer {
                    method_name: "read_to_string".to_string(),
                    description: "couldn't read `deflate` body to string".to_string(),
                    error: e.into(),
                })?;

                s
            }
            _ => {
                return Err(ServerError::Changer {
                    method_name: "".to_string(),
                    description: "unsupported content encoding".to_string(),
                    error: anyhow!("unsupported content encoding: {:?}", content_encoding),
                })
            }
        };

        Ok(res)
    }

    async fn change_response_body(
        &self,
        ctx: &Ctx,
        body: &mut Body,
        headers: &HeaderMap,
    ) -> Result<(Body, usize), ServerError> {
        let body_bytes = hyper::body::to_bytes(body)
            .await
            .map_err(|e| ServerError::Changer {
                method_name: "to_bytes".to_string(),
                description: "couldn't make body to bytes".to_string(),
                error: e.into(),
            })?;

        if body_bytes.is_empty() {
            return Ok((Body::empty(), 0));
        }

        let body_type = {
            match &ctx.config.target {
                Target::Text(_) => BodyType::Default,
                Target::Protobuf(t) => BodyType::Protobuf {
                    protobuf_request_message_descriptor: t
                        .protobuf_request_message_descriptor
                        .clone(),
                    protobuf_response_message_descriptor: t
                        .protobuf_response_message_descriptor
                        .clone(),
                },
            }
        };

        let mut unpacked_body = self
            .unpack_response_body_bytes(headers, body_type.clone(), body_bytes.clone())
            .map_err(|e| ServerError::Changer {
                method_name: "unpack_response_body_bytes".to_string(),
                description: "couldn't unpack response body bytes".to_string(),
                error: e.into(),
            })?;

        let url_encoded = headers
            .get("Content-Type")
            .is_some_and(|h| h == *HEADER_VALUE_URL_ENCODED);

        let flag_regexp = &ctx.config.flag_regexp;

        if url_encoded {
            let pairs = url::form_urlencoded::parse(&body_bytes);

            for (_i, (_key, value)) in pairs.into_iter().enumerate() {
                for flag in flag_regexp.find_iter(&value) {
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

                    unpacked_body =
                        unpacked_body.replace(encoded_flag_from.as_str(), encoded_flag_to.as_str());
                }
            }
        } else {
            let cloned_body = unpacked_body.clone();

            for flag in flag_regexp.find_iter(&cloned_body) {
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
                    unpacked_body = unpacked_body.replace(flag.as_str(), flag_from_cache.as_str())
                } else {
                    warn!("couldn't find pair flag for flag: {:?}", flag)
                }
            }
        }

        let packed_body = self
            .pack_response_body_bytes(body_type, Bytes::from(unpacked_body), headers)
            .map_err(|e| ServerError::Changer {
                method_name: "pack_response_body_bytes".to_string(),
                description: "couldn't pack response body bytes".to_string(),
                error: e.into(),
            })?;

        let packed_body_len = packed_body.len();

        Ok((Body::from(packed_body), packed_body_len))
    }

    async fn change_request(&self, ctx: &Ctx, req: &mut Request<Body>) -> Result<(), ServerError> {
        let mut headers = req.headers().clone();
        let mut uri = req.uri().clone();
        warn!("{:?}", uri.path());

        let body = req.body_mut();

        let (changed_host, scheme) = {
            (
                format!(
                    "{}:{}",
                    &ctx.config.target.team_host(),
                    &ctx.config.target.port()
                ),
                Scheme::HTTP,
            )
        };

        self.change_uri(ctx, &mut uri, changed_host.as_str(), scheme)
            .await
            .map_err(|e| ServerError::Changer {
                method_name: "change_uri".to_string(),
                description: "couldn't change uri".to_string(),
                error: e.into(),
            })?;

        if log::log_enabled!(log::Level::Debug) {
            debug!("changed_uri: {:?}", uri);
        }

        let changed_request_body = self
            .change_request_body(ctx, body, &headers)
            .await
            .map_err(|e| ServerError::Changer {
                method_name: "change_request_body".to_string(),
                description: "couldn't change request body".to_string(),
                error: e.into(),
            })?;

        if log::log_enabled!(log::Level::Debug) {
            debug!("changed_request_body: {:?}", changed_request_body);
        }

        match ctx.config.target {
            Target::Text(_) => {
                headers.insert(
                    "host",
                    HeaderValue::from_str(changed_host.as_str()).map_err(|e| {
                        ServerError::Changer {
                            method_name: "HeaderValue::from_str".to_string(),
                            description: "couldn't convert header value for header `host`"
                                .to_string(),
                            error: e.into(),
                        }
                    })?,
                );
            }
            _ => {}
        };

        *req.body_mut() = changed_request_body;
        *req.uri_mut() = uri;
        *req.headers_mut() = headers;

        return Ok(());
    }

    async fn change_response(
        &self,
        ctx: &Ctx,
        resp: &mut Response<Body>,
    ) -> Result<(), ServerError> {
        let mut headers = resp.headers().clone();

        let (changed_response_body, changed_response_body_len) = self
            .change_response_body(ctx, resp.body_mut(), &headers)
            .await
            .map_err(|e| ServerError::Changer {
                method_name: "change_response_body".to_string(),
                description: "couldn't get changed response body".to_string(),
                error: e.into(),
            })?;

        if log::log_enabled!(log::Level::Debug) {
            debug!("changed_response_body: {:?}", changed_response_body);
        }

        match ctx.config.target {
            Target::Text(_) => {
                headers.insert(
                    "Content-Length",
                    HeaderValue::from_str(changed_response_body_len.to_string().as_str()).map_err(
                        |e| ServerError::Changer {
                            method_name: "HeaderValue::from_str".to_string(),
                            description: String::from(
                                "couldn't convert header value for header `Content-Length`",
                            ),
                            error: e.into(),
                        },
                    )?,
                );
            }
            _ => {}
        }

        *resp.body_mut() = changed_response_body;
        *resp.headers_mut() = headers;

        Ok(())
    }

    pub async fn handle_request(&self, req: Request<Body>) -> Result<Response<Body>, ServerError> {
        INCOMING_REQUEST_COUNTER.inc();

        let config = self
            .config
            .read()
            .map_err(|e| ServerError::Changer {
                method_name: "config.read".to_string(),
                description: "couldn't read config".to_string(),
                error: anyhow!("{e}"),
            })?
            .clone();

        let headers = req.headers();
        let uri = req.uri();

        if log::log_enabled!(log::Level::Debug) {
            debug!("change_request: headers {:?}; URI {uri}", &headers);
        }

        let port = self
            .get_port(headers, uri)
            .map_err(|e| ServerError::Changer {
                method_name: String::from("get_port"),
                description: String::from("couldn't get port"),
                error: e.into(),
            })?;

        // try to parse host(ip) with port
        let target = config
            .targets
            .iter()
            .find(|t| t.port().eq(&port))
            .ok_or_else(|| ServerError::Changer {
                method_name: "targets".to_string(),
                description: format!("couldn't find target while parsing host: {:?}", uri.host()),
                error: anyhow!("no host with port {:?} in config", port),
            })?;

        let ctx = Ctx {
            config: Config {
                flag_ttl: config.flag_ttl,
                flag_regexp: config.flag_regexp,
                flag_alphabet: config.flag_alphabet,
                flag_postfix: config.flag_postfix,
                target: target.to_owned(),
            },
        };

        let mut req = req;

        // TODO: if change_request returns error, need to skip (original) request above maybe.
        let changed_req = match self.change_request(&ctx, &mut req).await {
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

        let changed_req_host = ctx.config.target.team_host();

        let mut target_service_resp = match self.client.send(changed_req).await {
            Ok(res) => {
                TARGET_SERVICE_STATUS_COUNTER
                    .with_label_values(&[changed_req_host.as_str(), "OK"])
                    .inc();

                res
            }
            Err(e) => {
                TARGET_SERVICE_STATUS_COUNTER
                    .with_label_values(&[changed_req_host.as_str(), "ERROR"])
                    .inc();

                return Err(ServerError::Changer {
                    method_name: "client.send".to_string(),
                    description: format!(
                        "target service with host `{changed_req_host}` returned error `{e}`"
                    ),
                    error: e.into(),
                });
            }
        };

        if log::log_enabled!(log::Level::Debug) {
            debug!("target_service_resp: {:?}", target_service_resp);
        }

        match self.change_response(&ctx, &mut target_service_resp).await {
            Ok(_) => {
                CHANGED_RESPONSE_COUNTER.with_label_values(&["OK"]).inc();

                Ok(target_service_resp)
            }
            Err(e) => {
                CHANGED_RESPONSE_COUNTER.with_label_values(&["ERROR"]).inc();

                return Err(ServerError::Changer {
                    method_name: "change_response".to_string(),
                    description: format!("couldn't change response {e}"),
                    error: e.into(),
                });
            }
        }
    }

    fn get_port(&self, headers: &HeaderMap, uri: &Uri) -> Result<u16, ServerError> {
        let port = {
            if headers.contains_key("host") {
                match headers.get("host") {
                    Some(res) => {
                        let host = res.to_str().map_err(|e| ServerError::Changer {
                            method_name: "res.to_str".to_string(),
                            description: "couldn't convert header `host` to str".to_string(),
                            error: e.into(),
                        })?;

                        if host.contains(&":") {
                            let split: Vec<&str> = host.split(":").collect();

                            if split.len() != 2 {
                                return Err(ServerError::Changer {
                                    method_name: "host.split".to_string(),
                                    description: "host is invalid".to_string(),
                                    error: anyhow!("Host is invalid: {:?}", host),
                                });
                            }

                            let port: u16 =
                                split[1].trim().parse().map_err(|e: ParseIntError| {
                                    ServerError::Changer {
                                        method_name: "split.parse".to_string(),
                                        description: "couldn't parse port".to_string(),
                                        error: e.into(),
                                    }
                                })?;

                            port
                        } else {
                            // TODO: add domain(example.rs) processing
                            return Err(ServerError::Changer {
                                method_name: "host.contains".to_string(),
                                description: "unexpected host".to_string(),
                                error: anyhow!("unexpected host: {:?}", uri.host()),
                            });
                        }
                    }
                    None => {
                        return Err(ServerError::Changer {
                            method_name: "headers.get".to_string(),
                            description: "couldn't get host".to_string(),
                            error: anyhow!("Host is None"),
                        });
                    }
                }
            } else {
                // probably there is protobuf message, so we try to find port in URI
                let port = uri.port_u16().ok_or_else(|| ServerError::Changer {
                    method_name: String::from("port"),
                    description: String::from("no port found"),
                    error: anyhow!("no port found"),
                })?;

                port
            }
        };

        Ok(port)
    }

    async fn process(&self, req: Request<Body>) -> Result<Response<Body>, hyper::Error> {
        match self.handle_request(req).await {
            Ok(res) => {
                HANDLED_REQUEST_COUNTER.with_label_values(&["OK"]).inc();

                if log::log_enabled!(log::Level::Debug) {
                    debug!("handle_request res: {:?}", res);
                }

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

#[derive(Debug, Clone)]
enum BodyType {
    Default,
    Protobuf {
        protobuf_request_message_descriptor: MessageDescriptor,
        protobuf_response_message_descriptor: MessageDescriptor,
    },
}

// Context for request processing.
#[derive(Debug, Clone)]
struct Ctx {
    config: Config,
}

#[derive(Debug, Clone)]
struct Config {
    flag_ttl: usize,
    flag_regexp: Regex,
    flag_alphabet: String,
    flag_postfix: String,
    target: Target,
}
