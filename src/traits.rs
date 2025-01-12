use anyhow::Error;
use async_trait::async_trait;
use http::{Request, Response};
use hyper::Body;

use crate::errors::CacheError;

#[cfg(test)]
use mockall::{automock, predicate::*};
#[cfg_attr(test, automock)]
#[async_trait]
pub trait Storage {
    async fn set_flag(&self, key: &str, value: &str, ttl: usize) -> Result<(), CacheError>;
    async fn get_flag(&self, key: &str) -> Result<String, CacheError>;
}

#[cfg_attr(test, automock)]
#[async_trait]
pub trait Sender {
    async fn send(&self, req: Request<Body>) -> Result<Response<Body>, Error>;
}

#[cfg_attr(test, automock)]
pub trait FlagsProvider {
    fn build_flag(&self, alphabet: &str, length: usize, postfix: &str) -> String;
}
