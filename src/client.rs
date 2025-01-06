use std::time::Duration;

use anyhow::Error;
use async_trait::async_trait;
use http::{Request, Response};
use hyper::Body;

use hyper::Client as HttpClient;

use crate::traits::Sender;

#[derive(Clone)]
pub struct Client {}

impl Client {
    pub fn new() -> Self {
        Client {}
    }
}

#[async_trait]
impl Sender for Client {
    async fn send(&self, req: Request<Body>) -> Result<Response<Body>, Error> {
        let resp: Response<Body> = HttpClient::builder()
            .pool_idle_timeout(Duration::from_secs(10))
            .build_http()
            .request(req)
            .await
            .map_err(|e| Error::new(e))?;

        Ok(resp)
    }
}
