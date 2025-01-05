#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use http::Request;

    use crate::{
        config::Target,
        server::Server,
        traits::{MockStorage, MockTargetsProvider},
    };

    #[tokio::test]
    async fn test_handle_request() {
        // let config = Arc::new(MockTargetsProvider::default());
        // let cache = Arc::new(MockStorage::default());
        // let server = Server::new(config, cache);

        // let flag = "flag1";
        // let new_flag = "new_flag1";

        // config.expect_targets().times(1).returning(|| {
        //     Ok(vec![Target {
        //         port: 5001,
        //         team_host: "192.0.0.1".to_string(),
        //     }])
        // });

        // let result: Result<http::Response<hyper::Body>, crate::errors::ServerError> =
        //     server.handle_request(Request::new("body".into())).await;

        // assert!(result.is_ok());
    }
}
