#[cfg(test)]
mod tests {
    use std::{
        io::{Read, Write},
        sync::{Arc, RwLock},
    };

    use http::Request;
    use mockall::predicate::eq;
    use regex::Regex;

    use crate::{
        config::{ProxySettingsConfig, Target},
        server::{Server, HEADER_VALUE_URL_ENCODED},
        traits::{MockFlagsProvider, MockSender, MockStorage},
    };

    use lazy_static::lazy_static;

    lazy_static! {
        static ref HOST: String = "10.10.2.10:1337".to_string();
        static ref URI_FLAG: String = format!("http://{}/flag", *HOST);
        static ref FLAG_REGEXP: Regex =
            Regex::new("[A-Za-z0-9]{31}=").expect("invalid FLAG_REGEXP");
        static ref FLAG_ALPHABET: String =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789".to_string();
        static ref FLAG_POSTFIX: String = "=".to_string();
        static ref FLAG1: String = "WEQEQWEQWEQWEQWEQWEQWEQWEQWEQWQ=".to_string();
        static ref FLAG2: String = "TURTURUTIRTURITURTURTRRTRETETET=".to_string();
        static ref FLAG1_URL_ENCODED: String = "WEQEQWEQWEQWEQWEQWEQWEQWEQWEQWQ%3D".to_string();
        static ref FLAG2_URL_ENCODED: String = "TURTURUTIRTURITURTURTRRTRETETET%3D".to_string();
        static ref TARGETS: Vec<Target> = vec![Target {
            port: 1337,
            team_host: "10.10.3.10".to_string(),
        }];
    }

    const FLAG_LENGTH: usize = 32;
    const FLAG_TTL: usize = 60;

    // Success

    #[tokio::test]
    async fn handle_request_success_checker_puts_flag_in_body() {
        let mut mock_storage = MockStorage::default();
        let mut mock_sender = MockSender::default();
        let mut mock_flags_provider = MockFlagsProvider::default();

        mock_storage
            .expect_get_flag()
            .with(eq(FLAG1.clone()))
            .returning(|_| Ok("".to_string()));

        mock_flags_provider
            .expect_build_flag()
            .with(
                eq(FLAG_ALPHABET.clone()),
                eq(FLAG_LENGTH),
                eq(FLAG_POSTFIX.clone()),
            )
            .returning(|_, _, _| FLAG2.clone());

        mock_storage
            .expect_set_flag()
            .with(eq(FLAG1.clone()), eq(FLAG2.clone()), eq(FLAG_TTL))
            .returning(|_, _, _| Ok(()));

        mock_storage
            .expect_set_flag()
            .with(eq(FLAG2.clone()), eq(FLAG1.clone()), eq(FLAG_TTL))
            .returning(|_, _, _| Ok(()));

        mock_sender.expect_send().return_once(|_| {
            Ok(http::Response::builder()
                .status(201)
                .body(hyper::Body::from("OK"))
                .unwrap())
        });

        let config = Arc::new(RwLock::new(ProxySettingsConfig {
            flag_ttl: FLAG_TTL,
            flag_regexp: FLAG_REGEXP.clone(),
            flag_alphabet: FLAG_ALPHABET.clone(),
            flag_postfix: FLAG_POSTFIX.clone(),
            targets: TARGETS.clone(),
        }));
        let cache = Arc::new(mock_storage);
        let client = Arc::new(mock_sender);
        let flags_provider = Arc::new(mock_flags_provider);

        let server = Server::new(config, cache, client, flags_provider);

        let result: Result<http::Response<hyper::Body>, crate::errors::ServerError> = server
            .handle_request(
                Request::get(URI_FLAG.clone())
                    .header("host", HOST.clone())
                    .body(hyper::Body::from(format!("flag={}", FLAG1.clone())))
                    .unwrap(),
            )
            .await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn handle_request_success_checker_puts_flag_in_body_url_encoded() {
        let mut mock_storage = MockStorage::default();
        let mut mock_sender = MockSender::default();
        let mut mock_flags_provider = MockFlagsProvider::default();

        mock_storage
            .expect_get_flag()
            .with(eq(FLAG1.clone()))
            .returning(|_| Ok("".to_string()));

        mock_flags_provider
            .expect_build_flag()
            .with(
                eq(FLAG_ALPHABET.clone()),
                eq(FLAG_LENGTH),
                eq(FLAG_POSTFIX.clone()),
            )
            .returning(|_, _, _| FLAG2.clone());

        mock_storage
            .expect_set_flag()
            .with(eq(FLAG1.clone()), eq(FLAG2.clone()), eq(FLAG_TTL))
            .returning(|_, _, _| Ok(()));

        mock_storage
            .expect_set_flag()
            .with(eq(FLAG2.clone()), eq(FLAG1.clone()), eq(FLAG_TTL))
            .returning(|_, _, _| Ok(()));

        mock_sender.expect_send().return_once(|_| {
            Ok(http::Response::builder()
                .status(201)
                .body(hyper::Body::from("OK"))
                .unwrap())
        });

        let config = Arc::new(RwLock::new(ProxySettingsConfig {
            flag_ttl: FLAG_TTL,
            flag_regexp: FLAG_REGEXP.clone(),
            flag_alphabet: FLAG_ALPHABET.clone(),
            flag_postfix: FLAG_POSTFIX.clone(),
            targets: TARGETS.clone(),
        }));
        let cache = Arc::new(mock_storage);
        let client = Arc::new(mock_sender);
        let flags_provider = Arc::new(mock_flags_provider);

        let server = Server::new(config, cache, client, flags_provider);

        let result: Result<http::Response<hyper::Body>, crate::errors::ServerError> = server
            .handle_request(
                Request::get(URI_FLAG.clone())
                    .header("host", HOST.clone())
                    .header("Content-Type", HEADER_VALUE_URL_ENCODED.clone())
                    .body(hyper::Body::from(format!(
                        "flag={}",
                        FLAG1_URL_ENCODED.clone()
                    )))
                    .unwrap(),
            )
            .await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn handle_request_success_checker_puts_flag_in_uri() {
        let mut mock_storage = MockStorage::default();
        let mut mock_sender = MockSender::default();
        let mut mock_flags_provider = MockFlagsProvider::default();

        mock_storage
            .expect_get_flag()
            .with(eq(FLAG1.clone()))
            .returning(|_| Ok("".to_string()));

        mock_flags_provider
            .expect_build_flag()
            .with(
                eq(FLAG_ALPHABET.clone()),
                eq(FLAG_LENGTH),
                eq(FLAG_POSTFIX.clone()),
            )
            .returning(|_, _, _| FLAG2.clone());

        mock_storage
            .expect_set_flag()
            .with(eq(FLAG1.clone()), eq(FLAG2.clone()), eq(FLAG_TTL))
            .returning(|_, _, _| Ok(()));

        mock_storage
            .expect_set_flag()
            .with(eq(FLAG2.clone()), eq(FLAG1.clone()), eq(FLAG_TTL))
            .returning(|_, _, _| Ok(()));

        mock_sender.expect_send().return_once(|_| {
            Ok(http::Response::builder()
                .status(201)
                .body(hyper::Body::from("OK"))
                .unwrap())
        });

        let config = Arc::new(RwLock::new(ProxySettingsConfig {
            flag_ttl: FLAG_TTL,
            flag_regexp: FLAG_REGEXP.clone(),
            flag_alphabet: FLAG_ALPHABET.clone(),
            flag_postfix: FLAG_POSTFIX.clone(),
            targets: TARGETS.clone(),
        }));
        let cache = Arc::new(mock_storage);
        let client = Arc::new(mock_sender);
        let flags_provider = Arc::new(mock_flags_provider);

        let server = Server::new(config, cache, client, flags_provider);

        let result: Result<http::Response<hyper::Body>, crate::errors::ServerError> = server
            .handle_request(
                Request::get(format!("{}?flag={}", URI_FLAG.clone(), FLAG1.clone()))
                    .header("host", HOST.clone())
                    .body(hyper::Body::empty())
                    .unwrap(),
            )
            .await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn handle_request_success_checker_puts_flag_in_uri_url_encoded() {
        let mut mock_storage = MockStorage::default();
        let mut mock_sender = MockSender::default();
        let mut mock_flags_provider = MockFlagsProvider::default();

        mock_storage
            .expect_get_flag()
            .with(eq(FLAG1.clone()))
            .returning(|_| Ok("".to_string()));

        mock_flags_provider
            .expect_build_flag()
            .with(
                eq(FLAG_ALPHABET.clone()),
                eq(FLAG_LENGTH),
                eq(FLAG_POSTFIX.clone()),
            )
            .returning(|_, _, _| FLAG2.clone());

        mock_storage
            .expect_set_flag()
            .with(eq(FLAG1.clone()), eq(FLAG2.clone()), eq(FLAG_TTL))
            .returning(|_, _, _| Ok(()));

        mock_storage
            .expect_set_flag()
            .with(eq(FLAG2.clone()), eq(FLAG1.clone()), eq(FLAG_TTL))
            .returning(|_, _, _| Ok(()));

        mock_sender.expect_send().return_once(|_| {
            Ok(http::Response::builder()
                .status(201)
                .body(hyper::Body::from("OK"))
                .unwrap())
        });

        let config = Arc::new(RwLock::new(ProxySettingsConfig {
            flag_ttl: FLAG_TTL,
            flag_regexp: FLAG_REGEXP.clone(),
            flag_alphabet: FLAG_ALPHABET.clone(),
            flag_postfix: FLAG_POSTFIX.clone(),
            targets: TARGETS.clone(),
        }));
        let cache = Arc::new(mock_storage);
        let client = Arc::new(mock_sender);
        let flags_provider = Arc::new(mock_flags_provider);

        let server = Server::new(config, cache, client, flags_provider);

        let result: Result<http::Response<hyper::Body>, crate::errors::ServerError> = server
            .handle_request(
                Request::get(format!(
                    "{}?flag={}",
                    URI_FLAG.clone(),
                    FLAG1_URL_ENCODED.clone()
                ))
                .header("host", HOST.clone())
                .body(hyper::Body::empty())
                .unwrap(),
            )
            .await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn handle_request_success_checker_gets_flag() {
        let mut mock_storage = MockStorage::default();
        let mut mock_sender = MockSender::default();
        let mock_flags_provider = MockFlagsProvider::default();

        let response_body = hyper::Body::from(format!("flag={}", FLAG2.clone()));

        mock_sender.expect_send().return_once(|_| {
            Ok(http::Response::builder()
                .status(200)
                .body(response_body)
                .unwrap())
        });

        mock_storage
            .expect_get_flag()
            .with(eq(FLAG2.clone()))
            .returning(|_| Ok(FLAG1.clone()));

        let config = Arc::new(RwLock::new(ProxySettingsConfig {
            flag_ttl: FLAG_TTL,
            flag_regexp: FLAG_REGEXP.clone(),
            flag_alphabet: FLAG_ALPHABET.clone(),
            flag_postfix: FLAG_POSTFIX.clone(),
            targets: TARGETS.clone(),
        }));
        let cache = Arc::new(mock_storage);
        let client = Arc::new(mock_sender);
        let flags_provider = Arc::new(mock_flags_provider);

        let server = Server::new(config, cache, client, flags_provider);

        let result: Result<http::Response<hyper::Body>, crate::errors::ServerError> = server
            .handle_request(
                Request::get(URI_FLAG.clone())
                    .header("host", HOST.clone())
                    .body(hyper::Body::empty())
                    .unwrap(),
            )
            .await;

        let result_body = hyper::body::to_bytes(result.unwrap().into_body())
            .await
            .unwrap();

        assert_eq!(result_body, format!("flag={}", FLAG1.clone()));
    }

    #[tokio::test]
    async fn handle_request_success_checker_gets_flag_gzip() {
        let mut mock_storage = MockStorage::default();
        let mut mock_sender = MockSender::default();
        let mock_flags_provider = MockFlagsProvider::default();

        let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::best());
        e.write_all(format!("flag={}", FLAG2.clone()).as_bytes())
            .unwrap();

        let encoded_body = e.finish().unwrap();
        let response_body = hyper::Body::from(encoded_body);

        mock_sender.expect_send().return_once(|_| {
            Ok(http::Response::builder()
                .header("Content-Encoding", "gzip")
                .status(200)
                .body(response_body)
                .unwrap())
        });

        mock_storage
            .expect_get_flag()
            .with(eq(FLAG2.clone()))
            .returning(|_| Ok(FLAG1.clone()));

        let config = Arc::new(RwLock::new(ProxySettingsConfig {
            flag_ttl: FLAG_TTL,
            flag_regexp: FLAG_REGEXP.clone(),
            flag_alphabet: FLAG_ALPHABET.clone(),
            flag_postfix: FLAG_POSTFIX.clone(),
            targets: TARGETS.clone(),
        }));
        let cache = Arc::new(mock_storage);
        let client = Arc::new(mock_sender);
        let flags_provider = Arc::new(mock_flags_provider);

        let server = Server::new(config, cache, client, flags_provider);

        let result: Result<http::Response<hyper::Body>, crate::errors::ServerError> = server
            .handle_request(
                Request::get(URI_FLAG.clone())
                    .header("host", HOST.clone())
                    .body(hyper::Body::empty())
                    .unwrap(),
            )
            .await;

        let result_body = hyper::body::to_bytes(result.unwrap().into_body())
            .await
            .unwrap();

        let mut d = flate2::read::GzDecoder::new(result_body.as_ref());
        let mut result = String::new();
        d.read_to_string(&mut result).unwrap();

        assert_eq!(result, format!("flag={}", FLAG1.clone()));
    }

    #[tokio::test]
    async fn handle_request_success_checker_gets_flags() {
        let mut mock_storage = MockStorage::default();
        let mut mock_sender = MockSender::default();
        let mock_flags_provider = MockFlagsProvider::default();

        let response_body = hyper::Body::from(format!("flag={}{}", FLAG2.clone(), FLAG2.clone()));

        mock_sender.expect_send().return_once(|_| {
            Ok(http::Response::builder()
                .status(200)
                .body(response_body)
                .unwrap())
        });

        mock_storage
            .expect_get_flag()
            .with(eq(FLAG2.clone()))
            .returning(|_| Ok(FLAG1.clone()));

        mock_storage
            .expect_get_flag()
            .with(eq(FLAG2.clone()))
            .returning(|_| Ok(FLAG1.clone()));

        let config = Arc::new(RwLock::new(ProxySettingsConfig {
            flag_ttl: FLAG_TTL,
            flag_regexp: FLAG_REGEXP.clone(),
            flag_alphabet: FLAG_ALPHABET.clone(),
            flag_postfix: FLAG_POSTFIX.clone(),
            targets: TARGETS.clone(),
        }));
        let cache = Arc::new(mock_storage);
        let client = Arc::new(mock_sender);
        let flags_provider = Arc::new(mock_flags_provider);

        let server = Server::new(config, cache, client, flags_provider);

        let result: Result<http::Response<hyper::Body>, crate::errors::ServerError> = server
            .handle_request(
                Request::get(URI_FLAG.clone())
                    .header("host", HOST.clone())
                    .body(hyper::Body::empty())
                    .unwrap(),
            )
            .await;

        let result_body = hyper::body::to_bytes(result.unwrap().into_body())
            .await
            .unwrap();

        assert_eq!(
            result_body,
            format!("flag={}{}", FLAG1.clone(), FLAG1.clone())
        );
    }

    #[tokio::test]
    async fn handle_request_success_checker_gets_flag_url_encoded() {
        let mut mock_storage = MockStorage::default();
        let mut mock_sender = MockSender::default();
        let mock_flags_provider = MockFlagsProvider::default();

        let response_body = hyper::Body::from(format!("flag={}", FLAG2_URL_ENCODED.clone()));

        mock_sender.expect_send().return_once(|_| {
            Ok(http::Response::builder()
                .header("Content-Type", HEADER_VALUE_URL_ENCODED.clone())
                .status(200)
                .body(response_body)
                .unwrap())
        });

        mock_storage
            .expect_get_flag()
            .with(eq(FLAG2.clone()))
            .returning(|_| Ok(FLAG1.clone()));

        let config = Arc::new(RwLock::new(ProxySettingsConfig {
            flag_ttl: FLAG_TTL,
            flag_regexp: FLAG_REGEXP.clone(),
            flag_alphabet: FLAG_ALPHABET.clone(),
            flag_postfix: FLAG_POSTFIX.clone(),
            targets: TARGETS.clone(),
        }));
        let cache = Arc::new(mock_storage);
        let client = Arc::new(mock_sender);
        let flags_provider = Arc::new(mock_flags_provider);

        let server = Server::new(config, cache, client, flags_provider);

        let result: Result<http::Response<hyper::Body>, crate::errors::ServerError> = server
            .handle_request(
                Request::get(URI_FLAG.clone())
                    .header("host", HOST.clone())
                    .header("Content-Type", HEADER_VALUE_URL_ENCODED.clone())
                    .body(hyper::Body::empty())
                    .unwrap(),
            )
            .await;

        let result_body = hyper::body::to_bytes(result.unwrap().into_body())
            .await
            .unwrap();

        assert_eq!(result_body, format!("flag={}", FLAG1_URL_ENCODED.clone()));
    }

    // Fail
    // TODO: add tests for failed cases
}
