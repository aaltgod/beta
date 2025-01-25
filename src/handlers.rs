use prometheus::Encoder;
use warp::http::StatusCode;
use warp::reply;

use crate::metrics::REGISTRY;

pub async fn metrics_handler() -> Result<impl reply::Reply, warp::Rejection> {
    let encoder = prometheus::TextEncoder::new();
    let mut buffer = Vec::new();
    if let Err(e) = encoder.encode(&REGISTRY.gather(), &mut buffer) {
        error!("couldn't encode requests metrics: {}", e);

        return Ok(reply::with_status(
            "INTERNAL_SERVER_ERROR".to_string(),
            StatusCode::INTERNAL_SERVER_ERROR,
        ));
    }

    let mut result = match String::from_utf8(buffer.clone()) {
        Ok(res) => res,
        Err(e) => {
            error!("couldn't convert metrics from utf8 to String: {}", e);

            return Ok(reply::with_status(
                "INTERNAL_SERVER_ERROR".to_string(),
                StatusCode::INTERNAL_SERVER_ERROR,
            ));
        }
    };

    buffer.clear();

    if let Err(e) = encoder.encode(&prometheus::gather(), &mut buffer) {
        error!("couldn't encode prometheus metrics: {}", e);

        return Ok(reply::with_status(
            "INTERNAL_SERVER_ERROR".to_string(),
            StatusCode::INTERNAL_SERVER_ERROR,
        ));
    }

    let prometheus_result = match String::from_utf8(buffer) {
        Ok(v) => v,
        Err(e) => {
            error!("couldn't convert metric from utf8 to String: {}", e);

            return Ok(reply::with_status(
                "INTERNAL_SERVER_ERROR".to_string(),
                StatusCode::INTERNAL_SERVER_ERROR,
            ));
        }
    };

    result.push_str(&prometheus_result);

    Ok(reply::with_status(result, StatusCode::OK))
}
