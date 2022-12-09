use warp::*;
use prometheus::Encoder;
use crate::metrics::REGISTRY;


pub async fn metrics_handler() -> Result<impl Reply, Rejection> {
    let encoder = prometheus::TextEncoder::new();
    let mut buffer = Vec::new();
    if let Err(e) = encoder.encode(&REGISTRY.gather(), &mut buffer) {
        eprintln!("couldn't encode requests metrics: {:?}", e);
    }
    
    let mut result = match String::from_utf8(buffer.clone()) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("couldn't convert metric from utf8 to String: {:?}", e);
            String::default()
        }
    };

    buffer.clear();

    let mut buffer = Vec::new();
    if let Err(e) = encoder.encode(&prometheus::gather(), &mut buffer) {
        eprintln!("couldn't encode prometheus metrics: {:?}", e);
    }

    let prometheus_result = match String::from_utf8(buffer.clone()) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("couldn't convert metric from utf8 to String: {:?}", e);
            String::default()
        }
    };

    buffer.clear();

    result.push_str(&prometheus_result);

    Ok(result)
}