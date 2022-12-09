use lazy_static::lazy_static;
use prometheus::{
    HistogramOpts, Registry, IntCounter
};

lazy_static! {
    pub static ref REGISTRY: Registry = Registry::new();

    pub static ref INCOMING_REQUESTS: IntCounter = 
        IntCounter::new("incoming_requests", "Incoming requests").expect("incoming metrics can't be created");
}

pub fn register_metrics() {
    REGISTRY
        .register(Box::new(INCOMING_REQUESTS.clone()))
        .expect("incoming requests can't be created")
}