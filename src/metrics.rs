use lazy_static::lazy_static;
use prometheus::{IntCounter, Registry};

lazy_static! {
    pub static ref REGISTRY: Registry = Registry::new();
    pub static ref INCOMING_REQUESTS: IntCounter =
        IntCounter::new("incoming_requests", "Incoming requests")
            .expect("INCOMING_REQUESTS metrics can't be created");
}

pub fn register_metrics() {
    REGISTRY
        .register(Box::new(INCOMING_REQUESTS.clone()))
        .expect("INCOMING_REQUESTS can't be registered")
}
