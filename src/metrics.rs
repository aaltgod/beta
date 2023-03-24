use lazy_static::lazy_static;
use prometheus::{IntCounter, IntCounterVec, Opts, Registry};

lazy_static! {
    pub static ref REGISTRY: Registry = Registry::new();
    pub static ref INCOMING_REQUEST_COUNTER: IntCounter =
        IntCounter::new("incoming_request_counter", "Incoming request counter")
            .expect("INCOMING_REQUEST_COUNTER metric can't be created");
    pub static ref TARGET_SERVICE_ERROR_COUNTER: IntCounterVec = IntCounterVec::new(
        Opts::new(
            "target_service_error_counter",
            "Target service error counter"
        ),
        &["host"]
    )
    .expect("TARGET_SERVICE_ERROR_COUNTER metric can't be created");
    pub static ref PROCESSED_REQUEST_COUNTER: IntCounterVec = IntCounterVec::new(
        Opts::new("processed_request_counter", "Processed requests counter"),
        &["status"]
    )
    .expect("PROCESSED_REQUEST_COUNTER metric can't be created");
    pub static ref PROCESSED_RESPONSE_COUNTER: IntCounterVec = IntCounterVec::new(
        Opts::new("processed_response_counter", "Processed response counter"),
        &["status"]
    )
    .expect("PROCESSED_RESPONSE_COUNTER metric can't be created");
}

pub fn register_metrics() {
    REGISTRY
        .register(Box::new(INCOMING_REQUEST_COUNTER.clone()))
        .expect("INCOMING_REQUEST_COUNTER can't be registered");

    REGISTRY
        .register(Box::new(TARGET_SERVICE_ERROR_COUNTER.clone()))
        .expect("TARGET_SERVICE_ERROR_COUNTER can't be registered");

    REGISTRY
        .register(Box::new(PROCESSED_REQUEST_COUNTER.clone()))
        .expect("PROCESSED_REQUEST_COUNTER can't be registered");

    REGISTRY
        .register(Box::new(PROCESSED_RESPONSE_COUNTER.clone()))
        .expect("PROCESSED_RESPONSE_COUNTER can't be registered")
}
