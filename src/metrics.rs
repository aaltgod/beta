use lazy_static::lazy_static;
use prometheus::{IntCounter, IntCounterVec, Opts, Registry};

lazy_static! {
    pub static ref REGISTRY: Registry = Registry::new();
    pub static ref INCOMING_REQUEST_COUNTER: IntCounter =
        IntCounter::new("incoming_request_counter", "Incoming request counter")
            .expect("INCOMING_REQUEST_COUNTER metric can't be created");
    pub static ref TARGET_SERVICE_STATUS_COUNTER: IntCounterVec = IntCounterVec::new(
        Opts::new(
            "target_service_status_counter",
            "Target service status counter"
        ),
        &["host", "status"]
    )
    .expect("TARGET_SERVICE_STATUS_COUNTER metric can't be created");
    pub static ref CHANGED_REQUEST_COUNTER: IntCounterVec = IntCounterVec::new(
        Opts::new("changed_request_counter", "Changed request counter"),
        &["status"]
    )
    .expect("CHANGED_REQUEST_COUNTER metric can't be created");
    pub static ref CHANGED_RESPONSE_COUNTER: IntCounterVec = IntCounterVec::new(
        Opts::new("changed_response_counter", "Changed response counter"),
        &["status"]
    )
    .expect("CHANGED_RESPONSE_COUNTER metric can't be created");
    pub static ref HANDLED_REQUEST_COUNTER: IntCounterVec = IntCounterVec::new(
        Opts::new("handled_request_counter", "Handled request counter"),
        &["status"]
    )
    .expect("HANDLED_REQUEST_COUNTER metric can't be created");
}

pub fn register_metrics() {
    REGISTRY
        .register(Box::new(INCOMING_REQUEST_COUNTER.clone()))
        .expect("INCOMING_REQUEST_COUNTER can't be registered");

    REGISTRY
        .register(Box::new(TARGET_SERVICE_STATUS_COUNTER.clone()))
        .expect("TARGET_SERVICE_STATUS_COUNTER can't be registered");

    REGISTRY
        .register(Box::new(CHANGED_REQUEST_COUNTER.clone()))
        .expect("CHANGED_REQUEST_COUNTER can't be registered");

    REGISTRY
        .register(Box::new(CHANGED_RESPONSE_COUNTER.clone()))
        .expect("CHANGED_RESPONSE_COUNTER can't be registered");

    REGISTRY
        .register(Box::new(HANDLED_REQUEST_COUNTER.clone()))
        .expect("HANDLED_REQUEST_COUNTER can't be registered")
}
