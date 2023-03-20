use serde::Deserialize;

#[derive(Default, Deserialize, Debug, Clone)]
pub struct Config {
    pub proxy_addr: Option<String>,
    pub metrics_addr: Option<String>,
    pub service_ports: Vec<u32>,
    pub team_ips: Vec<String>,
    pub targets: Vec<Target>,
}

#[derive(Default, Deserialize, Debug, Clone)]
pub struct Target {
    pub port: Option<u32>,
    pub team_ip: Option<String>,
}
