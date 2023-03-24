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

impl Config {
    pub fn build() -> Self {
        let config_file = std::fs::File::open("config.yaml").expect("couldn't open config file");

        let config: Config =
            serde_yaml::from_reader(config_file).expect("couldn't read config values");

        if config.proxy_addr.is_none() {
            panic!("proxy address is not set");
        };

        if config.service_ports.len() == 0 {
            panic!("service ports are not set");
        }

        if config.team_ips.len() == 0 {
            panic!("team ips are no set");
        }

        return config;
    }
}
