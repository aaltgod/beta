use serde::Deserialize;

#[derive(Default, Deserialize, Debug, Clone)]
struct ConfigFromReader {
    proxy_addr: Option<String>,
    metrics_addr: Option<String>,
    service_ports: Vec<u32>,
    team_ips: Vec<String>,
    targets: Vec<TargetFromReader>,
}

#[derive(Default, Deserialize, Debug, Clone)]
struct TargetFromReader {
    port: Option<u32>,
    team_ip: Option<String>,
}

#[derive(Default, Deserialize, Debug, Clone)]
pub struct Config {
    pub proxy_addr: String,
    pub metrics_addr: String,
    pub service_ports: Vec<u32>,
    pub team_ips: Vec<String>,
    pub targets: Vec<Target>,
}

#[derive(Default, Deserialize, Debug, Clone)]
pub struct Target {
    pub port: u32,
    pub team_ip: String,
}

impl Config {
    pub fn build() -> Self {
        let config_file = std::fs::File::open("config.yaml").expect("couldn't open config file");

        let config_from_reader: ConfigFromReader =
            serde_yaml::from_reader(config_file).expect("couldn't read config values");

        if config_from_reader.proxy_addr.is_none() {
            panic!("proxy address is not set");
        };

        if config_from_reader.service_ports.len() == 0 {
            panic!("service ports are not set");
        }

        if config_from_reader.team_ips.len() == 0 {
            panic!("team ips are not set");
        }

        if config_from_reader.targets.len() == 0 {
            panic!("targets are not set")
        }

        for t in config_from_reader.targets.iter() {
            if t.port.is_none() {
                panic!("target port is not set")
            }

            if t.team_ip.is_none() {
                panic!("target team ip is not set")
            }
        }

        Config {
            proxy_addr: config_from_reader.proxy_addr.unwrap(),
            metrics_addr: config_from_reader.metrics_addr.unwrap(),
            service_ports: config_from_reader.service_ports,
            team_ips: config_from_reader.team_ips,
            targets: config_from_reader
                .targets
                .iter()
                .map(|t| Target {
                    port: t.clone().port.unwrap(),
                    team_ip: t.clone().team_ip.unwrap(),
                })
                .collect(),
        }
    }
}
