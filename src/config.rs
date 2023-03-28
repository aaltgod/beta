use serde::Deserialize;
use std::io::{Error, ErrorKind};

#[derive(Default, Deserialize, Debug, Clone)]
struct ConfigFromReader {
    proxy_addr: Option<String>,
    metrics_addr: Option<String>,
    service_ports: Option<Vec<u32>>,
    team_ips: Option<Vec<String>>,
    targets: Option<Vec<TargetFromReader>>,
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
    pub fn build() -> Result<Self, Error> {
        let config_file = std::fs::File::open("config.yaml")?;

        let config_from_reader: ConfigFromReader = match serde_yaml::from_reader(config_file) {
            Ok(res) => res,
            Err(e) => {
                return Err(Error::new(
                    ErrorKind::InvalidInput,
                    format!("couldn't read config values: {}", e),
                ))
            }
        };

        Ok(Config {
            proxy_addr: match config_from_reader.proxy_addr {
                Some(res) => res,
                None => {
                    return Err(Error::new(
                        ErrorKind::InvalidInput,
                        "`proxy_addr` is not set, want(example):

                proxy_addr: 0.0.0.0:1337
                ",
                    ))
                }
            },
            metrics_addr: match config_from_reader.metrics_addr {
                Some(res) => res,
                None => {
                    return Err(Error::new(
                        ErrorKind::InvalidInput,
                        "`metrics_addr` is not set, want(example):

                metrics_addr: 0.0.0.0:8989
                ",
                    ))
                }
            },
            service_ports: match config_from_reader.service_ports {
                Some(res) => res,
                None => {
                    return Err(Error::new(
                        ErrorKind::InvalidInput,
                        "`service_ports` is not set, want(example):

                service_ports: [ 3444, 3445, 3446 ]
                ",
                    ))
                }
            },
            team_ips: match config_from_reader.team_ips {
                Some(res) => res,
                None => {
                    return Err(Error::new(
                        ErrorKind::InvalidInput,
                        "`team_ips` is not set, want(example):

                team_ips: [ 10.0.12.23, 10.0.12.24, 10.0.12.25 ]
                ",
                    ))
                }
            },
            targets: {
                let targets = match config_from_reader.targets {
                    Some(res) => res,
                    None => {
                        return Err(Error::new(
                            ErrorKind::InvalidInput,
                            "`team_ips` is not set, want(example):

                team_ips: [ 10.0.12.23, 10.0.12.24, 10.0.12.25 ]
                ",
                        ));
                    }
                };

                let mut result: Vec<Target> = Vec::new();

                for t in targets.iter() {
                    result.push(Target {
                        port: match t.clone().port {
                            Some(res) => res,
                            None => {
                                return Err(Error::new(
                                    ErrorKind::InvalidInput,
                                    "`port` in targets is not set, want(example):

                - { team_ip: 127.0.0.1, port: 4554 }
                ",
                                ));
                            }
                        },
                        team_ip: match t.clone().team_ip {
                            Some(res) => res,
                            None => {
                                return Err(Error::new(
                                    ErrorKind::InvalidInput,
                                    "`team_ip` in targets is not set, want(example):

                - { team_ip: 127.0.0.1, port: 4554 }
                ",
                                ));
                            }
                        },
                    })
                }

                result
            },
        })
    }
}
