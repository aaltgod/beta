use serde::Deserialize;
use std::{fs::File, thread};

use crate::{errors::ConfigError, helpers::ENV_VAR_REGEX};

#[derive(Default, Deserialize, Debug, Clone)]
struct SecretsFromReader {
    secrets: Option<Secrets>,
}

#[derive(Default, Deserialize, Debug, Clone)]
struct Secrets {
    redis_addr: Option<String>,
    redis_password: Option<String>,
    proxy_addr: Option<String>,
    metrics_addr: Option<String>,
}

#[derive(Default, Deserialize, Debug, Clone)]
struct ProxySettingsFromReader {
    proxy_settings: Option<ProxySettings>,
}

#[derive(Default, Deserialize, Debug, Clone)]
struct ProxySettings {
    service_ports: Option<Vec<u32>>,
    team_ips: Option<Vec<String>>,
    targets: Option<Vec<TargetFromReader>>,
}

#[derive(Default, Deserialize, Debug, Clone)]
struct TargetFromReader {
    port: Option<u32>,
    team_ip: Option<String>,
}

/// Config for env variables. It is used to initialize.
#[derive(Default, Debug, Clone)]
pub struct SecretsConfig {
    pub redis_addr: String,
    pub redis_password: String,
    pub proxy_addr: String,
    pub metrics_addr: String,
}

/// Config for proxy settings.
#[derive(Default, Debug, Clone)]
pub struct ProxySettingsConfig {
    service_ports: Vec<u32>,
    team_ips: Vec<String>,
    targets: Vec<Target>,
}

#[derive(Default, Debug, Clone)]
pub struct Target {
    pub port: u32,
    pub team_ip: String,
}

fn open_file(path: &str) -> Result<File, ConfigError> {
    match std::fs::File::open(path) {
        Ok(res) => return Ok(res),
        Err(e) => {
            return Err(ConfigError::Etc {
                description: format!("couldn't open file `{}`", path),
                error: e.into(),
            })
        }
    }
}

pub fn build_secrets_config() -> Result<SecretsConfig, ConfigError> {
    let config_file = open_file("config.yaml")?;
    let config_from_reader: SecretsFromReader = match serde_yaml::from_reader(config_file) {
        Ok(res) => res,
        Err(e) => {
            return Err(ConfigError::Etc {
                description: "couldn't read config values".to_string(),
                error: e.into(),
            })
        }
    };

    let secrets = match config_from_reader.secrets {
        Some(res) => res,
        None => {
            return Err(ConfigError::NoKey {
                key: "secrets".to_string(),
            });
        }
    };

    Ok(SecretsConfig {
        redis_addr: match secrets.redis_addr {
            Some(res) => match build_envs_from_str(&res) {
                Ok(res) => res,
                Err(e) => {
                    return Err(e);
                }
            },
            None => {
                return Err(ConfigError::NoGroupKey {
                    group: "secrets".to_string(),
                    key: "redis_addr".to_string(),
                    value_example: "127.0.0.1:2137".to_string(),
                });
            }
        },
        redis_password: match secrets.redis_password {
            Some(res) => match build_envs_from_str(&res) {
                Ok(res) => res,
                Err(e) => {
                    return Err(e);
                }
            },
            None => {
                return Err(ConfigError::NoGroupKey {
                    group: "secrets".to_string(),
                    key: "redis_password".to_string(),
                    value_example: "password".to_string(),
                });
            }
        },
        proxy_addr: match secrets.proxy_addr {
            Some(res) => res,
            None => {
                return Err(ConfigError::NoGroupKey {
                    group: "secrets".to_string(),
                    key: "proxy_addr".to_string(),
                    value_example: "0.0.0.0:1337".to_string(),
                });
            }
        },
        metrics_addr: match secrets.metrics_addr {
            Some(res) => res,
            None => {
                return Err(ConfigError::NoGroupKey {
                    group: "secrets".to_string(),
                    key: "metrics_addr".to_string(),
                    value_example: "0.0.0.0:8989".to_string(),
                });
            }
        },
    })
}

impl ProxySettingsConfig {
    pub fn new() -> Result<Self, ConfigError> {
        let mut c = ProxySettingsConfig {
            service_ports: vec![],
            team_ips: vec![],
            targets: vec![],
        };

        let build_result = c.clone().build()?;

        c.service_ports = build_result.service_ports;
        c.targets = build_result.targets;
        c.team_ips = build_result.team_ips;

        c.clone().watch();

        Ok(c)
    }

    fn watch(mut self) {
        std::thread::spawn(move || loop {
            thread::sleep(std::time::Duration::from_secs(2));

            let updated_config = match self.clone().build() {
                Ok(res) => res,
                Err(e) => {
                    error!("Got error, proxy settings config changes will not be applied: {e}");

                    continue
                }
            };

            let mut found_equals = 0;

            for target in self.targets.iter() {
                for updated_target in updated_config.targets.iter() {
                    if updated_target.port.eq(&target.port)
                        && updated_target.team_ip.eq(&target.team_ip)
                    {
                        found_equals += 1;
                        break;
                    }
                }
            }

            if !found_equals.eq(&self.targets.len())
                || !self.targets.len().eq(&updated_config.targets.len())
            {
                warn!("proxy settings config changes applied");
                self.targets = updated_config.targets;
            }
        });
    }

    pub fn services_ports(self) -> Vec<u32> {
        self.service_ports
    }

    pub fn targets(self) -> Vec<Target> {
        self.targets
    }

    fn build(self) -> Result<ProxySettingsConfig, ConfigError> {
        let config_file = open_file("config.yaml")?;
        let config_from_reader: ProxySettingsFromReader = match serde_yaml::from_reader(config_file)
        {
            Ok(res) => res,
            Err(e) => {
                return Err(ConfigError::Etc {
                    description: "couldn't read config values".to_string(),
                    error: e.into(),
                })
            }
        };

        let proxy_settings = match config_from_reader.proxy_settings {
            Some(res) => res,
            None => {
                return Err(ConfigError::NoKey {
                    key: "proxy_settings".to_string(),
                })
            }
        };

        Ok(ProxySettingsConfig {
            service_ports: match proxy_settings.service_ports {
                Some(res) => res,
                None => {
                    return Err(ConfigError::NoGroupKey {
                        group: "proxy_settings".to_string(),
                        key: "service_ports".to_string(),
                        value_example: "[ 3444, 3445, 3446 ]".to_string(),
                    })
                }
            },
            team_ips: match proxy_settings.team_ips {
                Some(res) => res,
                None => {
                    return Err(ConfigError::NoGroupKey {
                        group: "proxy_settings".to_string(),
                        key: "team_ips".to_string(),
                        value_example: "[ 10.0.12.23, 10.0.12.24, 10.0.12.25 ]".to_string(),
                    })
                }
            },
            targets: {
                let targets = match proxy_settings.targets {
                    Some(res) => res,
                    None => {
                        return Err(ConfigError::NoKey {
                            key: "targets".to_string(),
                        })
                    }
                };

                let mut result: Vec<Target> = Vec::new();

                for target in targets.iter() {
                    result.push(Target {
                        port: match target.clone().port {
                            Some(res) => res,
                            None => {
                                return Err(ConfigError::NoListElement {
                                    list_name: "targets".to_string(),
                                    element_example: "{ team_ip: 127.0.0.1, port: 4554 }"
                                        .to_string(),
                                })
                            }
                        },
                        team_ip: match target.clone().team_ip {
                            Some(res) => res,
                            None => {
                                return Err(ConfigError::NoListElement {
                                    list_name: "targets".to_string(),
                                    element_example: "{ team_ip: 127.0.0.1, port: 4554 }"
                                        .to_string(),
                                })
                            }
                        },
                    })
                }

                result
            },
        })
    }
}

fn build_envs_from_str(str: &str) -> Result<String, ConfigError> {
    let mut result = str.to_string();

    for v in ENV_VAR_REGEX.clone().captures_iter(str) {
        let env_name = v.get(1).map_or("", |m| m.as_str());
        let env_value = match dotenv::var(env_name) {
            Ok(res) => res,
            Err(_) => {
                return Err(ConfigError::Env {
                    env_name: env_name.to_string(),
                })
            }
        };

        let env_var_reg = v.get(0).map(|s| s.as_str()).unwrap();

        result = result.replace(env_var_reg, env_value.as_str())
    }

    Ok(result)
}
