use anyhow::Error;
use lazy_static::lazy_static;

use regex::Regex;
use serde::Deserialize;
use std::io::Read;
use std::marker::{Send, Sync};
use std::sync::mpsc::SyncSender;
use std::{
    fs::File,
    sync::{
        mpsc::{sync_channel, Receiver},
        Arc, Mutex,
    },
    thread, vec,
};

use crate::errors::ConfigError;

lazy_static! {
    pub static ref ENV_VAR_REGEX: Regex = Regex::new(r"\$\{([\w]*)\}").unwrap();
}

#[derive(Default, Deserialize, Debug, Clone)]
struct SecretsFromReader {
    secrets: Option<Secrets>,
}

#[derive(Default, Deserialize, Debug, Clone)]
struct Secrets {
    redis_addr: Option<String>,
    redis_password: Option<String>,
    proxy_port: Option<String>,
    proxy_addr: Option<String>,
    metrics_addr: Option<String>,
}

#[derive(Default, Deserialize, Debug, Clone)]
struct ProxySettingsFromReader {
    proxy_settings: Option<ProxySettings>,
}

#[derive(Default, Deserialize, Debug, Clone)]
struct ProxySettings {
    targets: Option<Vec<TargetFromReader>>,
}

#[derive(Default, Deserialize, Debug, Clone)]
struct TargetFromReader {
    port: Option<u32>,
    team_host: Option<String>,
}

/// Config for env variables. It is used to initialize.
#[derive(Default, Debug, Clone)]
pub struct SecretsConfig {
    pub redis_addr: String,
    pub redis_password: String,
    pub proxy_port: u32,
    pub proxy_addr: String,
    pub metrics_addr: String,
}

#[derive(Default, Debug, Clone)]
pub struct HTTPSTarget {
    pub team_host: String,
}

#[derive(Default, Debug, Clone)]
pub struct Target {
    pub port: u32,
    pub team_host: String,
}

impl PartialEq for Target {
    fn eq(&self, other: &Self) -> bool {
        self.port.eq(&other.port) && self.team_host.eq(&other.team_host)
    }

    fn ne(&self, other: &Self) -> bool {
        self.port.ne(&other.port) || self.team_host.ne(&other.team_host)
    }
}

fn get_file_data(path: &str) -> Result<String, ConfigError> {
    let mut data = String::new();
    {
        let mut file = std::fs::File::open(path).map_err(|e| ConfigError::Etc {
            description: "couldn't open file".to_string(),
            error: e.into(),
        })?;

        file.read_to_string(&mut data)
            .map_err(|e| ConfigError::Etc {
                description: "couldn't read file".to_string(),
                error: e.into(),
            })?;
    };

    Ok(data)
}

pub fn build_secrets_config() -> Result<SecretsConfig, ConfigError> {
    let file_data = get_file_data("config.yaml")?;
    let config_from_reader: SecretsFromReader =
        serde_yaml::from_str(file_data.as_str()).map_err(|e| ConfigError::Etc {
            description: "couldn't read config values".to_string(),
            error: e.into(),
        })?;

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
            Some(res) => build_envs_from_str(&res)?,
            None => {
                return Err(ConfigError::NoGroupKey {
                    group: "secrets".to_string(),
                    key: "redis_addr".to_string(),
                    value_example: "127.0.0.1:2137".to_string(),
                });
            }
        },
        redis_password: match secrets.redis_password {
            Some(res) => build_envs_from_str(&res)?,
            None => {
                return Err(ConfigError::NoGroupKey {
                    group: "secrets".to_string(),
                    key: "redis_password".to_string(),
                    value_example: "password".to_string(),
                });
            }
        },
        proxy_port: match secrets.proxy_port {
            Some(res) => {
                build_envs_from_str(&res)?
                    .parse::<u32>()
                    .map_err(|e| ConfigError::Etc {
                        description: "couldn't parse PROXY_PORT in .env".to_string(),
                        error: e.into(),
                    })?
            }
            None => {
                return Err(ConfigError::NoGroupKey {
                    group: "secrets".to_string(),
                    key: "proxy_port".to_string(),
                    value_example: "1337".to_string(),
                });
            }
        },
        proxy_addr: match secrets.proxy_addr {
            Some(res) => build_envs_from_str(&res)?,
            None => {
                return Err(ConfigError::NoGroupKey {
                    group: "secrets".to_string(),
                    key: "proxy_addr".to_string(),
                    value_example: "0.0.0.0:1337".to_string(),
                });
            }
        },
        metrics_addr: match secrets.metrics_addr {
            Some(res) => build_envs_from_str(&res)?,
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

/// Config for proxy settings in real-time.
pub struct ProxySettingsConfig {
    targets: Arc<Mutex<Vec<Target>>>,
    receiver: Arc<Mutex<Receiver<Result<Event, notify::Error>>>>,
}

impl Clone for ProxySettingsConfig {
    fn clone(&self) -> Self {
        ProxySettingsConfig {
            targets: self.targets.clone(),
            receiver: Arc::clone(&self.receiver),
        }
    }
}

impl ProxySettingsConfig {
    pub fn new() -> Result<Self, ConfigError> {
        let (sender, receiver) = sync_channel(1);

        let c = ProxySettingsConfig {
            targets: Arc::new(Mutex::new(vec![])),
            receiver: Arc::new(Mutex::new(receiver)),
        };

        c.channel(sender.clone()).map_err(|e| {
            return ConfigError::Etc {
                description: "channel".to_string(),
                error: e,
            };
        })?;

        Ok(c)
    }

    fn channel(&self, sender: SyncSender<Result<Event, notify::Error>>) -> Result<(), Error> {
        let cloned_self = self.clone();

        thread::spawn(move || loop {
            thread::sleep(std::time::Duration::from_secs(5));

            let mut current_targets = cloned_self.targets.lock().unwrap();
            let new_targets = match cloned_self.build() {
                Ok(res) => res,
                Err(e) => {
                    error!("couldn't build config with updates: {e}\nPlease, look at `proxy_settings` section in config.yaml.");

                    continue;
                }
            };

            let mut added_targets = vec![];
            for new_target in new_targets.iter() {
                if !current_targets.contains(new_target) {
                    added_targets.push(new_target.to_owned())
                }
            }

            let mut removed_targets: Vec<Target> = Vec::new();
            for current_target in current_targets.iter() {
                if !new_targets.contains(current_target) {
                    removed_targets.push(current_target.to_owned())
                }
            }

            if !removed_targets.is_empty() || !added_targets.is_empty() {
                *current_targets = new_targets;

                sender.send(Ok(Event::TargetsModify)).unwrap();
            }
        });

        Ok(())
    }

    pub fn recv(&self) -> Result<Event, notify::Error> {
        Arc::clone(&self.receiver).lock().unwrap().recv().unwrap()
    }

    pub fn targets(&self) -> Vec<Target> {
        let cloned_targets = Arc::clone(&self.targets);
        let targets = cloned_targets.lock().unwrap().to_vec();
        targets
    }

    fn build(&self) -> Result<Vec<Target>, ConfigError> {
        let file_data = get_file_data("config.yaml")?;
        let config_from_reader: ProxySettingsFromReader = serde_yaml::from_str(file_data.as_str())
            .map_err(|e| ConfigError::Etc {
                description: "couldn't read config values".to_string(),
                error: e.into(),
            })?;

        let proxy_settings = match config_from_reader.proxy_settings {
            Some(res) => res,
            None => {
                return Err(ConfigError::NoKey {
                    key: "proxy_settings".to_string(),
                })
            }
        };

        let targets = {
            let targets = match proxy_settings.clone().targets {
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
                                element_example: "{ team_host: 127.0.0.1, port: 4554 }".to_string(),
                            })
                        }
                    },
                    team_host: match target.clone().team_host {
                        Some(res) => res,
                        None => {
                            return Err(ConfigError::NoListElement {
                                list_name: "targets".to_string(),
                                element_example: "{ team_host: 127.0.0.1, port: 4554 }".to_string(),
                            })
                        }
                    },
                })
            }

            result
        };

        Ok(targets)
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

pub enum Event {
    Any,
    TargetsModify,
}

unsafe impl Send for Event {}
unsafe impl Sync for Event {}
