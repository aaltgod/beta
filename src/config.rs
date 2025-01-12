use lazy_static::lazy_static;
use anyhow::anyhow;


use regex::Regex;
use serde::Deserialize;
use std::io::Read;
use std::sync::RwLock;
use std::{
    sync::Arc,
    thread,
};

use crate::errors::ConfigError;

lazy_static! {
    pub static ref ENV_VAR_REGEX: Regex =
        Regex::new(r"\$\{([\w]*)\}").expect("invalid ENV_VAR_REGEX");
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
    flag_ttl: Option<usize>,
    flag_regexp: Option<String>,
    flag_alphabet: Option<String>,
    flag_postfix: Option<String>,
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

#[derive(Debug)]
/// Config for proxy settings in real-time.
pub struct ProxySettingsConfig {
    pub flag_ttl: usize,
    pub flag_regexp: Regex,
    pub flag_alphabet: String,
    pub flag_postfix: String,
    pub targets: Vec<Target>,
}

impl Clone for ProxySettingsConfig {
    fn clone(&self) -> Self {
        ProxySettingsConfig {
            flag_ttl: self.flag_ttl,
            flag_regexp: self.flag_regexp.clone(),
            flag_alphabet: self.flag_alphabet.clone(),
            flag_postfix: self.flag_postfix.clone(),
            targets: self.targets.clone(),
        }
    }
}

impl ProxySettingsConfig {
    pub fn new() -> Result<Arc<RwLock<Self>>, ConfigError> {
        let (flag_ttl, flag_regexp, flag_alphabet, flag_postfix, targets) =
            build_proxy_settings_config_data()?;

        let c = Arc::new(RwLock::new(ProxySettingsConfig {
            flag_ttl,
            flag_regexp,
            flag_alphabet,
            flag_postfix,
            targets,
        }));

        ProxySettingsConfig::watch(Arc::clone(&c));

        Ok(c)
    }

    fn watch(config: Arc<RwLock<Self>>) {
        thread::spawn(move || loop {
            thread::sleep(std::time::Duration::from_secs(5));

            let mut config = match config.write() {
                Ok(res) => res,
                Err(e) => {
                    error!("{}", 
                    ConfigError::Etc {
                        description: "couldn't get write lock".to_string(),
                        error: anyhow!("{e}"), 
                    });

                    continue;
                }
            };

            let (new_flag_ttl, new_flag_regexp, new_flag_alphabet, new_flag_postfix, new_targets) =
                match build_proxy_settings_config_data() {
                    Ok(res) => res,
                    Err(e) => {
                        error!("{}", 
                        ConfigError::Etc {
                             description: "couldn't build config with updates: {e}\nPlease, look at `proxy_settings` section in config.yaml.".to_string(),
                              error: e.into() 
                            });

                        continue;
                    }
                };
            
            config.flag_ttl = new_flag_ttl;
            config.flag_regexp = new_flag_regexp;
            config.flag_alphabet = new_flag_alphabet;
            config.flag_postfix = new_flag_postfix;
            config.targets = new_targets;

        });
    }
}

fn build_proxy_settings_config_data() -> Result<(usize, Regex, String, String, Vec<Target>), ConfigError> {
    let file_data = get_file_data("config.yaml")?;
    let config_from_reader: ProxySettingsFromReader = serde_yaml::from_str(file_data.as_str())
        .map_err(|e| ConfigError::Etc {
            description: "couldn't read config values".to_string(),
            error: e.into(),
        })?;

    let proxy_settings = config_from_reader
        .proxy_settings
        .ok_or_else(|| ConfigError::NoKey {
            key: "proxy_settings".to_string(),
        })?;

    let targets = proxy_settings
        .targets
        .ok_or_else(|| ConfigError::NoKey {
            key: "targets".to_string(),
        })?
        .into_iter()
        .map(|target| {
            Ok(Target {
                port: target.port.ok_or_else(|| ConfigError::NoListElement {
                    list_name: "targets".to_string(),
                    element_example: "{ team_host: 127.0.0.1, port: 4554 }".to_string(),
                })?,
                team_host: target.team_host.ok_or_else(|| ConfigError::NoListElement {
                    list_name: "targets".to_string(),
                    element_example: "{ team_host: 127.0.0.1, port: 4554 }".to_string(),
                })?,
            })
        })
        .collect::<Result<Vec<_>, ConfigError>>()?;
    
    let flag_ttl = proxy_settings
        .flag_ttl
        .ok_or_else(|| ConfigError::NoGroupKey {
            group: "proxy_settings".to_string(),
            key: "flag_ttl".to_string(),
            value_example: "flag_ttl: 60".to_string(),
        })?;

    let flag_regexp =
        Regex::new(
            &proxy_settings
                .flag_regexp
                .ok_or_else(|| ConfigError::NoGroupKey {
                    group: "proxy_settings".to_string(),
                    key: "flag_regexp".to_string(),
                    value_example: "flag_regexp: \"[A-Za-z0-9]{31}=\"".to_string(),
                })?,
        )
        .map_err(|e| ConfigError::Etc {
            description: "couldn't build flag_regexp".to_string(),
            error: e.into(),
        })?;

    let flag_alphabet = proxy_settings
        .flag_alphabet
        .ok_or_else(|| ConfigError::NoGroupKey {
            group: "proxy_settings".to_string(),
            key: "flag_alphabet".to_string(),
            value_example:
                "flag_alphabet: \"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789\""
                    .to_string(),
        })?;

    let flag_postfix = proxy_settings
        .flag_postfix
        .ok_or_else(|| ConfigError::NoGroupKey {
            group: "proxy_settings".to_string(),
            key: "flag_postfix".to_string(),
            value_example: "flag_postfix: \"=\"".to_string(),
        })?;

    Ok((flag_ttl, flag_regexp, flag_alphabet, flag_postfix, targets))
}

fn build_envs_from_str(str: &str) -> Result<String, ConfigError> {
    let mut result = str.to_string();

    for (c, [env_name]) in ENV_VAR_REGEX
        .clone()
        .captures_iter(str)
        .map(|c| c.extract())
    {
        let env_value = dotenv::var(env_name).map_err(|_| ConfigError::Env {
            env_name: env_name.to_string(),
        })?;

        result = result.replace(c, env_value.as_str())
    }

    Ok(result)
}
