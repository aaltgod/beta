use async_trait::async_trait;

use crate::{
    config::Target,
    errors::{CacheError, ConfigError},
};

#[cfg(test)]
use mockall::{automock, predicate::*};
#[cfg_attr(test, automock)]
#[async_trait]
pub trait Storage {
    async fn set_flag(&self, key: String, value: String) -> Result<(), CacheError>;
    async fn get_flag(&self, key: String) -> Result<String, CacheError>;
}

#[cfg_attr(test, automock)]
pub trait TargetsProvider {
    fn targets(&self) -> Result<Vec<Target>, ConfigError>;
}
