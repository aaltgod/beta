use async_trait::async_trait;
use mobc_redis::mobc::Pool;
use mobc_redis::RedisConnectionManager;
use redis::{AsyncCommands, RedisError};

use crate::{errors::CacheError, traits::Storage};

pub struct Cache {
    pool: Pool<RedisConnectionManager>,
}

impl Cache {
    pub fn new(pool: Pool<RedisConnectionManager>) -> Self {
        Cache { pool }
    }

    async fn get_conn(
        &self,
    ) -> Result<
        mobc_redis::mobc::Connection<RedisConnectionManager>,
        mobc_redis::mobc::Error<RedisError>,
    > {
        self.pool.get().await
    }
}

#[async_trait]
impl Storage for Cache {
    async fn set_flag(&self, key: &str, value: &str) -> Result<(), CacheError> {
        let mut conn = self.get_conn().await.map_err(|e| CacheError::Cache {
            method_name: "get_conn".to_string(),
            error: e.into(),
        })?;

        conn.set_nx(key, value)
            .await
            .map_err(|e| CacheError::Cache {
                method_name: "set_nx".to_string(),
                error: e.into(),
            })?;

        Ok(())
    }

    async fn get_flag(&self, key: &str) -> Result<String, CacheError> {
        let mut conn = self.get_conn().await.map_err(|e| CacheError::Cache {
            method_name: "get_conn".to_string(),
            error: e.into(),
        })?;

        let flag = match conn.get(key).await {
            Ok(flag) => flag,
            Err(e) => match e.kind() {
                redis::ErrorKind::TypeError => "".to_string(),
                _ => {
                    return Err(CacheError::Cache {
                        method_name: "conn.get".to_string(),
                        error: e.into(),
                    })
                }
            },
        };

        Ok(flag)
    }
}
