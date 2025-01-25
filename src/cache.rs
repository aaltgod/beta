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
    async fn set_flag(&self, key: &str, value: &str, ttl: usize) -> Result<(), CacheError> {
        let mut conn = self.get_conn().await.map_err(|e| CacheError::Cache {
            method_name: "get_conn".to_string(),
            error: e.into(),
        })?;

        conn.set_ex::<_, _, ()>(key, value, ttl)
            .await
            .map_err(|e| CacheError::Cache {
                method_name: "set_ex".to_string(),
                error: e.into(),
            })?;

        Ok(())
    }

    async fn get_flag(&self, key: &str) -> Result<String, CacheError> {
        let mut conn = self.get_conn().await.map_err(|e| CacheError::Cache {
            method_name: "get_conn".to_string(),
            error: e.into(),
        })?;

        let flag: Option<String> = conn.get(key).await.map_err(|e| CacheError::Cache {
            method_name: "conn.get".to_string(),
            error: e.into(),
        })?;

        Ok(flag.map_or(String::from(""), |flag| flag))
    }
}
