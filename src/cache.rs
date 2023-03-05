use mobc_redis::mobc::Pool;
use mobc_redis::RedisConnectionManager;
use redis::{AsyncCommands, RedisError};

#[derive(Clone)]
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

    // FIXME: please
    pub async fn set_flag(&self, key: String, value: String) -> Result<(), RedisError> {
        let mut conn = self.get_conn().await.expect("redis set_flag conn error");
        conn.set_nx(key, value).await?;

        Ok(())
    }

    pub async fn get_flag(&self, key: String) -> Result<String, RedisError> {
        let mut conn = self.get_conn().await.expect("redis get_flag conn error");

        match conn.get(key).await {
            Ok(flag) => return Ok(flag),
            Err(e) => match e.kind() {
                redis::ErrorKind::TypeError => return Ok("".to_string()),
                _ => return Err(e),
            },
        }
    }
}
