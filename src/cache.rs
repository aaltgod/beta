use redis::{Client, RedisError, RedisResult, AsyncCommands};

#[derive(Clone)]
pub struct Cache {
    redis_client: Client
}

impl Cache {
    pub fn new(redis_client: Client) -> Self {
        Cache { redis_client }
    }

    async fn get_conn(&self) -> RedisResult<redis::aio::Connection> {
        self.redis_client
            .get_tokio_connection()
            .await
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
                _ => return Err(e)
            },
        }
    }
}



