use redis::{Client, FromRedisValue, RedisError, AsyncCommands, RedisResult, Value};

pub async fn create_client(redis_uri: String) -> Result<Client, RedisError> {
    Ok(Client::open(redis_uri)?)
}

pub async fn set_flag(redis_client: &Client, key: String, value: String) -> Result<(), RedisError> {
    let mut conn = redis_client.get_tokio_connection().await.expect("set_flag conn");
    conn.set_nx(key, value).await?;

    Ok(())
}

pub async fn get_flag(redis_client: &Client, key: String) -> Result<String, RedisError> {
    let mut conn = redis_client.get_tokio_connection().await.expect("get_flag conn");
    match conn.get(key).await {
        Ok(flag) => return Ok(flag),
        Err(e) => match e.kind() {
            redis::ErrorKind::TypeError => return Ok("".to_string()),
            _ => return Err(e)
        },
    }
}