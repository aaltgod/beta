use std::error::Error;
use std::io::Write;
use tokio::net::TcpListener;


#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let listener = TcpListener::bind("127.0.0.1:1337").await?;
    let (socket, _) = listener.accept().await?;
    
    println!("listener were accepeted");

    let mut stream = socket.into_std()?;
    stream.set_nonblocking(false)?;
    stream.write_all(b"FLAG")?;
    
    Ok(())
}
