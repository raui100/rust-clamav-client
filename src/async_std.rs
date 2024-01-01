use async_std::{
    fs::File,
    io::{ReadExt, WriteExt},
    net::{TcpStream, ToSocketAddrs},
    path::Path,
};

use super::{IoResult, DEFAULT_CHUNK_SIZE, END_OF_STREAM, INSTREAM, PING, PONG};

async fn ping<RW: ReadExt + WriteExt + Unpin>(mut stream: RW) -> IoResult {
    stream.write_all(PING).await?;

    let capacity = PONG.len();
    let mut response = Vec::with_capacity(capacity);
    stream.read_to_end(&mut response).await?;
    Ok(response)
}

async fn scan<R: ReadExt + Unpin, RW: ReadExt + WriteExt + Unpin>(
    mut input: R,
    chunk_size: Option<usize>,
    mut stream: RW,
) -> IoResult {
    stream.write_all(INSTREAM).await?;

    let chunk_size = chunk_size
        .unwrap_or(DEFAULT_CHUNK_SIZE)
        .min(u32::MAX as usize);

    let mut buffer = vec![0; chunk_size];

    loop {
        let len = input.read(&mut buffer[..]).await?;
        if len != 0 {
            stream.write_all(&(len as u32).to_be_bytes()).await?;
            stream.write_all(&buffer[..len]).await?;
        } else {
            stream.write_all(END_OF_STREAM).await?;
            break;
        }
    }

    let mut response = Vec::new();
    stream.read_to_end(&mut response).await?;
    Ok(response)
}

/// Sends a ping request to ClamAV using a Unix socket connection
///
/// This function establishes a Unix socket connection to a ClamAV server at the
/// specified `socket_path` and sends a ping request to it.
///
/// # Example
///
/// ```
/// # #[async_std::main]
/// # async fn main() {
/// let clamd_available = match clamav_client::async_std::ping_socket("/tmp/clamd.socket").await {
///     Ok(ping_response) => ping_response == b"PONG\0",
///     Err(_) => false,
/// };
/// # assert!(clamd_available);
/// # }
/// ```
///
#[cfg(unix)]
pub async fn ping_socket<P: AsRef<Path>>(socket_path: P) -> IoResult {
    use async_std::os::unix::net::UnixStream;

    let stream = UnixStream::connect(socket_path).await?;
    ping(stream).await
}

/// Scans a file for viruses using a Unix socket connection
///
/// This function reads data from a file located at the specified `path` and
/// streams it to a ClamAV server through a Unix socket connection for scanning.
///
/// # Arguments
///
/// * `path`: Path to the file to be scanned
/// * `socket_path`: Path to the Unix socket for the ClamAV server
/// * `chunk_size`: An optional chunk size for reading data. If `None`, a default chunk size is used
///
/// # Returns
///
/// An `IoResult` containing the server's response as a vector of bytes
///
#[cfg(unix)]
pub async fn scan_file_socket<P: AsRef<Path>>(
    path: P,
    socket_path: P,
    chunk_size: Option<usize>,
) -> IoResult {
    use async_std::os::unix::net::UnixStream;

    let file = File::open(path).await?;
    let stream = UnixStream::connect(socket_path).await?;
    scan(file, chunk_size, stream).await
}

/// Scans a data buffer for viruses using a Unix socket connection
///
/// This function streams the provided `buffer` data to a ClamAV server through
/// a Unix socket connection for scanning.
///
/// # Arguments
///
/// * `buffer`: The data to be scanned
/// * `socket_path`: The path to the Unix socket for the ClamAV server
/// * `chunk_size`: An optional chunk size for reading data. If `None`, a default chunk size is used
///
/// # Returns
///
/// An `IoResult` containing the server's response as a vector of bytes
///
#[cfg(unix)]
pub async fn scan_buffer_socket<P: AsRef<Path>>(
    buffer: &[u8],
    socket_path: P,
    chunk_size: Option<usize>,
) -> IoResult {
    use async_std::os::unix::net::UnixStream;

    let stream = UnixStream::connect(socket_path).await?;
    scan(buffer, chunk_size, stream).await
}

/// Sends a ping request to ClamAV using a TCP connection
///
/// This function establishes a TCP connection to a ClamAV server at the
/// specified `host_address` and sends a ping request to it.
///
/// # Example
///
/// ```
/// # #[async_std::main]
/// # async fn main() {
/// let clamd_available = match clamav_client::async_std::ping_tcp("localhost:3310").await {
///     Ok(ping_response) => ping_response == b"PONG\0",
///     Err(_) => false,
/// };
/// # assert!(clamd_available);
/// # }
/// ```
///
pub async fn ping_tcp<A: ToSocketAddrs>(host_address: A) -> IoResult {
    let stream = TcpStream::connect(host_address).await?;
    ping(stream).await
}

/// Scans a file for viruses using a TCP connection
///
/// This function reads data from a file located at the specified `path` and
/// streams it to a ClamAV server through a TCP connection for scanning.
///
/// # Arguments
///
/// * `path`: The path to the file to be scanned
/// * `host_address`: The address (host and port) of the ClamAV server
/// * `chunk_size`: An optional chunk size for reading data. If `None`, a default chunk size is used
///
/// # Returns
///
/// An `IoResult` containing the server's response as a vector of bytes
///
pub async fn scan_file_tcp<P: AsRef<Path>, A: ToSocketAddrs>(
    path: P,
    host_address: A,
    chunk_size: Option<usize>,
) -> IoResult {
    let file = File::open(path).await?;
    let stream = TcpStream::connect(host_address).await?;
    scan(file, chunk_size, stream).await
}

/// Scans a data buffer for viruses using a TCP connection
///
/// This function streams the provided `buffer` data to a ClamAV server through
/// a TCP connection for scanning.
///
/// # Arguments
///
/// * `buffer`: The data to be scanned
/// * `host_address`: The address (host and port) of the ClamAV server
/// * `chunk_size`: An optional chunk size for reading data. If `None`, a default chunk size is used
///
/// # Returns
///
/// An `IoResult` containing the server's response as a vector of bytes
///
pub async fn scan_buffer_tcp<A: ToSocketAddrs>(
    buffer: &[u8],
    host_address: A,
    chunk_size: Option<usize>,
) -> IoResult {
    let stream = TcpStream::connect(host_address).await?;
    scan(buffer, chunk_size, stream).await
}
