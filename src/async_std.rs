use async_std::{
    io::{self, ReadExt, WriteExt},
    net::{TcpStream, ToSocketAddrs},
    path::Path,
    stream::Stream,
};
use async_trait::async_trait;

#[cfg(unix)]
use async_std::os::unix::net::UnixStream;

use crate::nonblocking::Connection;

use super::IoResult;

/// Use a TCP connection to communicate with a ClamAV server
#[derive(Copy, Clone)]
pub struct Tcp<A: ToSocketAddrs> {
    /// The address (host and port) of the ClamAV server
    pub host_address: A,
}

/// Use a Unix socket connection to communicate with a ClamAV server
#[derive(Copy, Clone)]
#[cfg(unix)]
pub struct Socket<P: AsRef<Path>> {
    /// The socket file path of the ClamAV server
    pub socket_path: P,
}

/// The communication protocol to use
#[async_trait(?Send)]
pub trait TransportProtocol {
    /// Bidirectional stream
    type Stream: ReadExt + WriteExt + Unpin;

    /// Converts the protocol instance into the corresponding stream
    async fn connect(&self) -> io::Result<Self::Stream>;
}

#[async_trait(?Send)]
impl<A: ToSocketAddrs> TransportProtocol for Tcp<A> {
    type Stream = TcpStream;

    async fn connect(&self) -> io::Result<Self::Stream> {
        TcpStream::connect(&self.host_address).await
    }
}

#[async_trait(?Send)]
#[cfg(unix)]
impl<P: AsRef<Path>> TransportProtocol for Socket<P> {
    type Stream = UnixStream;

    async fn connect(&self) -> io::Result<Self::Stream> {
        UnixStream::connect(&self.socket_path).await
    }
}

/// Sends a ping request to ClamAV
///
/// This function establishes a connection to a ClamAV server and sends the PING
/// command to it. If the server is available, it responds with [`PONG`].
///
/// # Arguments
///
/// * `connection`: The connection type to use - either TCP or a Unix socket connection
///
/// # Returns
///
/// An [`IoResult`] containing the server's response as a vector of bytes
///
/// # Example
///
/// ```
/// # #[async_std::main]
/// # async fn main() {
/// let clamd_tcp = clamav_client::async_std::Tcp{ host_address: "localhost:3310" };
/// let clamd_available = match clamav_client::async_std::ping(clamd_tcp).await {
///     Ok(ping_response) => ping_response == clamav_client::PONG,
///     Err(_) => false,
/// };
/// # assert!(clamd_available);
/// # }
/// ```
///
pub async fn ping<T: TransportProtocol>(connection: T) -> IoResult {
    let stream = connection.connect().await?;
    Connection(stream).ping().await
}

/// Gets the version number from ClamAV
///
/// This function establishes a connection to a ClamAV server and sends the
/// VERSION command to it. If the server is available, it responds with its
/// version number.
///
/// # Arguments
///
/// * `connection`: The connection type to use - either TCP or a Unix socket connection
///
/// # Returns
///
/// An [`IoResult`] containing the server's response as a vector of bytes
///
/// # Example
///
/// ```
/// # #[async_std::main]
/// # async fn main() {
/// let clamd_tcp = clamav_client::async_std::Tcp{ host_address: "localhost:3310" };
/// let version = clamav_client::async_std::get_version(clamd_tcp).await.unwrap();
/// # assert!(version.starts_with(b"ClamAV"));
/// # }
/// ```
///
pub async fn get_version<T: TransportProtocol>(connection: T) -> IoResult {
    let stream = connection.connect().await?;
    Connection(stream).get_version().await
}

/// Scans a file for viruses
///
/// This function reads data from a file located at the specified `file_path`
/// and streams it to a ClamAV server for scanning.
///
/// # Arguments
///
/// * `file_path`: The path to the file to be scanned
/// * `connection`: The connection type to use - either TCP or a Unix socket connection
/// * `chunk_size`: An optional chunk size for reading data. If [`None`], a default chunk size is used
///
/// # Returns
///
/// An [`IoResult`] containing the server's response as a vector of bytes
///
pub async fn scan_file<P: AsRef<Path>, T: TransportProtocol>(
    file_path: P,
    connection: T,
    chunk_size: Option<usize>,
) -> IoResult {
    let stream = connection.connect().await?;
    let path: &std::path::Path = file_path.as_ref().into();
    Connection(stream).scan_file(path, chunk_size).await
}

/// Scans a data buffer for viruses
///
/// This function streams the provided `buffer` data to a ClamAV server
///
/// # Arguments
///
/// * `buffer`: The data to be scanned
/// * `connection`: The connection type to use - either TCP or a Unix socket connection
/// * `chunk_size`: An optional chunk size for reading data. If [`None`], a default chunk size is used
///
/// # Returns
///
/// An [`IoResult`] containing the server's response as a vector of bytes
///
pub async fn scan_buffer<T: TransportProtocol>(
    buffer: &[u8],
    connection: T,
    chunk_size: Option<usize>,
) -> IoResult {
    let stream = connection.connect().await?;
    Connection(stream).scan(buffer, chunk_size).await
}

/// Scans a stream for viruses
///
/// This function sends the provided stream to a ClamAV server for scanning.
///
/// # Arguments
///
/// * `input_stream`: The stream to be scanned
/// * `connection`: The connection type to use - either TCP or a Unix socket connection
/// * `chunk_size`: An optional chunk size for reading data. If [`None`], a default chunk size is used
///
/// # Returns
///
/// An [`IoResult`] containing the server's response as a vector of bytes
///
pub async fn scan_stream<
    S: Stream<Item = Result<bytes::Bytes, io::Error>>,
    T: TransportProtocol,
>(
    input_stream: S,
    connection: T,
    chunk_size: Option<usize>,
) -> IoResult {
    let output_stream = connection.connect().await?;
    crate::nonblocking::scan_stream(input_stream, chunk_size, output_stream).await
}

/// Shuts down a ClamAV server
///
/// This function establishes a connection to a ClamAV server and sends the
/// SHUTDOWN command to it. If the server is available, it will perform a clean
/// exit and shut itself down. The response will be empty.
///
/// # Arguments
///
/// * `connection`: The connection type to use - either TCP or a Unix socket connection
///
/// # Returns
///
/// An [`IoResult`] containing the server's response
///
pub async fn shutdown<T: TransportProtocol>(connection: T) -> IoResult {
    let stream = connection.connect().await?;
    Connection(stream).shutdown().await
}
