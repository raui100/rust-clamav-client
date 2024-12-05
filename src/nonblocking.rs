use async_fs::File;
use async_net::TcpStream;
use futures_lite::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, Stream, StreamExt};
use std::path::Path;

#[cfg(unix)]
use async_net::unix::UnixStream;

use crate::{Socket, Tcp};

use super::{IoResult, DEFAULT_CHUNK_SIZE, END_OF_STREAM, INSTREAM, PING, SHUTDOWN, VERSION};

impl ClamAvAsync for Tcp {
    type Stream = TcpStream;
    fn connect(&self) -> impl std::future::Future<Output = std::io::Result<TcpStream>> + Send {
        TcpStream::connect(&self.0)
    }
}

#[cfg(unix)]
impl ClamAvAsync for Socket {
    type Stream = UnixStream;

    fn connect(&self) -> impl std::future::Future<Output = std::io::Result<Self::Stream>> + Send {
        UnixStream::connect(&self.0)
    }
}

/// Sending commands and scanning data with ClamAV
pub trait ClamAvAsync: Send + Sync {
    /// Bidirectional stream for communicating with ClamAV
    type Stream: AsyncRead + AsyncWrite + Unpin + Send;
    /// Connecting to the ClamAV instance
    fn connect(&self) -> impl std::future::Future<Output = std::io::Result<Self::Stream>> + Send;

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
    fn ping(&self) -> impl std::future::Future<Output = IoResult> + Send {
        async {
            let stream = self.connect().await?;
            send_command(stream, PING).await
        }
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
    fn get_version(&self) -> impl std::future::Future<Output = IoResult> + Send {
        async {
            let stream = self.connect().await?;
            send_command(stream, VERSION).await
        }
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
    fn scan_file<P: AsRef<Path> + Send>(
        &self,
        file_path: P,
        chunk_size: Option<usize>,
    ) -> impl std::future::Future<Output = IoResult> + Send {
        async move {
            let file = File::open(file_path).await?;
            let stream = self.connect().await?;
            scan(file, chunk_size, stream).await
        }
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
    fn scan_buffer(
        &self,
        buffer: &[u8],
        chunk_size: Option<usize>,
    ) -> impl std::future::Future<Output = IoResult> + Send {
        async move {
            let stream = self.connect().await?;
            scan(buffer, chunk_size, stream).await
        }
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
    fn scan_stream<S: Stream<Item = Result<bytes::Bytes, std::io::Error>> + Send>(
        &self,
        input_stream: S,
        chunk_size: Option<usize>,
    ) -> impl std::future::Future<Output = IoResult> + Send {
        async move {
            let output_stream = self.connect().await?;
            scan_stream(input_stream, chunk_size, output_stream).await
        }
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
    fn shutdown(&self) -> impl std::future::Future<Output = IoResult> + Send {
        async {
            let stream = self.connect().await?;
            send_command(stream, SHUTDOWN).await
        }
    }
}

/// Sends a command to ClamAV
pub async fn send_command<RW: AsyncRead + AsyncWrite + Unpin>(
    mut stream: RW,
    command: &[u8],
) -> IoResult {
    stream.write_all(command).await?;
    // stream.flush().await?;

    let mut response = Vec::new();
    stream.read_to_end(&mut response).await?;
    Ok(response)
}

/// Scan async readable data with ClamAV
pub async fn scan<R: AsyncRead + Unpin, RW: AsyncRead + AsyncWrite + Unpin>(
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
            stream.flush().await?;
            break;
        }
    }

    let mut response = Vec::new();
    stream.read_to_end(&mut response).await?;
    Ok(response)
}

/// Scans a stream of data with ClamAV
pub async fn scan_stream<S, RW>(
    input_stream: S,
    chunk_size: Option<usize>,
    mut output_stream: RW,
) -> IoResult
where
    S: Stream<Item = Result<bytes::Bytes, std::io::Error>>,
    RW: AsyncRead + AsyncWrite + Unpin,
{
    output_stream.write_all(INSTREAM).await?;

    let chunk_size = chunk_size
        .unwrap_or(DEFAULT_CHUNK_SIZE)
        .min(u32::MAX as usize);

    let mut input_stream = std::pin::pin!(input_stream);

    while let Some(bytes) = input_stream.next().await {
        let bytes = bytes?;
        let bytes = bytes.as_ref();
        for chunk in bytes.chunks(chunk_size) {
            let len = chunk.len();
            output_stream.write_all(&(len as u32).to_be_bytes()).await?;
            output_stream.write_all(chunk).await?;
        }
    }

    output_stream.write_all(END_OF_STREAM).await?;
    output_stream.flush().await?;

    let mut response = Vec::new();
    output_stream.read_to_end(&mut response).await?;
    Ok(response)
}
