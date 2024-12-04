use async_fs::File;
use futures_lite::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, Stream, StreamExt};
use std::path::Path;

#[cfg(unix)]
use async_net::unix::UnixStream;

use super::{IoResult, DEFAULT_CHUNK_SIZE, END_OF_STREAM, INSTREAM, PING, PONG, SHUTDOWN, VERSION};

/// Connection to ClamAV
pub struct Connection<S: AsyncRead + AsyncWrite + Unpin>(pub S);

#[cfg(unix)]
impl Connection<UnixStream> {
    /// Tries connecting to ClamAV via Unix socket
    pub async fn try_connect_socket<P: AsRef<Path>>(path: P) -> Result<Self, std::io::Error> {
        let stream = UnixStream::connect(path).await?;
        Ok(Self(stream))
    }
}

impl Connection<UnixStream> {
    /// Tries connecting to ClamAV via TCP
    pub async fn try_connect_tcp<P: AsRef<Path>>(path: P) -> Result<Self, std::io::Error> {
        let stream = UnixStream::connect(path).await?;
        Ok(Self(stream))
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> Connection<S> {
    /// Sends a ping command to ClamAV
    pub async fn ping(&mut self) -> IoResult {
        send_command(&mut self.0, PING, Some(PONG.len())).await
    }

    /// Gets the version number from ClamAV
    pub async fn get_version(&mut self) -> IoResult {
        send_command(&mut self.0, VERSION, None).await
    }

    /// Shuts down a ClamAV server
    pub async fn shutdown(&mut self) -> IoResult {
        send_command(&mut self.0, SHUTDOWN, None).await
    }

    /// Scanning data with ClamAV
    pub async fn scan<T: AsyncRead + Unpin>(
        &mut self,
        input: T,
        chunk_size: Option<usize>,
    ) -> IoResult {
        scan(input, chunk_size, &mut self.0).await
    }

    /// Scanning a file with ClamAV
    pub async fn scan_file<P: AsRef<Path>>(
        &mut self,
        file_path: P,
        chunk_size: Option<usize>,
    ) -> IoResult {
        let file = File::open(file_path).await?;
        self.scan(file, chunk_size).await
    }

    /// Scanning a stream with ClamAV
    pub async fn scan_stream<T>(&mut self, stream: T, chunk_size: Option<usize>) -> IoResult
    where
        T: Stream<Item = Result<bytes::Bytes, std::io::Error>>,
    {
        scan_stream(stream, chunk_size, &mut self.0).await
    }
}

/// Sends a command to ClamAV
pub async fn send_command<RW: AsyncRead + AsyncWrite + Unpin>(
    mut stream: RW,
    command: &[u8],
    expected_response_length: Option<usize>,
) -> IoResult {
    stream.write_all(command).await?;
    stream.flush().await?;

    let mut response = match expected_response_length {
        Some(len) => Vec::with_capacity(len),
        None => Vec::new(),
    };

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
