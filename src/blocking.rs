use std::{
    fs::File,
    io::{Read, Write},
    net::TcpStream,
    path::Path,
};

#[cfg(unix)]
use std::os::unix::net::UnixStream;

use crate::{
    IoResult, Socket, Tcp, DEFAULT_CHUNK_SIZE, END_OF_STREAM, INSTREAM, PING, SHUTDOWN, VERSION,
};

impl ClamAvSync for Tcp {
    type Stream = TcpStream;

    fn connect(&self) -> std::io::Result<Self::Stream> {
        TcpStream::connect(self.0)
    }
}

#[cfg(unix)]
impl ClamAvSync for Socket {
    type Stream = UnixStream;

    fn connect(&self) -> std::io::Result<Self::Stream> {
        UnixStream::connect(&self.0)
    }
}

/// Sending commands and scanning data with ClamAV
pub trait ClamAvSync {
    /// Bidirectional stream for communicating with ClamAV
    type Stream: Write + Read;
    /// Connecting to the ClamAV instance
    fn connect(&self) -> std::io::Result<Self::Stream>;

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
    fn ping(&self) -> IoResult {
        let stream = self.connect()?;
        send_command(stream, PING)
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
    fn get_version(&self) -> IoResult {
        let stream = self.connect()?;
        send_command(stream, VERSION)
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
    ) -> IoResult {
        let file = File::open(file_path)?;
        let stream = self.connect()?;
        scan(file, chunk_size, stream)
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
    fn scan_buffer(&self, buffer: &[u8], chunk_size: Option<usize>) -> IoResult {
        let stream = self.connect()?;
        scan(buffer, chunk_size, stream)
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
    fn shutdown(&self) -> IoResult {
        let stream = self.connect()?;
        send_command(stream, SHUTDOWN)
    }
}

fn send_command<RW: Read + Write>(mut stream: RW, command: &[u8]) -> IoResult {
    stream.write_all(command)?;
    stream.flush()?;

    let mut response = Vec::new();
    stream.read_to_end(&mut response)?;
    Ok(response)
}

fn scan<R: Read, RW: Read + Write>(
    mut input: R,
    chunk_size: Option<usize>,
    mut stream: RW,
) -> IoResult {
    stream.write_all(INSTREAM)?;

    let chunk_size = chunk_size
        .unwrap_or(DEFAULT_CHUNK_SIZE)
        .min(u32::MAX as usize);
    let mut buffer = vec![0; chunk_size];
    loop {
        let len = input.read(&mut buffer[..])?;
        if len != 0 {
            stream.write_all(&(len as u32).to_be_bytes())?;
            stream.write_all(&buffer[..len])?;
        } else {
            stream.write_all(END_OF_STREAM)?;
            stream.flush()?;
            break;
        }
    }

    let mut response = Vec::new();
    stream.read_to_end(&mut response)?;
    Ok(response)
}
