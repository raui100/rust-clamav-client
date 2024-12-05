// #![doc = include_str!("../README.md")]
// #![deny(missing_docs)]

use std::{net::SocketAddr, path::PathBuf};

/// Async ClamAV client that is abstract over all runtimes
#[cfg(feature = "async")]
mod nonblocking;
#[cfg(feature = "async")]
pub use nonblocking::ClamAvAsync;

/// Synchronous ClamAV client
pub mod blocking;
pub use blocking::ClamAvSync;

/// Custom result type
pub type IoResult = Result<Vec<u8>, std::io::Error>;

/// Custom result type
pub type Utf8Result = Result<bool, std::str::Utf8Error>;

/// Default chunk size in bytes for reading data during scanning
const DEFAULT_CHUNK_SIZE: usize = 4096;

/// ClamAV commands
const PING: &[u8; 6] = b"zPING\0";
const VERSION: &[u8; 9] = b"zVERSION\0";
const SHUTDOWN: &[u8; 10] = b"zSHUTDOWN\0";
const INSTREAM: &[u8; 10] = b"zINSTREAM\0";
const END_OF_STREAM: &[u8; 4] = &[0, 0, 0, 0];

/// ClamAV's response to a PING request
pub const PONG: &[u8; 5] = b"PONG\0";

/// Use a TCP connection to communicate with a ClamAV server
#[derive(Debug, Clone)]
pub struct Tcp(pub SocketAddr);

/// Use a Unix socket connection to communicate with a ClamAV server
#[cfg(unix)]
#[derive(Debug, Clone)]
pub struct Socket(pub PathBuf);

/// Checks whether the ClamAV response indicates that the scanned content is
/// clean or contains a virus
/// # Returns
///
/// An [`Utf8Result`] containing the scan result as [`bool`]
pub fn clean(response: &[u8]) -> Utf8Result {
    let response = std::str::from_utf8(response)?;
    Ok(response.contains("OK") && !response.contains("FOUND"))
}
