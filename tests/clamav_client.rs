use std::sync::LazyLock;

use clamav_client::{Socket, Tcp};
#[cfg(unix)]
const TEST_SOCKET_PATH: &str = "/tmp/clamd.socket";
const TEST_HOST_ADDRESS: &str = "127.0.0.1:3310";
const EICAR_TEST_FILE_PATH: &str = "tests/data/eicar.txt";
const CLEAN_TEST_FILE_PATH: &str = "README.md";

const EICAR_FILE_SIGNATURE_FOUND_RESPONSE: &[u8] = b"stream: Eicar-Signature FOUND\0";
const OK_RESPONSE: &[u8] = b"stream: OK\0";

// `StreamMaxLength` is limited to 1 MB (1_000_000 bytes) in `clamd.conf` - this
// binary test file is 1 byte larger than allowed (1_000_001 bytes in total) to
// test ClamAV's "size limit exceeded" error. The file was created using the
// truncate utility: `truncate -s 1000001 filename`
const OVERSIZED_TEST_FILE_PATH: &str = "tests/data/stream-max-length-test-file.bin";
const SIZE_LIMIT_EXCEEDED_ERROR_RESPONSE: &[u8] = b"INSTREAM size limit exceeded. ERROR\0";

static TCP: LazyLock<clamav_client::Tcp> =
    LazyLock::new(|| Tcp(dbg!(TEST_HOST_ADDRESS.parse()).unwrap()));

#[cfg(unix)]
static SOCKET: LazyLock<clamav_client::Socket> = LazyLock::new(|| Socket(TEST_SOCKET_PATH.into()));

#[cfg(unix)]
mod test_socket_sync {
    use super::*;
    use clamav_client::ClamAvSync;

    #[test]
    fn ping_socket() {
        let err_msg = format!("Could not ping clamd via Unix socket at {:?}", SOCKET.0);

        let response = SOCKET.ping().expect(&err_msg);
        assert_eq!(&response, clamav_client::PONG);
    }

    #[test]
    fn get_version_socket() {
        let err_msg = format!(
            "Could not get ClamAV version via Unix socket at {:?}",
            SOCKET.0
        );
        let response = SOCKET.get_version().expect(&err_msg);
        assert!(&response.starts_with(b"ClamAV"));
    }

    #[test]
    fn scan_socket_infected_file() {
        let err_msg = format!(
            "Could not scan test file {} via socket at {:?}",
            EICAR_TEST_FILE_PATH, SOCKET.0
        );
        let response = SOCKET
            .scan_file(EICAR_TEST_FILE_PATH, None)
            .expect(&err_msg);
        assert_eq!(&response, EICAR_FILE_SIGNATURE_FOUND_RESPONSE);
        assert_eq!(clamav_client::clean(&response), Ok(false));
    }

    #[test]
    fn scan_socket_infected_buffer() {
        let err_msg = format!(
            "Could not scan EICAR test string via socket at {:?}",
            SOCKET.0
        );
        let buffer = include_bytes!("data/eicar.txt");
        let response = SOCKET.scan_buffer(buffer, None).expect(&err_msg);
        assert_eq!(&response, EICAR_FILE_SIGNATURE_FOUND_RESPONSE);
        assert_eq!(clamav_client::clean(&response), Ok(false));
    }

    #[test]
    fn scan_socket_clean_file() {
        let err_msg = format!(
            "Could not scan test file {} via socket at {:?}",
            CLEAN_TEST_FILE_PATH, SOCKET.0
        );
        let response = SOCKET
            .scan_file(CLEAN_TEST_FILE_PATH, None)
            .expect(&err_msg);
        assert_eq!(&response, OK_RESPONSE);
        assert_eq!(clamav_client::clean(&response), Ok(true));
    }

    #[test]
    fn scan_socket_oversized_file() {
        let err_msg = format!(
            "Could not scan test file {} via socket at {:?}",
            OVERSIZED_TEST_FILE_PATH, SOCKET.0
        );
        let response = SOCKET
            .scan_file(OVERSIZED_TEST_FILE_PATH, None)
            .expect(&err_msg);

        assert_eq!(&response, SIZE_LIMIT_EXCEEDED_ERROR_RESPONSE);
        assert_eq!(clamav_client::clean(&response), Ok(false));
    }
}

mod test_tcp_sync {
    use super::*;
    use clamav_client::ClamAvSync;

    #[test]
    fn ping_tcp() {
        let err_msg = format!("Could not ping clamd via TCP at {}", TCP.0);
        let response = TCP.ping().expect(&err_msg);
        assert_eq!(&response, clamav_client::PONG);
    }

    #[test]
    fn get_version_tcp() {
        let err_msg = format!("Could not get ClamAV version via TCP at {}", TCP.0);
        let response = TCP.get_version().expect(&err_msg);
        assert!(&response.starts_with(b"ClamAV"));
    }

    #[test]
    fn scan_tcp_infected_file() {
        let err_msg = format!(
            "Could not scan test file {} via TCP at {}",
            EICAR_TEST_FILE_PATH, TCP.0
        );
        let response = TCP.scan_file(EICAR_TEST_FILE_PATH, None).expect(&err_msg);
        assert_eq!(&response, EICAR_FILE_SIGNATURE_FOUND_RESPONSE);
        assert_eq!(clamav_client::clean(&response), Ok(false));
    }

    #[test]
    fn scan_tcp_clean_file() {
        let err_msg = format!(
            "Could not scan test file {} via TCP at {}",
            CLEAN_TEST_FILE_PATH, TCP.0
        );
        let response = TCP.scan_file(CLEAN_TEST_FILE_PATH, None).expect(&err_msg);
        assert_eq!(&response, OK_RESPONSE);
        assert_eq!(clamav_client::clean(&response), Ok(true));
    }

    #[test]
    fn scan_tcp_infected_buffer() {
        let err_msg = format!("Could not scan EICAR test string via TCP at {}", TCP.0);
        let buffer = include_bytes!("data/eicar.txt");
        let response = TCP.scan_buffer(buffer, None).expect(&err_msg);
        assert_eq!(&response, EICAR_FILE_SIGNATURE_FOUND_RESPONSE);
        assert_eq!(clamav_client::clean(&response), Ok(false));
    }

    #[test]
    fn scan_tcp_oversized_file() {
        let err_msg = format!(
            "Could not scan test file {} via TCP at {}",
            OVERSIZED_TEST_FILE_PATH, TCP.0
        );
        let response = TCP
            .scan_file(OVERSIZED_TEST_FILE_PATH, None)
            .expect(&err_msg);
        assert_eq!(&response, SIZE_LIMIT_EXCEEDED_ERROR_RESPONSE);
        assert_eq!(clamav_client::clean(&response), Ok(false));
    }
}

#[cfg(unix)]
#[cfg(feature = "async")]
mod test_socket_async_tokio {
    use super::*;
    use clamav_client::ClamAvSync;

    #[tokio::test]
    async fn ping_socket() {
        let err_msg = format!("Could not ping clamd via Unix socket at {:?}", SOCKET.0);

        let response = SOCKET.ping().expect(&err_msg);
        assert_eq!(&response, clamav_client::PONG);
    }

    #[tokio::test]
    async fn get_version_socket() {
        let err_msg = format!(
            "Could not get ClamAV version via Unix socket at {:?}",
            SOCKET.0
        );
        let response = SOCKET.get_version().expect(&err_msg);
        assert!(&response.starts_with(b"ClamAV"));
    }

    #[tokio::test]
    async fn scan_socket_infected_file() {
        let err_msg = format!(
            "Could not scan test file {} via socket at {:?}",
            EICAR_TEST_FILE_PATH, SOCKET.0
        );
        let response = SOCKET
            .scan_file(EICAR_TEST_FILE_PATH, None)
            .expect(&err_msg);
        assert_eq!(&response, EICAR_FILE_SIGNATURE_FOUND_RESPONSE);
        assert_eq!(clamav_client::clean(&response), Ok(false));
    }

    #[tokio::test]
    async fn scan_socket_infected_buffer() {
        let err_msg = format!(
            "Could not scan EICAR test string via socket at {:?}",
            SOCKET.0
        );
        let buffer = include_bytes!("data/eicar.txt");
        let response = SOCKET.scan_buffer(buffer, None).expect(&err_msg);
        assert_eq!(&response, EICAR_FILE_SIGNATURE_FOUND_RESPONSE);
        assert_eq!(clamav_client::clean(&response), Ok(false));
    }

    #[tokio::test]
    async fn scan_socket_clean_file() {
        let err_msg = format!(
            "Could not scan test file {} via socket at {:?}",
            CLEAN_TEST_FILE_PATH, SOCKET.0
        );
        let response = SOCKET
            .scan_file(CLEAN_TEST_FILE_PATH, None)
            .expect(&err_msg);
        assert_eq!(&response, OK_RESPONSE);
        assert_eq!(clamav_client::clean(&response), Ok(true));
    }

    #[tokio::test]
    async fn scan_socket_oversized_file() {
        let err_msg = format!(
            "Could not scan test file {} via socket at {:?}",
            OVERSIZED_TEST_FILE_PATH, SOCKET.0
        );
        let response = SOCKET
            .scan_file(OVERSIZED_TEST_FILE_PATH, None)
            .expect(&err_msg);

        assert_eq!(&response, SIZE_LIMIT_EXCEEDED_ERROR_RESPONSE);
        assert_eq!(clamav_client::clean(&response), Ok(false));
    }
}

#[cfg(feature = "async")]
mod test_tcp_async_tokio {
    use super::*;
    use clamav_client::ClamAvSync;

    #[tokio::test]
    async fn ping_tcp() {
        let err_msg = format!("Could not ping clamd via TCP at {}", TCP.0);
        let response = TCP.ping().expect(&err_msg);
        assert_eq!(&response, clamav_client::PONG);
    }

    #[tokio::test]
    async fn get_version_tcp() {
        let err_msg = format!("Could not get ClamAV version via TCP at {}", TCP.0);
        let response = TCP.get_version().expect(&err_msg);
        assert!(&response.starts_with(b"ClamAV"));
    }

    #[tokio::test]
    async fn scan_tcp_infected_file() {
        let err_msg = format!(
            "Could not scan test file {} via TCP at {}",
            EICAR_TEST_FILE_PATH, TCP.0
        );
        let response = TCP.scan_file(EICAR_TEST_FILE_PATH, None).expect(&err_msg);
        assert_eq!(&response, EICAR_FILE_SIGNATURE_FOUND_RESPONSE);
        assert_eq!(clamav_client::clean(&response), Ok(false));
    }

    #[tokio::test]
    async fn scan_tcp_clean_file() {
        let err_msg = format!(
            "Could not scan test file {} via TCP at {}",
            CLEAN_TEST_FILE_PATH, TCP.0
        );
        let response = TCP.scan_file(CLEAN_TEST_FILE_PATH, None).expect(&err_msg);
        assert_eq!(&response, OK_RESPONSE);
        assert_eq!(clamav_client::clean(&response), Ok(true));
    }

    #[tokio::test]
    async fn scan_tcp_infected_buffer() {
        let err_msg = format!("Could not scan EICAR test string via TCP at {}", TCP.0);
        let buffer = include_bytes!("data/eicar.txt");
        let response = TCP.scan_buffer(buffer, None).expect(&err_msg);
        assert_eq!(&response, EICAR_FILE_SIGNATURE_FOUND_RESPONSE);
        assert_eq!(clamav_client::clean(&response), Ok(false));
    }

    #[tokio::test]
    async fn scan_tcp_oversized_file() {
        let err_msg = format!(
            "Could not scan test file {} via TCP at {}",
            OVERSIZED_TEST_FILE_PATH, TCP.0
        );
        let response = TCP
            .scan_file(OVERSIZED_TEST_FILE_PATH, None)
            .expect(&err_msg);
        assert_eq!(&response, SIZE_LIMIT_EXCEEDED_ERROR_RESPONSE);
        assert_eq!(clamav_client::clean(&response), Ok(false));
    }
}

#[cfg(unix)]
#[cfg(feature = "async")]
mod test_socket_async_async_std {
    use super::*;
    use clamav_client::ClamAvSync;

    #[async_std::test]
    async fn ping_socket() {
        let err_msg = format!("Could not ping clamd via Unix socket at {:?}", SOCKET.0);

        let response = SOCKET.ping().expect(&err_msg);
        assert_eq!(&response, clamav_client::PONG);
    }

    #[async_std::test]
    async fn get_version_socket() {
        let err_msg = format!(
            "Could not get ClamAV version via Unix socket at {:?}",
            SOCKET.0
        );
        let response = SOCKET.get_version().expect(&err_msg);
        assert!(&response.starts_with(b"ClamAV"));
    }

    #[async_std::test]
    async fn scan_socket_infected_file() {
        let err_msg = format!(
            "Could not scan test file {} via socket at {:?}",
            EICAR_TEST_FILE_PATH, SOCKET.0
        );
        let response = SOCKET
            .scan_file(EICAR_TEST_FILE_PATH, None)
            .expect(&err_msg);
        assert_eq!(&response, EICAR_FILE_SIGNATURE_FOUND_RESPONSE);
        assert_eq!(clamav_client::clean(&response), Ok(false));
    }

    #[async_std::test]
    async fn scan_socket_infected_buffer() {
        let err_msg = format!(
            "Could not scan EICAR test string via socket at {:?}",
            SOCKET.0
        );
        let buffer = include_bytes!("data/eicar.txt");
        let response = SOCKET.scan_buffer(buffer, None).expect(&err_msg);
        assert_eq!(&response, EICAR_FILE_SIGNATURE_FOUND_RESPONSE);
        assert_eq!(clamav_client::clean(&response), Ok(false));
    }

    #[async_std::test]
    async fn scan_socket_clean_file() {
        let err_msg = format!(
            "Could not scan test file {} via socket at {:?}",
            CLEAN_TEST_FILE_PATH, SOCKET.0
        );
        let response = SOCKET
            .scan_file(CLEAN_TEST_FILE_PATH, None)
            .expect(&err_msg);
        assert_eq!(&response, OK_RESPONSE);
        assert_eq!(clamav_client::clean(&response), Ok(true));
    }

    #[async_std::test]
    async fn scan_socket_oversized_file() {
        let err_msg = format!(
            "Could not scan test file {} via socket at {:?}",
            OVERSIZED_TEST_FILE_PATH, SOCKET.0
        );
        let response = SOCKET
            .scan_file(OVERSIZED_TEST_FILE_PATH, None)
            .expect(&err_msg);

        assert_eq!(&response, SIZE_LIMIT_EXCEEDED_ERROR_RESPONSE);
        assert_eq!(clamav_client::clean(&response), Ok(false));
    }
}

#[cfg(feature = "async")]
mod test_tcp_async_async_std {
    use super::*;
    use clamav_client::ClamAvSync;

    #[async_std::test]
    async fn ping_tcp() {
        let err_msg = format!("Could not ping clamd via TCP at {}", TCP.0);
        let response = TCP.ping().expect(&err_msg);
        assert_eq!(&response, clamav_client::PONG);
    }

    #[async_std::test]
    async fn get_version_tcp() {
        let err_msg = format!("Could not get ClamAV version via TCP at {}", TCP.0);
        let response = TCP.get_version().expect(&err_msg);
        assert!(&response.starts_with(b"ClamAV"));
    }

    #[async_std::test]
    async fn scan_tcp_infected_file() {
        let err_msg = format!(
            "Could not scan test file {} via TCP at {}",
            EICAR_TEST_FILE_PATH, TCP.0
        );
        let response = TCP.scan_file(EICAR_TEST_FILE_PATH, None).expect(&err_msg);
        assert_eq!(&response, EICAR_FILE_SIGNATURE_FOUND_RESPONSE);
        assert_eq!(clamav_client::clean(&response), Ok(false));
    }

    #[async_std::test]
    async fn scan_tcp_clean_file() {
        let err_msg = format!(
            "Could not scan test file {} via TCP at {}",
            CLEAN_TEST_FILE_PATH, TCP.0
        );
        let response = TCP.scan_file(CLEAN_TEST_FILE_PATH, None).expect(&err_msg);
        assert_eq!(&response, OK_RESPONSE);
        assert_eq!(clamav_client::clean(&response), Ok(true));
    }

    #[async_std::test]
    async fn scan_tcp_infected_buffer() {
        let err_msg = format!("Could not scan EICAR test string via TCP at {}", TCP.0);
        let buffer = include_bytes!("data/eicar.txt");
        let response = TCP.scan_buffer(buffer, None).expect(&err_msg);
        assert_eq!(&response, EICAR_FILE_SIGNATURE_FOUND_RESPONSE);
        assert_eq!(clamav_client::clean(&response), Ok(false));
    }

    #[async_std::test]
    async fn scan_tcp_oversized_file() {
        let err_msg = format!(
            "Could not scan test file {} via TCP at {}",
            OVERSIZED_TEST_FILE_PATH, TCP.0
        );
        let response = TCP
            .scan_file(OVERSIZED_TEST_FILE_PATH, None)
            .expect(&err_msg);
        assert_eq!(&response, SIZE_LIMIT_EXCEEDED_ERROR_RESPONSE);
        assert_eq!(clamav_client::clean(&response), Ok(false));
    }
}

#[cfg(feature = "async")]
mod test_stream_tokio {
    use super::*;
    use clamav_client::ClamAvAsync;
    use std::path::Path;
    use tokio::fs::File;
    use tokio_util::io::ReaderStream;

    async fn stream_from_file<P: AsRef<Path>>(path: P) -> ReaderStream<File> {
        let path_str = path.as_ref().to_str().expect("Invalid path");
        let err_msg = format!("Could not read test file {}", path_str);
        let file = File::open(path).await.expect(&err_msg);
        ReaderStream::with_capacity(file, 16)
    }

    #[tokio::test]
    #[cfg(unix)]
    async fn async_tokio_scan_socket_infected_stream() {
        let stream = stream_from_file(EICAR_TEST_FILE_PATH).await;

        let err_msg = format!(
            "Could not scan test file {} via socket at {:?}",
            EICAR_TEST_FILE_PATH, SOCKET.0
        );
        let response = SOCKET.scan_stream(stream, None).await.expect(&err_msg);
        assert_eq!(&response, EICAR_FILE_SIGNATURE_FOUND_RESPONSE);
        assert_eq!(clamav_client::clean(&response), Ok(false));
    }

    #[tokio::test]
    #[cfg(unix)]
    async fn async_tokio_scan_socket_clean_stream() {
        let stream = stream_from_file(CLEAN_TEST_FILE_PATH).await;

        let err_msg = format!(
            "Could not scan test file {} via socket at {:?}",
            CLEAN_TEST_FILE_PATH, SOCKET.0
        );
        let response = SOCKET.scan_stream(stream, None).await.expect(&err_msg);
        assert_eq!(&response, OK_RESPONSE);
        assert_eq!(clamav_client::clean(&response), Ok(true));
    }

    #[tokio::test]
    #[cfg(unix)]
    async fn async_tokio_scan_socket_oversized_stream() {
        let stream = stream_from_file(OVERSIZED_TEST_FILE_PATH).await;

        let err_msg = format!(
            "Could not scan test file {} via socket at {:?}",
            OVERSIZED_TEST_FILE_PATH, SOCKET.0
        );
        let response = SOCKET.scan_stream(stream, None).await.expect(&err_msg);
        assert_eq!(&response, SIZE_LIMIT_EXCEEDED_ERROR_RESPONSE);
        assert_eq!(clamav_client::clean(&response), Ok(false));
    }

    #[tokio::test]
    async fn async_tokio_scan_tcp_infected_stream() {
        let stream = stream_from_file(EICAR_TEST_FILE_PATH).await;

        let err_msg = format!(
            "Could not scan test file {} via TCP at {}",
            EICAR_TEST_FILE_PATH, TCP.0
        );
        let response = TCP.scan_stream(stream, None).await.expect(&err_msg);
        assert_eq!(&response, EICAR_FILE_SIGNATURE_FOUND_RESPONSE);
        assert_eq!(clamav_client::clean(&response), Ok(false));
    }

    #[tokio::test]
    async fn async_tokio_scan_tcp_clean_stream() {
        let stream = stream_from_file(CLEAN_TEST_FILE_PATH).await;

        let err_msg = format!(
            "Could not scan test file {} via TCP at {}",
            CLEAN_TEST_FILE_PATH, TCP.0
        );
        let response = TCP.scan_stream(stream, None).await.expect(&err_msg);
        assert_eq!(&response, OK_RESPONSE);
        assert_eq!(clamav_client::clean(&response), Ok(true));
    }

    #[tokio::test]
    async fn async_tokio_scan_tcp_oversized_stream() {
        let stream = stream_from_file(OVERSIZED_TEST_FILE_PATH).await;

        let err_msg = format!(
            "Could not scan test file {} via TCP at {}",
            OVERSIZED_TEST_FILE_PATH, TCP.0
        );
        let response = TCP.scan_stream(stream, None).await.expect(&err_msg);
        assert_eq!(&response, SIZE_LIMIT_EXCEEDED_ERROR_RESPONSE);
        assert_eq!(clamav_client::clean(&response), Ok(false));
    }
}

#[cfg(feature = "async")]
mod test_stream_asnc_std {
    use super::*;
    use async_std::fs::File;
    use async_std::io::BufReader;
    use bytes::Bytes;
    use clamav_client::ClamAvAsync;
    use futures_lite::stream::{self, Stream};
    use futures_lite::AsyncReadExt;
    use std::path::Path;

    async fn stream_from_file<P: AsRef<Path>>(
        path: P,
    ) -> impl Stream<Item = std::io::Result<Bytes>> {
        let path = path.as_ref().to_owned();
        let err_msg = format!("Could not read test file {:?}", path);
        let file = File::open(&path).await.expect(&err_msg);
        let reader = BufReader::with_capacity(16, file);

        stream::unfold(reader, |mut reader| async move {
            let mut buffer = vec![0u8; 16];
            match reader.read(&mut buffer).await {
                Ok(0) => None, // EOF
                Ok(n) => {
                    buffer.truncate(n);
                    Some((Ok(Bytes::from(buffer)), reader))
                }
                Err(e) => Some((Err(e), reader)),
            }
        })
    }

    #[async_std::test]
    #[cfg(unix)]
    async fn async_tokio_scan_socket_infected_stream() {
        let stream = stream_from_file(EICAR_TEST_FILE_PATH).await;

        let err_msg = format!(
            "Could not scan test file {} via socket at {:?}",
            EICAR_TEST_FILE_PATH, SOCKET.0
        );
        let response = SOCKET.scan_stream(stream, None).await.expect(&err_msg);
        assert_eq!(&response, EICAR_FILE_SIGNATURE_FOUND_RESPONSE);
        assert_eq!(clamav_client::clean(&response), Ok(false));
    }

    #[async_std::test]
    #[cfg(unix)]
    async fn async_tokio_scan_socket_clean_stream() {
        let stream = stream_from_file(CLEAN_TEST_FILE_PATH).await;

        let err_msg = format!(
            "Could not scan test file {} via socket at {:?}",
            CLEAN_TEST_FILE_PATH, SOCKET.0
        );
        let response = SOCKET.scan_stream(stream, None).await.expect(&err_msg);
        assert_eq!(&response, OK_RESPONSE);
        assert_eq!(clamav_client::clean(&response), Ok(true));
    }

    #[async_std::test]
    #[cfg(unix)]
    async fn async_tokio_scan_socket_oversized_stream() {
        let stream = stream_from_file(OVERSIZED_TEST_FILE_PATH).await;

        let err_msg = format!(
            "Could not scan test file {} via socket at {:?}",
            OVERSIZED_TEST_FILE_PATH, SOCKET.0
        );
        let response = SOCKET.scan_stream(stream, None).await.expect(&err_msg);
        assert_eq!(&response, SIZE_LIMIT_EXCEEDED_ERROR_RESPONSE);
        assert_eq!(clamav_client::clean(&response), Ok(false));
    }

    #[async_std::test]
    async fn async_tokio_scan_tcp_infected_stream() {
        let stream = stream_from_file(EICAR_TEST_FILE_PATH).await;

        let err_msg = format!(
            "Could not scan test file {} via TCP at {}",
            EICAR_TEST_FILE_PATH, TCP.0
        );
        let response = TCP.scan_stream(stream, None).await.expect(&err_msg);
        assert_eq!(&response, EICAR_FILE_SIGNATURE_FOUND_RESPONSE);
        assert_eq!(clamav_client::clean(&response), Ok(false));
    }

    #[async_std::test]
    async fn async_tokio_scan_tcp_clean_stream() {
        let stream = stream_from_file(CLEAN_TEST_FILE_PATH).await;

        let err_msg = format!(
            "Could not scan test file {} via TCP at {}",
            CLEAN_TEST_FILE_PATH, TCP.0
        );
        let response = TCP.scan_stream(stream, None).await.expect(&err_msg);
        assert_eq!(&response, OK_RESPONSE);
        assert_eq!(clamav_client::clean(&response), Ok(true));
    }

    #[async_std::test]
    async fn async_tokio_scan_tcp_oversized_stream() {
        let stream = stream_from_file(OVERSIZED_TEST_FILE_PATH).await;

        let err_msg = format!(
            "Could not scan test file {} via TCP at {}",
            OVERSIZED_TEST_FILE_PATH, TCP.0
        );
        let response = TCP.scan_stream(stream, None).await.expect(&err_msg);
        assert_eq!(&response, SIZE_LIMIT_EXCEEDED_ERROR_RESPONSE);
        assert_eq!(clamav_client::clean(&response), Ok(false));
    }
}
