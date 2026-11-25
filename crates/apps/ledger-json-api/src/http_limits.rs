//! The limits of the HTTP listener ([`crate::http::run_server_with`]): what a client can make the server allocate or hold before the
//! request reaches authentication.
//!
//! [CANTON-NOTE: SEMANTICS] Canton's JSON API is a Pekko HTTP server (`HttpService.serverBinding`): its parser refuses a body longer than
//! `max-inbound-message-size` (`ServerConfig.defaultMaxInboundMessageSize`, 10 MiB) from the `Content-Length` alone with 413, a request
//! has `request-timeout` (`JsonApiConfig.defaultRequestTimeout`, 20 s), and Pekko's own defaults bound the open connections
//! (`pekko.http.server.max-connections`, 1024; past it connections wait in the accept queue), the header count (64) and a header's length
//! (8 KiB).
use std::io::{self, BufRead, BufReader, Read};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// The limits of one HTTP listener.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HttpLimits {
    /// The longest body read; a longer `Content-Length` is answered 413 without reading it.
    pub max_body_bytes: usize,
    /// The most connections served at once; the next ones wait to be accepted.
    pub max_connections: usize,
    /// How long reading one request (its head and its body) may take, however slowly its bytes arrive.
    pub request_timeout: Duration,
    /// The longest line of the head (request line or header).
    pub max_line_bytes: usize,
    /// The most header lines.
    pub max_headers: usize,
    /// How long a stopping server waits for the requests in flight (`ProcessingTimeouts.shutdownProcessing`, 60 s).
    pub shutdown_grace: Duration,
}

impl Default for HttpLimits {
    fn default() -> Self {
        Self {
            max_body_bytes: 10 * 1024 * 1024,
            max_connections: 1024,
            request_timeout: Duration::from_secs(20),
            max_line_bytes: 8 * 1024,
            max_headers: 64,
            shutdown_grace: Duration::from_secs(60),
        }
    }
}

/// Why a request was not read.
#[derive(Debug)]
pub(crate) enum ReadError {
    /// The connection failed, closed or timed out: nothing is answered.
    Io(io::Error),
    /// The request breaks a limit: it is answered with this status and message, and the connection closed.
    Refused { status: u16, message: String },
}

impl From<io::Error> for ReadError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

impl ReadError {
    pub(crate) fn into_io(self) -> io::Error {
        match self {
            Self::Io(e) => e,
            Self::Refused { message, .. } => io::Error::new(io::ErrorKind::InvalidData, message),
        }
    }
}

/// When reading a request has to end.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Deadline {
    at: Instant,
    pub(crate) limits: HttpLimits,
}

impl Deadline {
    pub(crate) fn starting_now(limits: HttpLimits) -> Self {
        Self {
            at: Instant::now() + limits.request_timeout,
            limits,
        }
    }

    fn check(&self) -> io::Result<()> {
        if Instant::now() >= self.at {
            Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "the request was not received within the request timeout",
            ))
        } else {
            Ok(())
        }
    }

    /// Reads one head line (up to and including `\n`), refusing one longer than the limit.
    pub(crate) fn read_line<R: Read>(
        &self,
        reader: &mut BufReader<R>,
    ) -> Result<String, ReadError> {
        let mut line = Vec::new();
        loop {
            self.check()?;
            let available = reader.fill_buf()?;
            if available.is_empty() {
                break;
            }
            let (take, done) = match available.iter().position(|b| *b == b'\n') {
                Some(i) => (i + 1, true),
                None => (available.len(), false),
            };
            line.extend_from_slice(&available[..take]);
            reader.consume(take);
            if line.len() > self.limits.max_line_bytes {
                return Err(ReadError::Refused {
                    status: 431,
                    message: format!(
                        "HTTP header line exceeds the configured limit of {} bytes",
                        self.limits.max_line_bytes
                    ),
                });
            }
            if done {
                break;
            }
        }
        String::from_utf8(line).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidData, "a head line is not UTF-8").into()
        })
    }

    /// Refuses a body longer than the limit before any of it is read.
    pub(crate) fn admit_body(&self, content_length: usize) -> Result<(), ReadError> {
        if content_length > self.limits.max_body_bytes {
            return Err(ReadError::Refused {
                status: 413,
                message: format!(
                    "Request Content-Length of {content_length} bytes exceeds the configured limit of {} bytes",
                    self.limits.max_body_bytes
                ),
            });
        }
        Ok(())
    }

    /// Reads a body of `len` bytes (already admitted), within the deadline.
    pub(crate) fn read_body<R: Read>(
        &self,
        reader: &mut BufReader<R>,
        len: usize,
    ) -> Result<Vec<u8>, ReadError> {
        let mut body = Vec::with_capacity(len.min(64 * 1024));
        while body.len() < len {
            self.check()?;
            let available = reader.fill_buf()?;
            if available.is_empty() {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "body cut short").into());
            }
            let take = available.len().min(len - body.len());
            body.extend_from_slice(&available[..take]);
            reader.consume(take);
        }
        Ok(body)
    }

    pub(crate) fn too_many_headers(&self) -> ReadError {
        ReadError::Refused {
            status: 431,
            message: format!(
                "HTTP message contains more than the configured limit of {} headers",
                self.limits.max_headers
            ),
        }
    }
}

/// The count of connections being served; a [`ConnectionSlot`] holds one.
#[derive(Debug, Default)]
pub(crate) struct ConnectionGate {
    open: AtomicUsize,
}

impl ConnectionGate {
    /// Waits until no connection is open, at most `grace`.
    pub(crate) fn drain(&self, grace: Duration) {
        let deadline = Instant::now() + grace;
        while self.open.load(Ordering::Acquire) > 0 && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    /// A slot for one more connection, if fewer than `max` are open.
    pub(crate) fn try_enter(self: &Arc<Self>, max: usize) -> Option<ConnectionSlot> {
        self.open
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| {
                (n < max).then_some(n + 1)
            })
            .ok()
            .map(|_| ConnectionSlot(Arc::clone(self)))
    }
}

/// One open connection; dropping it frees its place.
pub(crate) struct ConnectionSlot(Arc<ConnectionGate>);

impl Drop for ConnectionSlot {
    fn drop(&mut self) {
        self.0.open.fetch_sub(1, Ordering::AcqRel);
    }
}
