//! Framing: one JSON value per line, with a size cap.

use std::io::{self, BufRead, BufReader, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;

use serde::de::DeserializeOwned;
use serde::Serialize;

/// Largest accepted message (scripts and installed files travel inline).
pub const MAX_MSG: u64 = 32 * 1024 * 1024;

/// Default daemon socket.
pub const SOCKET: &str = "/run/peekexec/peekexec.sock";

pub fn write_msg<W: Write, T: Serialize>(w: &mut W, msg: &T) -> io::Result<()> {
    let mut buf = serde_json::to_vec(msg).map_err(io::Error::other)?;
    buf.push(b'\n');
    w.write_all(&buf)?;
    w.flush()
}

/// `Ok(None)` on a clean EOF before any byte of a message.
pub fn read_msg<R: BufRead, T: DeserializeOwned>(r: &mut R) -> io::Result<Option<T>> {
    let mut buf = Vec::new();
    r.by_ref().take(MAX_MSG).read_until(b'\n', &mut buf)?;
    if buf.is_empty() {
        return Ok(None);
    }
    if buf.last() != Some(&b'\n') {
        let why = if buf.len() as u64 >= MAX_MSG {
            "message too large"
        } else {
            "connection closed mid-message"
        };
        return Err(io::Error::new(io::ErrorKind::InvalidData, why));
    }
    serde_json::from_slice(&buf)
        .map(Some)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

/// Connect, send one message, read one reply.
pub fn call<Q: Serialize, A: DeserializeOwned>(socket: &Path, msg: &Q) -> io::Result<A> {
    let mut stream = UnixStream::connect(socket)?;
    write_msg(&mut stream, msg)?;
    let mut reader = BufReader::new(stream);
    read_msg(&mut reader)?.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "daemon closed the connection without replying",
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_eof() {
        let mut buf = Vec::new();
        write_msg(&mut buf, &vec!["a", "b\nc"]).unwrap();
        write_msg(&mut buf, &42).unwrap();
        let mut r = io::Cursor::new(buf);
        assert_eq!(
            read_msg::<_, Vec<String>>(&mut r).unwrap().unwrap(),
            ["a", "b\nc"]
        );
        assert_eq!(read_msg::<_, u32>(&mut r).unwrap(), Some(42));
        assert_eq!(read_msg::<_, u32>(&mut r).unwrap(), None);
    }

    #[test]
    fn truncated_message_is_an_error() {
        let mut r = io::Cursor::new(b"{\"a\":".to_vec());
        assert!(read_msg::<_, serde_json::Value>(&mut r).is_err());
    }
}
