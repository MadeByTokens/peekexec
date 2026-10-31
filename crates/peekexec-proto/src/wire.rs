//! Framing: one JSON value per line, with a size cap.

use std::io::{self, BufRead, BufReader, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;

use serde::de::DeserializeOwned;
use serde::Serialize;

/// Largest accepted message (scripts and installed files travel inline).
pub const MAX_MSG: u64 = 32 * 1024 * 1024;

/// What a command's output may take of a reply, per stream, as JSON. A
/// reply must fit [`MAX_MSG`] once encoded, and encoding can multiply the
/// size by six (a control character becomes `\\u0000`), so the budget is on
/// the encoded length, not on the bytes the command wrote.
pub const OUTPUT_BUDGET: usize = 14 * 1024 * 1024;

/// Bytes `c` takes in a JSON string.
fn encoded_len(c: char) -> usize {
    match c {
        '"' | '\\' | '\u{8}' | '\u{c}' | '\n' | '\r' | '\t' => 2,
        '\0'..='\u{1f}' => 6,
        c => c.len_utf8(),
    }
}

/// Cut `text` to [`OUTPUT_BUDGET`] encoded bytes. Returns how many bytes
/// were cut off, if any.
pub fn fit_output(text: &mut String) -> Option<usize> {
    let mut used = 0;
    for (i, c) in text.char_indices() {
        used += encoded_len(c);
        if used > OUTPUT_BUDGET {
            let cut = text.len() - i;
            text.truncate(i);
            return Some(cut);
        }
    }
    None
}

/// Default daemon socket.
pub const SOCKET: &str = "/run/peekexec/peekexec.sock";

/// Overwrite bytes that held a secret. `black_box` keeps the compiler from
/// dropping the writes as dead stores.
pub fn wipe(bytes: &mut [u8]) {
    bytes.fill(0);
    std::hint::black_box(bytes);
}

/// Message buffers are wiped once used: a message may carry a password.
pub fn write_msg<W: Write, T: Serialize>(w: &mut W, msg: &T) -> io::Result<()> {
    let mut buf = serde_json::to_vec(msg).map_err(io::Error::other)?;
    buf.push(b'\n');
    let sent = w.write_all(&buf).and_then(|()| w.flush());
    buf.resize(buf.capacity(), 0);
    wipe(&mut buf);
    sent
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
    let parsed = serde_json::from_slice(&buf)
        .map(Some)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e));
    buf.resize(buf.capacity(), 0);
    wipe(&mut buf);
    parsed
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

    #[test]
    fn output_fits_a_reply_however_it_encodes() {
        for c in ['a', '\0', '"', 'é', '\u{fffd}', '\n'] {
            let mut text = c.to_string().repeat(20 * 1024 * 1024);
            let cut = fit_output(&mut text);
            assert!(cut.is_some());
            let encoded = serde_json::to_string(&text).unwrap();
            assert!(
                encoded.len() <= OUTPUT_BUDGET + 2,
                "{c:?}: {}",
                encoded.len()
            );
            assert!(2 * OUTPUT_BUDGET + 64 * 1024 < MAX_MSG as usize);
        }
        let mut short = "ok".to_string();
        assert_eq!(fit_output(&mut short), None);
        assert_eq!(short, "ok");
    }
}
