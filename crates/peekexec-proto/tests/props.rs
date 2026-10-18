//! Property tests: whatever bytes arrive on the socket, parsing fails
//! cleanly instead of crashing the root daemon.

use peekexec_proto::wire::read_msg;
use peekexec_proto::ClientMsg;
use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(4000))]

    #[test]
    fn arbitrary_bytes_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..2048)) {
        let mut r = std::io::Cursor::new(bytes);
        let _ = read_msg::<_, ClientMsg>(&mut r);
    }

    #[test]
    fn jsonish_lines_never_panic(s in r#"\{("op":"(run|submit|wait|cancel|preview|register|unregister)",?)?.{0,200}\}\n"#) {
        let mut r = std::io::Cursor::new(s.into_bytes());
        let _ = read_msg::<_, ClientMsg>(&mut r);
    }
}
