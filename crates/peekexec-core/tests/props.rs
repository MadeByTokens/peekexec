//! Property tests: random and adversarial input for the parts that turn
//! requester-controlled text into what the human sees.

use peekexec_core::format::format_shell;
use peekexec_core::textcheck::scan;
use proptest::prelude::*;

/// Shell-ish text: operators, quotes, substitutions, odd Unicode.
fn shellish() -> impl Strategy<Value = String> {
    let atom = prop_oneof![
        Just("&&".to_string()),
        Just("||".to_string()),
        Just(";".to_string()),
        Just("|".to_string()),
        Just("'".to_string()),
        Just("\"".to_string()),
        Just("$(".to_string()),
        Just(")".to_string()),
        Just("`".to_string()),
        Just("\\".to_string()),
        Just("\n".to_string()),
        Just(">&2".to_string()),
        Just("then ".to_string()),
        Just("fi".to_string()),
        Just(" ".to_string()),
        "[a-z]{1,4}",
        any::<char>().prop_map(String::from),
    ];
    proptest::collection::vec(atom, 0..40).prop_map(|v| v.concat())
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(4000))]

    #[test]
    fn formatter_lines_always_rejoin_to_the_original(s in shellish()) {
        let rejoined: String = format_shell(&s).iter().map(|l| l.text.as_str()).collect();
        prop_assert_eq!(rejoined, s);
    }

    #[test]
    fn formatter_lines_hold_at_most_their_own_final_newline(s in shellish()) {
        for l in format_shell(&s) {
            let body = l.text.strip_suffix('\n').unwrap_or(&l.text);
            prop_assert!(!body.contains('\n'), "{:?}", l.text);
        }
    }

    #[test]
    fn formatter_never_panics_on_any_string(s in any::<String>()) {
        let rejoined: String = format_shell(&s).iter().map(|l| l.text.as_str()).collect();
        prop_assert_eq!(rejoined, s);
    }

    #[test]
    fn scan_positions_point_at_the_flagged_characters(s in any::<String>()) {
        let lines: Vec<&str> = s.split('\n').collect();
        for f in scan(&s) {
            let c = lines[f.line - 1].chars().nth(f.column - 1).expect("position exists");
            prop_assert_eq!(format!("U+{:04X}", c as u32), f.codepoint);
        }
    }
}
