use super::super::*;

/// Every refusal text this module can give has its own stable code and a fix, so rewording
/// a text cannot silently fall back to the generic code.
#[test]
fn every_reason_text_has_a_code_and_a_fix() {
    let texts = [
        reasons::PULL_REFS,
        reasons::REPLACE_REFS,
        reasons::NAMESPACE_CASE,
        reasons::DELETION,
        reasons::RESTRICTED,
        reasons::PULL_REQUEST,
        reasons::NO_WRITE,
        reasons::TOKEN_SCOPE,
        reasons::ARCHIVED,
        reasons::ARCHIVED_API,
    ];
    for text in texts {
        let (code, fix) = meta(text);
        assert_ne!(code, codes::REF_REFUSED, "{text} has no code of its own");
        assert!(!fix.is_empty(), "{text} has no remediation");
    }
}
