use super::super::*;

/// Every code this crate can emit is listed in docs/error-codes.md, so a new code cannot ship
/// undocumented.
#[test]
fn every_code_is_documented() {
    let docs = include_str!("../../../../../docs/error-codes.md");
    for code in codes::ALL {
        assert!(docs.contains(&format!("`{code}`")), "`{code}` is not in docs/error-codes.md");
    }
}
