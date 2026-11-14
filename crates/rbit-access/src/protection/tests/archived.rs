use super::super::*;

/// Both archived refusal texts (the Git one and the API one) name the archived code.
#[test]
fn archived_texts_both_name_the_archived_code() {
    for text in [reasons::ARCHIVED, reasons::ARCHIVED_API] {
        assert_eq!(meta(text).0, codes::REPOSITORY_ARCHIVED, "{text}");
    }
}
