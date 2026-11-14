//! The body of `rbit workflow list --json`: the API's workflows, each with its `warnings`
//! (an array of `{code, message}`), as the `rbit.workflows/1` schema documents them.
use serde_json::{Value, json};

use super::agent;

/// The body of `rbit workflow list --json` (after `schema`): the API's workflows, each with
/// its `warnings`, an array of `{code, message}`.
pub(super) fn workflow_listing(listed: &Value, fields: &[String]) -> Value {
    let workflows = listed["workflows"].as_array().cloned().unwrap_or_default();
    json!({ "workflows": agent::select(workflows, fields) })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn workflow_list_json_carries_each_workflows_warnings() {
        let warning = json!({ "code": "unsupported_event", "message": "release does not start runs on rbit" });
        let release = json!({
            "id": "release.yml",
            "name": "Release",
            "path": ".rbit/workflows/release.yml",
            "state": "active",
            "warnings": [warning],
        });
        let ci = json!({ "id": "ci.yml", "name": "CI", "path": ".rbit/workflows/ci.yml", "state": "active", "warnings": [] });
        let listed = json!({ "total_count": 2, "workflows": [release, ci] });
        assert_eq!(workflow_listing(&listed, &[]), json!({ "workflows": [release, ci] }));
        assert_eq!(workflow_listing(&json!({}), &[]), json!({ "workflows": [] }));
    }
}
