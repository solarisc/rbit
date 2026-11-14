//! The `warnings` of a workflow in the workflows API: what its file says that rbit accepts
//! but never acts on, each as a `{code, message}` object.
use rbit_services::actions::browse::WorkflowState;
use serde_json::{Value, json};

/// A workflow's warnings, each with its `code` and an English `message`.
pub(super) fn warnings_json(workflow: &WorkflowState) -> Vec<Value> {
    workflow.warnings.iter().map(|warning| json!({ "code": warning.code, "message": warning.message() })).collect()
}
