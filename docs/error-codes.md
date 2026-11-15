# Error codes

Every refusal rbit gives carries a stable, machine-readable `code`. Clients may branch on it;
rbit adds codes but does not rename or reuse them.

## Where a code appears

- **API errors** answer `{"message", "code"}` as before. A refusal adds two optional fields:
  `rule` names the rule or setting that refused (for example
  `branch protection main (require_pull_request)` or `token scope read`), and `remediation`
  is a short sentence on what would make the request pass. The OpenAPI `Error` schema declares
  both.
- **Git pushes** answer a refused ref as `ng <ref> [code] reason (fix: remediation)` in the
  receive-pack report (clients that asked for `report-status`), and as the same text in the
  `403` explanation for clients that did not. A push refused before Git starts (a token that
  cannot push, a repository without write access) answers `403` with the same `[code] reason
  (fix: …)` text. Over SSH the text is shown on stderr.
- **`rbit --json`** prints the server's `code`, `rule` and `remediation` in its
  `rbit.error/1` object (see [the CLI guide](cli.md#output-for-programs)).

## Push codes

These come from the push gate that HTTP and SSH pushes run before Git.

| Code | Refused because | Remediation |
|---|---|---|
| `protected_branch_deletion` | a rule with `deny_deletion` matches the branch | Ask an administrator to change the rule, or to delete the branch. |
| `protected_branch_restricted` | a rule with `restrict_pushers` does not list you or your teams | Ask an administrator to allow you in this rule. |
| `protected_branch_requires_pull_request` | a rule with `require_pull_request` matches; updates must go through a pull request | Push a branch and open a pull request into it. |
| `protected_branch_force_push` | a rule with `deny_force_push` matches and the change rewrites the branch | Merge or push without rewriting the branch, or ask an administrator to change the rule. |
| `no_write_access` | you may not write to this repository | Ask an administrator for write access. |
| `token_scope_insufficient` | your personal access token's scope has no write right (API: the scope is narrower than the request needs) | Use a personal access token with the write scope, created under Settings > Access tokens. |
| `repository_archived` | the repository is archived and read-only | Ask an administrator to unarchive it. |
| `repository_mirror` | the repository is a pull mirror, which only changes by fetching its upstream | Push to the upstream repository instead. |
| `ref_reserved` | the ref is in a namespace rbit manages (`refs/pull/`, `refs/replace/`, `refs/merge-queue/`, reserved branch names) | Push to a branch under `refs/heads/`. |
| `ref_not_canonical` | the branch is not spelled in the canonical `refs/heads/` namespace | Use the canonical spelling. |
| `scratch_ref_not_owned` | a `refs/scratch/` ref is not under your own name | Push under `refs/scratch/<your name>/`. |
| `scratch_ref_limit` | you already hold the maximum number of scratch refs here | Delete one, or wait for them to expire. |
| `task_tag_moved` | a workflow task moves or deletes an existing tag | Push a new tag name. |
| `task_workflow_files` | a workflow task changes workflow files | Make the change as a person. |
| `pack_unreadable` | the pushed pack could not be read | Retry; if it keeps failing, check the pack locally. |
| `ref_refused` | any other refusal | Ask an administrator why the update is refused. |

## Merge codes

A merge, a queued merge, or a write to a pull request's branch that waits for something answers
`405` with one of these codes. `rule` names the protection rule when the requirement comes from
one.

| Code | Waits for | Remediation |
|---|---|---|
| `pull_closed` | the pull request to be open | Reopen the pull request, or open a new one. |
| `merge_draft` | the pull request to leave draft | Mark it ready for review. |
| `head_branch_missing` | the head branch to exist | Push the head branch again. |
| `base_branch_missing` | the base branch to exist | Create the base branch, or retarget the pull request. |
| `base_changed` | the base branch to stop moving during the merge | Review the pull request and try again. |
| `merge_conflicts` | the branches to merge without conflicts | Update the pull request branch from its base and resolve the conflicts. |
| `merge_nothing_to_merge` | a commit the base does not already have | Push a commit the base does not already have. |
| `merge_unrelated_histories` | the branches to share history | Rebase the head branch onto the base. |
| `merge_failed` | the merge to be made by Git | Retry; the message says what Git reported. |
| `merge_requires_approvals` | approvals from writers other than the author | Ask a writer other than the author to approve the pull request. |
| `merge_changes_requested` | requested changes to be dismissed or resolved | Ask the reviewers to approve, or to dismiss their requested changes. |
| `merge_restricted_pusher` | you to be allowed to push to the base | Ask an administrator to allow you in this branch's rule. |
| `merge_checks_required` | the required status checks to pass on the head commit | Wait for them to pass. |
| `merge_checks_failing` | the head commit's checks to pass | Fix the failing checks. |
| `branch_exists` | a branch name that is free | Choose another branch name. |
| `head_in_other_repository` | the head branch to live in this repository | Update the branch in its own repository. |

Branch writes made through a merge (updating a branch from its base, reverting into a new
branch) use the push codes above where protection refuses them, such as
`protected_branch_force_push` for a rewrite of a protected branch.

## Other API codes

`not_found`, `unauthenticated`, `forbidden`, `conflict`, `head_changed`, `base_changed`,
`blocked`, `invalid`, `rate_limited`, `unavailable`, `moved` and `internal` keep their
meaning; see [the CLI guide](cli.md#output-for-programs) for the exit codes they map to. A
`rate_limited` answer carries the remediation `Retry after N seconds.` with its `Retry-After`.

## Deliberately uncoded

- **Suspended accounts** answer `401 unauthenticated`, exactly as a bad token does. This is a
  decision, not a gap: a distinct answer would reveal that an account exists and is suspended
  to anyone holding its token.
- **Non-fast-forward pushes refused by Git** (`receive.denyNonFastForwards`) keep Git's own
  text. The gate does not know whether an update is a fast-forward, and Git makes that check
  itself.
- **Git pushes with a read-scoped token** get `token_scope_insufficient` whatever the user's
  rights: the token is the ceiling, so it is named first, and the fix (a token with the write
  scope) is the first step either way.
