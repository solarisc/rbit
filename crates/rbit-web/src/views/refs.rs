//! Branch and tag listings.
//!
//! Milestone 2 workstream B (branch protection) adds the "Protected" badge: branches some
//! rule protects (`ProtectionService::protected_branches`) are marked with
//! [`RefsPage::with_protected`].
//!
//! Like GitHub's, the branches page puts the default branch in its own box and shows each
//! other branch's pull request (or a button to open one) and how far it is behind and
//! ahead of the default branch. Those counts walk history, so they arrive afterwards as
//! out-of-band cells ([`BranchDivergenceFragment`]).

use std::fmt::Write as _;

use askama::Template;
use askama_web::WebTemplate;
use rbit_git::{Divergence, RefDetail};

use crate::{
    urls::RepoUrls,
    views::{
        layout::Page,
        repo::{CommitView, RepoHeader},
        timeline::StateBadge,
    },
};

/// Commits counted at most on each side of a branch's divergence.
pub const DIVERGENCE_CAP: usize = 1000;

/// The pull request whose head is a branch: its open one, or else its latest.
#[derive(Debug, Clone)]
pub struct BranchPull {
    /// `#12`.
    pub number: String,
    pub title: String,
    pub url: String,
    pub badge: StateBadge,
}

/// One branch or tag row.
#[derive(Debug, Clone)]
pub struct RefRow {
    pub name: String,
    /// Browse the tree at this ref.
    pub url: String,
    pub is_default: bool,
    pub commit: CommitView,
    /// Source archives of the ref (shown for tags).
    pub zip_url: String,
    pub tar_url: String,
    /// The branch compared against the default branch (other branches only).
    pub compare_url: Option<String>,
    /// The ref's history.
    pub history_url: String,
    /// A branch protection rule matches this branch.
    pub protected: bool,
    /// The branch's pull request (branches page).
    pub pull: Option<BranchPull>,
    /// "New pull request" for a branch without an open one, into the default branch.
    pub new_pull_url: Option<String>,
    /// Id of the cell [`BranchDivergenceFragment`] fills.
    pub divergence_slot: String,
}

/// The id of a branch's divergence cell: its name in hex, so any branch name gives a
/// valid id and the fragment needs no shared ordering with the page.
pub fn divergence_slot(name: &str) -> String {
    let mut slot = String::from("branch-divergence-");
    for byte in name.bytes() {
        let _ = write!(slot, "{byte:02x}");
    }
    slot
}

impl RefRow {
    pub fn new(detail: &RefDetail, default_branch: &str, urls: &RepoUrls) -> Self {
        // Link by full ref name: a branch and a tag may share a short name.
        let full_name = match detail.kind {
            rbit_git::RefKind::Branch => format!("refs/heads/{}", detail.name),
            rbit_git::RefKind::Tag => format!("refs/tags/{}", detail.name),
        };
        let is_default = detail.kind == rbit_git::RefKind::Branch && detail.name == default_branch;
        Self {
            compare_url: (detail.kind == rbit_git::RefKind::Branch && !is_default).then(|| urls.compare(default_branch, &detail.name)),
            name: detail.name.clone(),
            url: urls.tree(&full_name, ""),
            zip_url: urls.archive(&detail.name, ".zip"),
            tar_url: urls.archive(&detail.name, ".tar.gz"),
            history_url: urls.commits(&full_name),
            is_default,
            commit: CommitView::new(&detail.commit, urls),
            protected: false,
            pull: None,
            new_pull_url: None,
            divergence_slot: divergence_slot(&detail.name),
        }
    }
}

/// Shared by the branches and tags pages; `kind` is `"branch"` or `"tag"`.
#[derive(Debug, Template, WebTemplate)]
#[template(path = "repo/refs.html")]
pub struct RefsPage {
    pub pagination: super::pagination::Pagination,
    pub page: Page,
    pub header: RepoHeader,
    pub kind: &'static str,
    pub graph: Option<crate::views::branch_graph::BranchGraph>,
    pub rows: Vec<RefRow>,
    /// The default branch's name, for the column heading.
    pub default_branch: String,
    /// The lazily loaded divergence cells (branches page).
    pub divergence_url: Option<String>,
}

impl RefsPage {
    /// The search box's label and placeholder.
    pub fn search_label(&self) -> &'static str {
        if self.kind == "branch" { "Search branches" } else { "Search tags" }
    }

    /// The default branch's row, which the branches page shows in a box of its own.
    pub fn default_row(&self) -> Option<&RefRow> {
        self.rows.iter().find(|row| row.is_default)
    }

    /// Every row but the default branch's.
    pub fn other_rows(&self) -> Vec<&RefRow> {
        self.rows.iter().filter(|row| !row.is_default).collect()
    }

    /// Marks the branches named in `protected` (on the branches page only).
    #[must_use]
    pub fn with_protected(mut self, protected: &[String]) -> Self {
        if self.kind == "branch" {
            for row in &mut self.rows {
                row.protected = protected.contains(&row.name);
            }
        }
        self
    }
}

/// How far one branch is behind and ahead of the default branch, drawn as two bars that
/// meet in the middle. Widths are percentages of the largest count on the page.
#[derive(Debug, Clone)]
pub struct DivergenceCell {
    pub slot: String,
    pub ahead: String,
    pub behind: String,
    pub ahead_width: usize,
    pub behind_width: usize,
    pub title: String,
}

/// `GET /{owner}/{repo}/branches/divergence`: out-of-band cells for the branches page.
#[derive(Debug, Template, WebTemplate)]
#[template(path = "repo/branch_divergence.html")]
pub struct BranchDivergenceFragment {
    pub cells: Vec<DivergenceCell>,
}

impl BranchDivergenceFragment {
    /// Cells for `branches` (name and divergence, `None` when unknown) against `base`.
    pub fn new(base: &str, branches: &[(String, Option<Divergence>)]) -> Self {
        let largest = branches.iter().filter_map(|(_, found)| found.map(|d| d.ahead.max(d.behind))).max().unwrap_or(0).max(1);
        let cells = branches
            .iter()
            .filter_map(|(name, found)| {
                let found = (*found)?;
                let count = |value: usize| {
                    if found.capped && value >= DIVERGENCE_CAP { format!("{DIVERGENCE_CAP}+") } else { value.to_string() }
                };
                let width = |value: usize| if value == 0 { 0 } else { (value * 100 / largest).max(4) };
                Some(DivergenceCell {
                    slot: divergence_slot(name),
                    title: format!("{} behind, {} ahead of {base}", plural(&count(found.behind)), plural(&count(found.ahead))),
                    ahead: count(found.ahead),
                    behind: count(found.behind),
                    ahead_width: width(found.ahead),
                    behind_width: width(found.behind),
                })
            })
            .collect();
        Self { cells }
    }
}

fn plural(count: &str) -> String {
    if count == "1" { "1 commit".to_owned() } else { format!("{count} commits") }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::views::components::Avatar;

    fn row(name: &str) -> RefRow {
        let commit = CommitView {
            id: "1".repeat(40),
            short_id: "1111111".to_owned(),
            summary: "Initial commit".to_owned(),
            author: "Alice".to_owned(),
            avatar: Avatar::default(),
            when: "today".to_owned(),
            when_iso: String::new(),
            date: String::new(),
            browse_url: String::new(),
            url: "/acme/rocket/commit/1111111".to_owned(),
            status: None,
        };
        RefRow {
            name: name.to_owned(),
            url: format!("/acme/rocket/tree/refs/heads/{name}"),
            is_default: name == "main",
            commit,
            zip_url: String::new(),
            tar_url: String::new(),
            compare_url: None,
            history_url: String::new(),
            protected: false,
            pull: None,
            new_pull_url: (name != "main").then(|| format!("/acme/rocket/pulls/new?base=main&head={name}")),
            divergence_slot: divergence_slot(name),
        }
    }

    fn page(kind: &'static str) -> RefsPage {
        RefsPage {
            pagination: super::super::pagination::Pagination::new(
                2,
                &super::super::pagination::ListQuery::default(),
                "/acme/rocket/branches".into(),
                vec![],
            ),
            page: Page {
                updates: rbit_services::updates::UpdateStatus::default(),
                site_name: "rbit".to_owned(),
                branding: rbit_core::config::BrandingConfig::default(),
                title: None,
                viewer: None,
                path: "/acme/rocket/branches".to_owned(),
                theme: crate::themes::Theme::System,
                has_unread_notifications: false,
            },
            header: RepoHeader { owner: "acme".to_owned(), name: "rocket".to_owned(), active_tab: "branches", ..RepoHeader::default() },
            kind,
            graph: None,
            rows: vec![row("main"), row("feature")],
            default_branch: "main".to_owned(),
            divergence_url: (kind == "branch").then(|| "/acme/rocket/branches/divergence?q=&page=1".to_owned()),
        }
    }

    #[test]
    fn protected_branches_carry_a_badge() {
        let protected = ["main".to_owned()];
        let branches = page("branch").with_protected(&protected);
        assert!(branches.rows[0].protected && !branches.rows[1].protected);
        let html = branches.render().unwrap();
        assert_eq!(html.matches("Protected</span>").count(), 1);
        assert!(!html.contains("style="));

        let tags = page("tag").with_protected(&protected);
        assert!(!tags.rows[0].protected, "tags are never marked");
        assert!(!page("branch").render().unwrap().contains("Protected</span>"));
    }

    #[test]
    fn branches_page_offers_a_pull_request_and_loads_divergence() {
        let html = page("branch").render().unwrap();
        assert!(
            html.contains("/acme/rocket/pulls/new?base=main&#38;head=feature")
                || html.contains("/acme/rocket/pulls/new?base=main&amp;head=feature"),
            "{html}"
        );
        assert_eq!(html.matches("New pull request").count(), 1, "not for the default branch");
        assert!(html.contains("/acme/rocket/branches/divergence"));
        assert!(html.contains(&format!("id=\"{}\"", divergence_slot("feature"))));
        assert!(!html.contains(&format!("id=\"{}\"", divergence_slot("main"))));
    }

    #[test]
    fn divergence_cells_scale_to_the_largest_count() {
        let found = |ahead, behind, capped| Some(Divergence { ahead, behind, capped });
        let fragment = BranchDivergenceFragment::new(
            "main",
            &[("a/b".into(), found(2, 8, false)), ("big".into(), found(1000, 0, true)), ("gone".into(), None)],
        );
        assert_eq!(fragment.cells.len(), 2);
        let first = &fragment.cells[0];
        assert_eq!((first.ahead.as_str(), first.behind.as_str(), first.ahead_width, first.behind_width), ("2", "8", 4, 4));
        assert_eq!(first.title, "8 commits behind, 2 commits ahead of main");
        assert_eq!(first.slot, "branch-divergence-612f62");
        assert_eq!((fragment.cells[1].ahead.as_str(), fragment.cells[1].ahead_width), ("1000+", 100));
        let html = fragment.render().unwrap();
        assert_eq!(html.matches("hx-swap-oob").count(), 2);
        assert!(!html.contains("style="));
    }
}
