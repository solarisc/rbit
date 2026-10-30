//! Bounded, searchable branch/tag selection, loaded only when the picker is opened. Like
//! GitHub's, it lists branches or tags under two tabs, filters as you type and links to
//! the full branches or tags page.

use askama::Template;
use askama_web::WebTemplate;
use percent_encoding::{NON_ALPHANUMERIC, utf8_percent_encode};
use rbit_git::{RefKind, RefSummary};
use serde::Deserialize;

use crate::{
    urls::RepoUrls,
    views::{
        layout::Page,
        repo::{RefLink, RepoHeader},
    },
};

pub const PAGE_SIZE: usize = 50;

#[derive(Debug, Default, Clone, Copy, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RefTarget {
    #[default]
    Tree,
    Commits,
    Blame,
}

impl RefTarget {
    fn key(self) -> &'static str {
        match self {
            Self::Tree => "tree",
            Self::Commits => "commits",
            Self::Blame => "blame",
        }
    }

    fn link(self, urls: &RepoUrls, revision: &str, path: &str) -> String {
        match self {
            Self::Tree => urls.tree(revision, ""),
            Self::Commits => urls.commits(revision),
            Self::Blame => urls.blame(revision, path),
        }
    }
}

/// The picker's tab. Unset, it opens on the kind of the current ref, or on whichever kind
/// the repository has when it has only one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RefTab {
    Branch,
    Tag,
}

impl RefTab {
    fn key(self) -> &'static str {
        match self {
            Self::Branch => "branch",
            Self::Tag => "tag",
        }
    }

    fn holds(self, kind: RefKind) -> bool {
        matches!((self, kind), (Self::Branch, RefKind::Branch) | (Self::Tag, RefKind::Tag))
    }
}

#[derive(Debug, Default, Clone, Deserialize)]
#[serde(default)]
pub struct RefPickerQuery {
    pub target: RefTarget,
    pub path: String,
    pub current: String,
    pub q: String,
    pub page: usize,
    pub kind: Option<RefTab>,
}

impl RefPickerQuery {
    pub fn url(&self, base: &str, page: usize) -> String {
        let encode = |value: &str| utf8_percent_encode(value, NON_ALPHANUMERIC).to_string();
        let mut url = format!(
            "{base}?target={}&path={}&current={}&q={}&page={page}",
            self.target.key(),
            encode(&self.path),
            encode(&self.current),
            encode(&self.q)
        );
        if let Some(kind) = self.kind {
            url.push_str("&kind=");
            url.push_str(kind.key());
        }
        url
    }
}

#[derive(Debug, Clone)]
pub struct RefPickerLinks {
    pub page: String,
    pub options: String,
}

impl RefPickerLinks {
    pub fn new(urls: &RepoUrls, query: &RefPickerQuery) -> Self {
        let base = format!("{}/ref-picker", urls.home());
        Self { page: query.url(&base, 1), options: query.url(&format!("{base}/options"), 1) }
    }
}

#[derive(Debug)]
pub struct RefOption {
    pub link: RefLink,
    pub kind: &'static str,
}

#[derive(Debug)]
pub struct RefPicker {
    pub rows: Vec<RefOption>,
    pub total: usize,
    pub page: usize,
    pub pages: usize,
    pub query: String,
    pub current: String,
    pub target: &'static str,
    pub path: String,
    pub action: String,
    pub options_action: String,
    pub previous: Option<RefPickerLinks>,
    pub next: Option<RefPickerLinks>,
    /// `"branch"` or `"tag"`: the tab shown.
    pub kind: &'static str,
    pub branch_count: usize,
    pub tag_count: usize,
    /// Each tab, keeping the search.
    pub branches_tab: RefPickerLinks,
    pub tags_tab: RefPickerLinks,
    /// The full branches or tags page.
    pub view_all_url: String,
}

impl RefPicker {
    pub fn new(refs: &[RefSummary], default_branch: &str, urls: &RepoUrls, mut query: RefPickerQuery) -> Self {
        query.q = query.q.trim().chars().take(100).collect();
        let branch_count = refs.iter().filter(|reference| reference.kind == RefKind::Branch).count();
        let tag_count = refs.len() - branch_count;
        let current_is_tag = query.current.starts_with("refs/tags/")
            || (!query.current.starts_with("refs/heads/")
                && refs.iter().any(|r| r.kind == RefKind::Tag && r.name == query.current)
                && !refs.iter().any(|r| r.kind == RefKind::Branch && r.name == query.current));
        let tab = query.kind.unwrap_or(match (branch_count, tag_count) {
            (0, tags) if tags > 0 => RefTab::Tag,
            (_, 0) => RefTab::Branch,
            _ if current_is_tag => RefTab::Tag,
            _ => RefTab::Branch,
        });
        let needle = query.q.to_lowercase();
        let matches =
            |reference: &&RefSummary| tab.holds(reference.kind) && (needle.is_empty() || reference.name.to_lowercase().contains(&needle));
        let total = refs.iter().filter(matches).count();
        let pages = total.div_ceil(PAGE_SIZE).max(1);
        let page = query.page.clamp(1, pages);
        let mut rows: Vec<RefOption> = refs
            .iter()
            .filter(matches)
            .skip((page - 1) * PAGE_SIZE)
            .take(PAGE_SIZE)
            .map(|reference| {
                let (prefix, kind) = match reference.kind {
                    RefKind::Branch => ("refs/heads/", "Branch"),
                    RefKind::Tag => ("refs/tags/", "Tag"),
                };
                let full_revision = format!("{prefix}{}", reference.name);
                // Keep branch URLs compatible with the editing routes; disambiguate tags.
                let revision = if reference.kind == RefKind::Branch { &reference.name } else { &full_revision };
                RefOption {
                    kind,
                    link: RefLink {
                        name: reference.name.clone(),
                        url: query.target.link(urls, revision, &query.path),
                        is_current: query.current == full_revision || query.current == reference.name,
                        is_default: reference.kind == RefKind::Branch && reference.name == default_branch,
                    },
                }
            })
            .collect();
        // The default branch leads, as on the branches page.
        rows.sort_by_key(|row| !row.link.is_default);
        let action = format!("{}/ref-picker", urls.home());
        let options_action = format!("{action}/options");
        let tab_links = |kind| {
            let query = RefPickerQuery { kind: Some(kind), page: 1, ..query.clone() };
            RefPickerLinks { page: query.url(&action, 1), options: query.url(&options_action, 1) }
        };
        let (branches_tab, tags_tab) = (tab_links(RefTab::Branch), tab_links(RefTab::Tag));
        let query = RefPickerQuery { kind: Some(tab), ..query };
        let links = |page| RefPickerLinks { page: query.url(&action, page), options: query.url(&options_action, page) };
        Self {
            rows,
            total,
            page,
            pages,
            previous: (page > 1).then(|| links(page - 1)),
            next: (page < pages).then(|| links(page + 1)),
            branches_tab,
            tags_tab,
            view_all_url: if tab == RefTab::Branch { urls.branches() } else { urls.tags() },
            kind: tab.key(),
            branch_count,
            tag_count,
            query: query.q,
            current: query.current,
            target: query.target.key(),
            path: query.path,
            action,
            options_action,
        }
    }
}

#[derive(Debug, Template, WebTemplate)]
#[template(path = "repo/ref_picker_options.html")]
pub struct RefPickerOptions {
    pub picker: RefPicker,
}

#[derive(Debug, Template, WebTemplate)]
#[template(path = "repo/ref_picker.html")]
pub struct RefPickerPage {
    pub page: Page,
    pub header: RepoHeader,
    pub picker: RefPicker,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn refs() -> Vec<RefSummary> {
        (0..1020).map(|i| RefSummary { name: format!("v{i:04}"), kind: RefKind::Tag, target: "a".repeat(40) }).collect()
    }

    #[test]
    fn pagination_bounds_links_and_clamps_extreme_pages() {
        let refs = refs();
        let urls = RepoUrls::new("realworld", "git");
        let first = RefPicker::new(&refs, "main", &urls, RefPickerQuery::default());
        assert_eq!((first.rows.len(), first.total, first.pages), (50, 1020, 21));
        assert!(first.previous.is_none());
        assert!(first.next.is_some());
        let last = RefPicker::new(&refs, "main", &urls, RefPickerQuery { page: usize::MAX, ..Default::default() });
        assert_eq!((last.rows.len(), last.page), (20, 21));
        assert!(last.next.is_none());
    }

    #[test]
    fn search_finds_refs_beyond_first_page_and_escapes_paths() {
        let refs = refs();
        let picker = RefPicker::new(
            &refs,
            "main",
            &RepoUrls::new("realworld", "git"),
            RefPickerQuery { target: RefTarget::Blame, path: "src/a #.c".into(), q: " V1019 ".into(), ..Default::default() },
        );
        assert_eq!(picker.total, 1);
        assert_eq!(picker.rows[0].link.url, "/realworld/git/blame/refs/tags/v1019/src/a%20%23.c");
    }

    #[test]
    fn fragment_is_bounded_and_keeps_no_script_navigation() {
        let picker = RefPicker::new(&refs(), "main", &RepoUrls::new("realworld", "git"), RefPickerQuery::default());
        let html = RefPickerOptions { picker }.render().expect("render picker");
        assert_eq!(html.matches("data-ref-option").count(), PAGE_SIZE);
        assert!(html.contains("method=\"get\""));
        assert!(html.contains("page=2"));
        assert!(!html.contains("v1019"));
    }

    #[test]
    fn opens_on_the_current_kind_with_the_default_branch_first() {
        let mut references = refs();
        for name in ["feature", "main"] {
            references.push(RefSummary { name: name.into(), kind: RefKind::Branch, target: "b".repeat(40) });
        }
        let urls = RepoUrls::new("realworld", "git");
        let branches = RefPicker::new(&references, "main", &urls, RefPickerQuery { current: "feature".into(), ..Default::default() });
        assert_eq!(branches.kind, "branch");
        assert_eq!((branches.branch_count, branches.tag_count, branches.total), (2, 1020, 2));
        assert_eq!(branches.rows[0].link.name, "main", "the default branch leads");
        assert!(branches.rows[1].link.is_current);
        assert!(branches.tags_tab.options.contains("kind=tag"));
        assert_eq!(branches.view_all_url, "/realworld/git/branches");
        let html = RefPickerOptions { picker: branches }.render().unwrap();
        assert!(html.contains("View all branches") && html.contains("Find a branch"));

        let tags = RefPicker::new(&references, "main", &urls, RefPickerQuery { current: "refs/tags/v0001".into(), ..Default::default() });
        assert_eq!((tags.kind, tags.total), ("tag", 1020));
        assert_eq!(tags.view_all_url, "/realworld/git/tags");
        let found = RefPicker::new(
            &references,
            "main",
            &urls,
            RefPickerQuery { q: "feat".into(), kind: Some(RefTab::Branch), ..Default::default() },
        );
        assert_eq!(found.rows.iter().map(|row| row.link.name.as_str()).collect::<Vec<_>>(), ["feature"]);
    }

    #[test]
    fn closed_picker_keeps_counts_without_rendering_ref_links() {
        #[derive(Template)]
        #[template(path = "repo/ref_switcher.html")]
        struct Menu {
            switcher: crate::views::repo::RefSwitcher,
        }
        let mut references = refs();
        references.push(RefSummary { name: "main".into(), kind: RefKind::Branch, target: "a".repeat(40) });
        let links = RefPickerLinks::new(&RepoUrls::new("realworld", "git"), &RefPickerQuery::default());
        let switcher = crate::views::repo::RefSwitcher::deferred(&references, "refs/tags/v1019", links);
        assert_eq!((switcher.branch_count, switcher.tag_count), (1, 1020));
        assert_eq!(switcher.current, "v1019");
        assert!(switcher.current_is_tag);
        let html = Menu { switcher }.render().unwrap();
        assert_eq!(html.matches("<a ").count(), 1);
        assert!(!html.contains("v0000"));
        assert!(html.contains("hx-disinherit=\"hx-target hx-swap\""));
    }
}
