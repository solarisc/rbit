//! "Go to file": every file of a revision, ranked against what the visitor types. The
//! code page's box asks for the [fragment](FindResults) as they type; without scripts it
//! submits to the [page](FindPage).

use askama::Template;
use askama_web::WebTemplate;

use crate::{
    urls::RepoUrls,
    views::{layout::Page, pagination::Pagination, repo::RepoHeader},
};

/// Rows the code page's dropdown shows; the page lists the rest.
pub const DROPDOWN_ROWS: usize = 12;

/// One matching file: the folder part muted, the name emphasised.
#[derive(Debug, Clone)]
pub struct FoundFile {
    pub path: String,
    /// The folder, with a trailing `/`, or empty at the root.
    pub folder: String,
    pub name: String,
    pub url: String,
}

impl FoundFile {
    pub fn new(path: &str, urls: &RepoUrls, revision: &str) -> Self {
        let (folder, name) = path.rsplit_once('/').map_or(("", path), |(folder, name)| (folder, name));
        Self {
            path: path.to_owned(),
            folder: if folder.is_empty() { String::new() } else { format!("{folder}/") },
            name: name.to_owned(),
            url: urls.blob(revision, path),
        }
    }
}

/// How well `path` matches `query`, higher is better; `None` when the query's characters
/// do not all appear in order. Both are compared lowercase, ignoring spaces in the query.
/// A match inside the file name beats one elsewhere in the path, a contiguous match beats
/// a scattered one, and shorter paths win ties.
pub fn score(path: &str, query: &str) -> Option<i64> {
    let path = path.to_lowercase();
    let query: String = query.chars().filter(|c| !c.is_whitespace()).flat_map(char::to_lowercase).collect();
    if query.is_empty() {
        return Some(0);
    }
    let length = i64::try_from(path.chars().count()).unwrap_or(i64::MAX / 4);
    let name_start = path.rfind('/').map_or(0, |index| index + 1);
    if let Some(at) = path[name_start..].find(&query) {
        let at = i64::try_from(at).unwrap_or(0);
        return Some(30_000 - at * 10 - length);
    }
    if let Some(at) = path.find(&query) {
        let at = i64::try_from(at).unwrap_or(0);
        return Some(20_000 - at - length);
    }
    let mut wanted = query.chars().peekable();
    let mut total = 10_000 - length;
    let mut previous = '/';
    let mut run = false;
    for current in path.chars() {
        let Some(&next) = wanted.peek() else { break };
        if next == current {
            wanted.next();
            if run {
                total += 15;
            }
            if matches!(previous, '/' | '_' | '-' | '.' | ' ') {
                total += 10;
            }
            run = true;
        } else {
            run = false;
        }
        previous = current;
    }
    wanted.peek().is_none().then_some(total)
}

/// The paths matching `query`, best first (then by path).
pub fn rank<'a>(paths: &'a [String], query: &str) -> Vec<&'a str> {
    let mut found: Vec<(i64, &str)> = paths.iter().filter_map(|path| score(path, query).map(|score| (score, path.as_str()))).collect();
    found.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.cmp(b.1)));
    found.into_iter().map(|(_, path)| path).collect()
}

/// The dropdown under the code page's "Go to file" box.
#[derive(Debug, Template, WebTemplate)]
#[template(path = "repo/find_results.html")]
pub struct FindResults {
    pub query: String,
    pub rows: Vec<FoundFile>,
    pub total: usize,
    /// The full finder page for this query.
    pub page_url: String,
}

/// `/{owner}/{repo}/find/{revision}`: the finder without scripts, and "see all matches".
#[derive(Debug, Template, WebTemplate)]
#[template(path = "repo/find.html")]
pub struct FindPage {
    pub page: Page,
    pub header: RepoHeader,
    /// The branch, tag or commit searched, as the visitor named it.
    pub revision: String,
    pub tree_url: String,
    pub action: String,
    pub query: String,
    pub rows: Vec<FoundFile>,
    pub pagination: Pagination,
    /// The repository has more files than the finder reads.
    pub truncated: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn paths() -> Vec<String> {
        ["README.md", "crates/rbit-web/src/views/find.rs", "crates/rbit-web/templates/repo/find.html", "docs/guide.md", "src/main.rs"]
            .map(String::from)
            .to_vec()
    }

    #[test]
    fn file_names_rank_above_folders_and_scattered_matches() {
        let paths = paths();
        assert_eq!(rank(&paths, "find")[..2], ["crates/rbit-web/src/views/find.rs", "crates/rbit-web/templates/repo/find.html"]);
        assert_eq!(rank(&paths, "main")[0], "src/main.rs");
        // A subsequence across the path still matches; spaces and case are ignored.
        assert_eq!(rank(&paths, "Doc GD"), ["docs/guide.md"]);
        assert_eq!(rank(&paths, "zzz"), Vec::<&str>::new());
        assert_eq!(rank(&paths, "").len(), paths.len());
    }

    #[test]
    fn rows_split_folder_and_name() {
        let urls = RepoUrls::new("alice", "demo");
        let row = FoundFile::new("src/net/client.rs", &urls, "feature/login");
        assert_eq!((row.folder.as_str(), row.name.as_str()), ("src/net/", "client.rs"));
        assert_eq!(row.url, "/alice/demo/blob/feature/login/src/net/client.rs");
        let root = FoundFile::new("README.md", &urls, "main");
        assert_eq!((root.folder.as_str(), root.name.as_str()), ("", "README.md"));
    }

    #[test]
    fn dropdown_escapes_and_links_to_every_match() {
        let urls = RepoUrls::new("alice", "demo");
        let html = FindResults {
            query: "<b>".into(),
            rows: vec![FoundFile::new("a/<b>.rs", &urls, "main")],
            total: 30,
            page_url: "/alice/demo/find/main?q=%3Cb%3E".into(),
        }
        .render()
        .unwrap();
        assert!(!html.contains("<b>.rs"));
        assert!(html.contains("&#60;b&#62;.rs") || html.contains("&lt;b&gt;.rs"), "{html}");
        assert!(html.contains("See all 30 files"));
    }
}
