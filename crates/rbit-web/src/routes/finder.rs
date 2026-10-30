//! `GET /{owner}/{repo}/find/{revision}`: "Go to file", and the history length shown on
//! the code page. Both answers never change for a commit, so small in-memory caches keyed
//! by commit id keep typing in the finder from walking the tree on every keystroke.

use std::{
    collections::HashMap,
    sync::{Arc, LazyLock, Mutex, PoisonError},
};

use axum::{
    extract::{Path, Query, State},
    response::{IntoResponse, Response},
};
use rbit_git::RepositoryReader;
use rbit_services::ServiceError;
use serde::Deserialize;

use super::repo::RepoPage;
use crate::{
    AppState,
    error::WebResult,
    extract::Viewer,
    views::{
        find::{DROPDOWN_ROWS, FindPage, FindResults, FoundFile, rank},
        layout::Page,
        pagination::{ListQuery, Pagination},
    },
};

/// Files the finder reads at most; beyond it the repository is searched in part.
const MAX_PATHS: usize = 200_000;
/// File lists kept. Each is the paths of one commit; a large tree is a few megabytes.
const PATH_LISTS: usize = 6;
/// Histories counted at most, and commit counts remembered.
pub const MAX_COUNTED_COMMITS: usize = 1_000_000;
const COMMIT_COUNTS: usize = 4096;

type PathList = Arc<(Vec<String>, bool)>;

/// Most recently used last.
static PATHS: LazyLock<Mutex<Vec<(String, PathList)>>> = LazyLock::new(Mutex::default);
static COUNTS: LazyLock<Mutex<HashMap<String, (usize, bool)>>> = LazyLock::new(Mutex::default);

/// Every file path of `commit` (a resolved id), from the cache when it was read recently.
async fn paths_of(reader: &RepositoryReader, commit: &str) -> Result<PathList, ServiceError> {
    {
        let mut lists = PATHS.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(index) = lists.iter().position(|(id, _)| id == commit) {
            let entry = lists.remove(index);
            let list = Arc::clone(&entry.1);
            lists.push(entry);
            return Ok(list);
        }
    }
    let list = Arc::new(reader.file_paths(commit.to_owned(), MAX_PATHS).await?);
    let mut lists = PATHS.lock().unwrap_or_else(PoisonError::into_inner);
    if !lists.iter().any(|(id, _)| id == commit) {
        if lists.len() == PATH_LISTS {
            lists.remove(0);
        }
        lists.push((commit.to_owned(), Arc::clone(&list)));
    }
    Ok(list)
}

/// How many commits `commit` (a resolved id) has in its history, and whether that count
/// stopped at [`MAX_COUNTED_COMMITS`].
pub async fn commit_count(reader: &RepositoryReader, commit: &str) -> Result<(usize, bool), ServiceError> {
    if let Some(count) = COUNTS.lock().unwrap_or_else(PoisonError::into_inner).get(commit) {
        return Ok(*count);
    }
    let count = reader.commit_count(commit.to_owned(), MAX_COUNTED_COMMITS).await?;
    let mut counts = COUNTS.lock().unwrap_or_else(PoisonError::into_inner);
    if counts.len() >= COMMIT_COUNTS {
        counts.clear();
    }
    counts.insert(commit.to_owned(), count);
    Ok(count)
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct FindQuery {
    q: String,
    page: usize,
    /// Answer with the dropdown alone (the code page's box), not the whole page.
    fragment: bool,
}

pub async fn find(
    State(state): State<AppState>,
    viewer: Viewer,
    page: Page,
    Path((owner, repo, revision)): Path<(String, String, String)>,
    Query(query): Query<FindQuery>,
) -> WebResult<Response> {
    let loaded = RepoPage::load(&state, &viewer, &owner, &repo).await?;
    let reader = &loaded.ctx.reader;
    let commit = reader.commit_id(revision.clone()).await.map_err(ServiceError::from)?;
    let list = paths_of(reader, &commit).await?;
    let (paths, truncated) = (&list.0, list.1);
    let search = ListQuery { q: query.q.trim().chars().take(200).collect(), page: query.page };
    let ranked = rank(paths, &search.q);
    let urls = &loaded.urls;
    let action = urls.find(&revision);
    if query.fragment {
        let rows = ranked.iter().take(DROPDOWN_ROWS).map(|path| FoundFile::new(path, urls, &revision)).collect();
        let page_url = Pagination::new(ranked.len(), &search, action, vec![]).url(1);
        return Ok(FindResults { query: search.q, rows, total: ranked.len(), page_url }.into_response());
    }
    let pagination = Pagination::new(ranked.len(), &search, action.clone(), vec![]);
    let rows = ranked[pagination.start..pagination.end].iter().map(|path| FoundFile::new(path, urls, &revision)).collect();
    Ok(FindPage {
        page: page.titled(format!("Go to file · {}", loaded.ctx.repo.full_name())),
        header: loaded.header(&state, "code"),
        tree_url: urls.tree(&revision, ""),
        revision,
        action,
        query: search.q,
        rows,
        pagination,
        truncated,
    }
    .into_response())
}
