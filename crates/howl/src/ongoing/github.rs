use std::{io, time::Duration};

use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize)]
pub(super) struct PullRequest {
    number: u64,
    title: String,
}

pub(super) fn valid_repository(repository: &str) -> bool {
    let Some((owner, name)) = repository.split_once('/') else {
        return false;
    };
    !owner.is_empty()
        && owner.len() <= 39
        && owner
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        && !matches!(name, "" | "." | "..")
        && name.len() <= 100
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
}

pub(super) async fn open_pulls(repository: &str) -> io::Result<Vec<PullRequest>> {
    let client = reqwest::Client::builder()
        .user_agent("howl-agent-mesh")
        .timeout(Duration::from_secs(12))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(io::Error::other)?;
    let url = format!("https://api.github.com/repos/{repository}/pulls?state=open&per_page=5");
    let mut response = client
        .get(url)
        .send()
        .await
        .map_err(io::Error::other)?
        .error_for_status()
        .map_err(io::Error::other)?;
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(io::Error::other)? {
        if bytes.len() + chunk.len() > 1024 * 1024 {
            return Err(io::Error::other(
                "GitHub pull request response exceeds limit",
            ));
        }
        bytes.extend_from_slice(&chunk);
    }
    let pulls: Vec<PullRequest> = serde_json::from_slice(&bytes)?;
    if pulls.len() > 5 || pulls.iter().any(|pr| pr.title.len() > 4096) {
        return Err(io::Error::other("invalid GitHub pull request list"));
    }
    Ok(pulls)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schedule_accepts_only_a_github_owner_and_repository() {
        assert!(valid_repository("pallets/click"));
        assert!(valid_repository("example-org/project.rs"));
        for name in [
            "pallets/..",
            "pallets/",
            "/click",
            "https://example.org/repo",
            "a/b/c",
            "a/b?q=1",
        ] {
            assert!(!valid_repository(name));
        }
    }
}
