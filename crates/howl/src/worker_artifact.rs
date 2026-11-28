use std::{
    io::{self, Write},
    path::Path,
};

use sha2::{Digest, Sha256};

use crate::{identity::StateDirectory, microvm::PATCH_LIMIT, observer::Snapshot};

pub fn inspect(state: &Path, repository: &Path, run: &str) -> io::Result<()> {
    if !hex_id(run, &[32, 64]) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid worker run ID",
        ));
    }
    let bytes = StateDirectory::open(&state.join("worker-patches"))?
        .read_bounded(&format!("{run}.patch"), PATCH_LIMIT as u64)?;
    let artifact = std::str::from_utf8(&bytes).map_err(io::Error::other)?;
    let (base, patch) = parse(artifact, run).ok_or_else(invalid_artifact)?;
    let snapshot = Snapshot::from_repository(repository, base).map_err(io::Error::other)?;
    let canonical = snapshot
        .verify_worker_patch(run, patch.as_bytes())
        .map_err(io::Error::other)?;
    if canonical != bytes {
        return Err(invalid_artifact());
    }
    let repo = snapshot.repository();
    let mut digest = Sha256::new();
    digest.update(b"howl/worker-operation/apply/v1\0");
    let target = repo.as_os_str().as_encoded_bytes();
    digest.update((target.len() as u64).to_be_bytes());
    digest.update(target);
    digest.update(Sha256::digest(&bytes));
    let mut output = io::stdout().lock();
    writeln!(output, "Run {run}")?;
    writeln!(
        output,
        "Repository {}",
        terminal_text(&repo.to_string_lossy())
    )?;
    writeln!(output, "Base commit {base}")?;
    writeln!(output, "Apply operation {}", hex::encode(digest.finalize()))?;
    write!(output, "\n{}", terminal_text(patch))
}

fn parse<'a>(artifact: &'a str, run: &str) -> Option<(&'a str, &'a str)> {
    let (header, patch) = artifact.split_once("\n\n")?;
    let mut lines = header.split('\n');
    let artifact_run = lines.next()?.strip_prefix("Howl-Run: ")?;
    let base = lines.next()?.strip_prefix("Howl-Base-Commit: ")?;
    let snapshot = lines.next()?.strip_prefix("Howl-Snapshot: ")?;
    (artifact_run == run
        && hex_id(base, &[40, 64])
        && hex_id(snapshot, &[64])
        && lines.next().is_none()
        && !patch.is_empty())
    .then_some((base, patch))
}

fn hex_id(value: &str, lengths: &[usize]) -> bool {
    lengths.contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn invalid_artifact() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "worker artifact does not match its pinned snapshot",
    )
}

fn terminal_text(text: &str) -> String {
    let mut visible = String::with_capacity(text.len());
    for character in text.chars() {
        match character {
            '\n' | '\t' => visible.push(character),
            c if c.is_control()
                || matches!(c, '\u{061c}' | '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}') =>
            {
                visible.extend(c.escape_default());
            }
            c => visible.push(c),
        }
    }
    visible
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn review_rejects_mismatched_or_malformed_artifact_headers() {
        let run = "a".repeat(32);
        let base = "b".repeat(40);
        let snapshot = "c".repeat(64);
        let raw = format!(
            "Howl-Run: {run}\nHowl-Base-Commit: {base}\nHowl-Snapshot: {snapshot}\n\nPatch\n"
        );
        assert_eq!(parse(&raw, &run), Some((base.as_str(), "Patch\n")));
        assert!(parse(&raw, &"f".repeat(32)).is_none());
        assert!(parse(&raw.replace(&base, "HEAD"), &run).is_none());
        assert!(parse(&raw.replace("Patch\n", ""), &run).is_none());
    }

    #[test]
    fn review_displays_escape_sequences_as_text() {
        assert_eq!(
            terminal_text("+\u{1b}[1A\u{202e}text\n"),
            "+\\u{1b}[1A\\u{202e}text\n"
        );
    }
}
