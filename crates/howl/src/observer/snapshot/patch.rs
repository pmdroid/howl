use super::*;

impl Snapshot {
    pub fn verify_worker_patch(&self, run: &str, patch: &[u8]) -> Result<Vec<u8>> {
        if patch.is_empty() {
            return Ok(Vec::new());
        }
        let text = str::from_utf8(patch).map_err(|_| Error::InvalidSnapshot)?;
        if run.is_empty()
            || run.len() > 64
            || !run
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
            || patch.len() > crate::microvm::PATCH_LIMIT
            || text.contains('\0')
            || text.lines().any(|line| line == "GIT binary patch")
        {
            return Err(Error::InvalidSnapshot);
        }
        let index = tempfile::tempdir_in(self.directory.path())?;
        let root = index.path();
        let objects = {
            let mut locate = git(&self.repository);
            locate.args([
                "rev-parse",
                "--path-format=absolute",
                "--git-path",
                "objects",
            ]);
            run_git(locate)?
        };
        let path = objects.strip_suffix(b"\n").ok_or(Error::InvalidSnapshot)?;
        if !path.starts_with(b"/") || path.contains(&b'\n') || path.contains(&b'\r') {
            return Err(Error::InvalidSnapshot);
        }
        let format = if self.commit.len() == 64 {
            "--object-format=sha256"
        } else {
            "--object-format=sha1"
        };
        let mut init = git(root);
        init.args(["init", "--quiet", "--template=", format]);
        run_git(init)?;
        fs::write(root.join(".git/objects/info/alternates"), objects)?;
        let tree = self.directory.path().join("tree");
        let mut stage = git(root);
        stage
            .arg("--work-tree")
            .arg(&tree)
            .args(["add", "--force", "--all"]);
        run_git(stage)?;
        let verify = |args: &[&str]| {
            let output = git(root).args(args).stderr(Stdio::null()).output()?;
            if output.status.success() {
                Ok(output.stdout)
            } else {
                Err(process_error("verify worker patch", output.status))
            }
        };
        let base = verify(&["write-tree"])?;
        let base = str::from_utf8(&base)
            .map_err(|_| Error::InvalidSnapshot)?
            .trim();
        let input = root.join("worker.patch");
        fs::write(&input, patch)?;
        verify(&[
            "apply",
            "--cached",
            "--whitespace=nowarn",
            "--",
            "worker.patch",
        ])?;
        let updated = verify(&["write-tree"])?;
        let updated = str::from_utf8(&updated)
            .map_err(|_| Error::InvalidSnapshot)?
            .trim();
        let entries = verify(&["ls-tree", "-r", "-l", "-z", updated])?;
        validate_files(&entries)?;
        let canonical = verify(&[
            "diff",
            "--cached",
            "--full-index",
            "--no-renames",
            "--no-ext-diff",
            "--no-textconv",
            base,
            "--",
        ])?;
        if canonical.is_empty() {
            return Err(Error::InvalidSnapshot);
        }
        fs::write(&input, &canonical)?;
        verify(&["read-tree", &self.commit])?;
        verify(&[
            "apply",
            "--cached",
            "--check",
            "--whitespace=nowarn",
            "--",
            "worker.patch",
        ])?;
        let mut artifact = format!(
            "Howl-Run: {run}\nHowl-Base-Commit: {}\nHowl-Snapshot: {}\n\n",
            self.commit,
            hex::encode(self.selection)
        )
        .into_bytes();
        if artifact.len() + canonical.len() > crate::microvm::PATCH_LIMIT {
            return Err(Error::InvalidSnapshot);
        }
        artifact.extend(canonical);
        Ok(artifact)
    }
}

fn validate_files(entries: &[u8]) -> Result<()> {
    let mut total = 0usize;
    for (index, entry) in entries
        .split(|byte| *byte == 0)
        .filter(|entry| !entry.is_empty())
        .enumerate()
    {
        let (header, path) = str::from_utf8(entry)
            .ok()
            .and_then(|entry| entry.split_once('\t'))
            .ok_or(Error::InvalidSnapshot)?;
        let mut fields = header.split_whitespace();
        if !matches!(fields.next(), Some("100644" | "100755"))
            || fields.next() != Some("blob")
            || index >= MAX_REPOSITORY_PATHS
        {
            return Err(Error::UnsafePath(path.into()));
        }
        selected_path(Path::new(path))?;
        let size = fields
            .nth(1)
            .and_then(|field| field.parse::<usize>().ok())
            .filter(|size| *size <= MAX_FILE)
            .ok_or(Error::InvalidSnapshot)?;
        total += size;
        if total > MAX_SNAPSHOT {
            return Err(Error::InvalidSnapshot);
        }
    }
    Ok(())
}
