use std::{
    ffi::OsString,
    path::Path,
    process::{Output, Stdio},
    time::Duration,
};

use axum::{
    extract::Request,
    http::Method,
    middleware::{Next, from_fn},
};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    process::{Child, Command},
    time::{sleep, timeout},
};

use super::*;

struct Cli {
    binary: OsString,
    url: String,
}

impl Cli {
    fn command(&self, action: &[&str], state: &Path, args: &[&str]) -> Command {
        let mut cmd = Command::new(&self.binary);
        cmd.args(action)
            .arg(state)
            .args(args)
            .env("HOWL_CONTROL_URL", &self.url)
            .env_remove("HOWL_CONTROL_AUDIENCE")
            .env_remove("HOWL_CONTROL_ACCESS_TOKEN")
            .env_remove("HOWL_CONTROL_SESSION_ID")
            .kill_on_drop(true);
        cmd
    }

    async fn run(&self, action: &[&str], state: &Path, args: &[&str]) -> Output {
        timeout(
            Duration::from_secs(30),
            self.command(action, state, args).output(),
        )
        .await
        .expect("CLI command timed out")
        .unwrap()
    }

    async fn start_mesh(&self, state: &Path) -> Child {
        let mut node = self
            .command(&["mesh", "run"], state, &["-"])
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let mut output = BufReader::new(node.stdout.take().unwrap()).lines();
        timeout(Duration::from_secs(20), async {
            while let Some(line) = output.next_line().await.unwrap() {
                if line.starts_with("Ready ") {
                    return;
                }
            }
            panic!("mesh daemon exited before announcing readiness");
        })
        .await
        .unwrap();
        node
    }

    async fn send(&self, state: &Path, channel: &str, peer: &str, text: &str) -> Output {
        let mut sender = self
            .command(&["send"], state, &[channel, peer, "-"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        sender
            .stdin
            .take()
            .unwrap()
            .write_all(text.as_bytes())
            .await
            .unwrap();
        timeout(Duration::from_secs(10), sender.wait_with_output())
            .await
            .unwrap()
            .unwrap()
    }
}

#[track_caller]
fn success_text(output: Output) -> String {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap()
}

fn field<'a>(text: &'a str, prefix: &str) -> &'a str {
    text.lines()
        .find_map(|line| line.strip_prefix(prefix))
        .unwrap_or_else(|| panic!("missing {prefix} in {text}"))
}

#[tokio::test]
#[ignore = "requires disposable PostgreSQL roles and HOWL_TEST_CONTROL_CLI"]
async fn github_login_and_owner_approval_connect_two_devices_over_iroh() {
    let owner = pool("HOWL_TEST_CONTROL_DATABASE_OWNER");
    migrate(&owner).await.unwrap();
    let github_id = i64::from_be_bytes(crate::random().unwrap()[..8].try_into().unwrap())
        .saturating_abs()
        .max(1);
    let (_provider, upstream, github) = github_fixture(github_id, 2).await;
    let control = Arc::new(
        ControlPlane::new(
            pool("HOWL_TEST_CONTROL_DATABASE_RUNTIME"),
            github,
            AUDIENCE,
            Zeroizing::new([3; 32]),
        )
        .unwrap(),
    );
    let lookups = Arc::new(AtomicUsize::new(0));
    let observed = lookups.clone();
    let server = serve(
        control
            .router()
            .layer(from_fn(move |request: Request, next: Next| {
                let observed = observed.clone();
                async move {
                    let lookup = request.method() == Method::GET
                        && request.uri().path().starts_with("/v1/discovery/hints/");
                    let response = next.run(request).await;
                    if lookup && response.status().is_success() {
                        observed.fetch_add(1, Ordering::SeqCst);
                    }
                    response
                }
            })),
    )
    .await;
    let http = Client::new();
    let legacy_key = SigningKey::from_bytes(&[11; 32]);
    let login_url = format!("{}/v1/login/device", server.url);
    let begin = success(
        http.post(&login_url)
            .json(&json!({
                "device_id": hex::encode(DEVICE),
                "signing_key": hex::encode(legacy_key.verifying_key().to_bytes()),
            }))
            .send()
            .await
            .unwrap(),
    )
    .await;
    let login = string(&begin, "login");
    allow_poll(&owner, &proof::decode(login).unwrap()).await;
    let proof = sign(&legacy_key, login, "poll", string(&begin, "nonce"), None);
    let verified = success(
        http.post(format!("{login_url}/{login}/poll"))
            .json(&proof)
            .send()
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(verified["credentials"]["session"]["github_id"], github_id);
    assert!(
        owner
            .get()
            .await
            .unwrap()
            .query_opt(
                "SELECT founder FROM howl_control.networks WHERE github_id = $1",
                &[&github_id]
            )
            .await
            .unwrap()
            .is_none()
    );
    let cli = Cli {
        binary: std::env::var_os("HOWL_TEST_CONTROL_CLI").unwrap(),
        url: server.url.clone(),
    };
    let root = tempfile::tempdir().unwrap();
    let founder = root.path().join("founder");
    let candidate = root.path().join("candidate");
    let a = success_text(cli.run(&["control", "login"], &founder, &[]).await);
    let b = success_text(cli.run(&["control", "login"], &candidate, &[]).await);
    assert_eq!(upstream.revoked.load(Ordering::SeqCst), 3);
    assert_eq!(field(&a, "Membership "), "founder");
    assert_eq!(field(&b, "Membership "), "pending");
    let channel = field(&a, "Network ");
    let a_id = field(&a, "Device ");
    let b_id = field(&b, "Device ");
    assert_ne!(a_id, b_id);
    assert_eq!(field(&b, "Network "), channel);
    let lock = std::fs::File::open(founder.join("control-auth.lock")).unwrap();
    lock.try_lock().unwrap();
    let (pending, ()) = tokio::join!(cli.run(&["control", "devices"], &founder, &[]), async {
        sleep(Duration::from_millis(300)).await;
        drop(lock);
    });
    let pending = success_text(pending);
    assert_eq!(field(&pending, "Pending "), b_id);
    assert!(
        !cli.run(&["control", "approve"], &candidate, &[b_id])
            .await
            .status
            .success()
    );
    let mut a_node = cli.start_mesh(&founder).await;
    assert!(
        !cli.send(&founder, channel, b_id, "before approval")
            .await
            .status
            .success()
    );
    success_text(cli.run(&["control", "approve"], &founder, &[b_id]).await);
    let mut b_node = cli.start_mesh(&candidate).await;
    let sent = success_text(
        cli.send(&candidate, channel, a_id, "approved over iroh")
            .await,
    );
    let receipt = field(&sent, "queued ");
    timeout(Duration::from_secs(40), async {
        loop {
            let report = success_text(cli.run(&["status"], &candidate, &[channel, receipt]).await);
            if report.contains(" delivered ") {
                break;
            }
            sleep(Duration::from_millis(200)).await;
        }
    })
    .await
    .expect("no signed delivery acknowledgment from the founder");
    assert!(lookups.load(Ordering::SeqCst) > 0);
    let received = success_text(cli.run(&["read"], &founder, &[channel]).await);
    assert!(received.contains("approved over iroh"));
    assert!(!received.contains("before approval"));
    for (state, mesh) in [(&founder, &mut a_node), (&candidate, &mut b_node)] {
        success_text(cli.run(&["mesh", "stop"], state, &[]).await);
        assert!(
            timeout(Duration::from_secs(10), mesh.wait())
                .await
                .unwrap()
                .unwrap()
                .success()
        );
    }
}
