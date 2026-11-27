use std::{
    env,
    ffi::{OsStr, OsString},
    io::{self, Read},
    path::{Path, PathBuf},
    process::ExitCode,
};

use howl::{
    HELP,
    channel::{Channel, MAX_MANIFEST_LEN},
    control_client, discovery_client,
    identity::{LocalIdentity, PeerCertificate, PeerTrust},
    mailbox_client,
    managed_acp::{Harness, HostClaude, HostCodex, HostGrok},
    node,
    observer::{ObserverProvider, Snapshot},
    workflow::{self, RunTurn},
};
use howl_envelope::AgentRole;

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    let args = env::args_os().skip(1).collect::<Vec<_>>();
    let result = match args.as_slice() {
        [] => {
            println!("{HELP}");
            Ok(())
        }
        [arg] if arg == "--help" || arg == "-h" => {
            println!("{HELP}");
            Ok(())
        }
        [arg] if arg == "--version" || arg == "-V" => {
            println!("howl {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        [group, action, state]
            if (group == "identity" && action == "show")
                || (group == "mesh" && action == "init") =>
        {
            show_identity(Path::new(state))
        }
        [group, action, state, certificate, fingerprint]
            if group == "peer" && action == "trust" =>
        {
            let Some(certificate) = certificate.to_str() else {
                return invalid_arguments();
            };
            let Some(fingerprint) = fingerprint.to_str() else {
                return invalid_arguments();
            };
            pin_peer(Path::new(state), certificate, fingerprint)
        }
        [group, action, state, peer_ids @ ..] if group == "channel" && action == "create" => {
            create_channel(Path::new(state), peer_ids)
        }
        [group, action, state, manifest] if group == "channel" && action == "join" => {
            let Some(manifest) = manifest.to_str() else {
                return invalid_arguments();
            };
            join_channel(Path::new(state), manifest)
        }
        [group, action, state, listen, relay @ ..]
            if group == "mesh" && action == "run" && relay.len() <= 1 =>
        {
            let Some(listen) = listen.to_str() else {
                return invalid_arguments();
            };
            let relay = match relay.first() {
                Some(value) => {
                    let Some(value) = value.to_str() else {
                        return invalid_arguments();
                    };
                    Some(value)
                }
                None => None,
            };
            node::run(Path::new(state), listen, relay).await
        }
        [group, command, action, state, recipient, cursor @ ..]
            if group == "mesh"
                && command == "mailbox"
                && action == "deposit"
                && cursor.len() <= 1 =>
        {
            mailbox_deposit(state, recipient, cursor.first()).await
        }
        [group, command, action, state]
            if group == "mesh" && command == "mailbox" && action == "fetch" =>
        {
            mailbox_client::pull(Path::new(state))
                .await
                .and_then(|report| {
                    println!(
                        "Mailbox stored {} and acknowledged {} message(s).",
                        report.stored, report.acknowledged,
                    );
                    if report.unacknowledged == 0 {
                        Ok(())
                    } else {
                        Err(io::Error::other(format!(
                            "{} mailbox message(s) could not be admitted locally",
                            report.unacknowledged,
                        )))
                    }
                })
        }
        [group, command, action, state, address]
            if group == "mesh" && command == "hint" && action == "export" =>
        {
            required_text(address)
                .and_then(|address| address.parse().map_err(io::Error::other))
                .and_then(|address| node::export_hint(Path::new(state), address))
                .map(|hint| println!("{hint}"))
        }
        [group, command, action, state, hint]
            if group == "mesh" && command == "hint" && action == "import" =>
        {
            required_text(hint).and_then(|hint| node::import_hint(Path::new(state), hint))
        }
        [group, command, action, state, address]
            if group == "mesh" && command == "hint" && action == "publish" =>
        {
            match required_text(address)
                .and_then(|address| address.parse().map_err(io::Error::other))
            {
                Ok(address) => discovery_client::publish(Path::new(state), address).await,
                Err(error) => Err(error),
            }
        }
        [group, command, action, state, peer]
            if group == "mesh" && command == "hint" && action == "fetch" =>
        {
            match parse_id(peer) {
                Ok(peer) => discovery_client::fetch(Path::new(state), peer).await,
                Err(error) => Err(error),
            }
        }
        [group, action, state] if group == "mesh" && action == "stop" => {
            node::stop(Path::new(state)).await
        }
        [group, command, state] if group == "control" && command == "login" => {
            control_client::login(Path::new(state)).await
        }
        [group, command, state, authority, designation, certificate]
            if group == "control" && command == "enroll" =>
        {
            control_client::enroll(
                Path::new(state),
                Path::new(authority),
                Path::new(designation),
                Path::new(certificate),
            )
            .await
        }
        [group, command @ ..] if group == "enrollment" => howl::enrollment::cli::run(command),
        [group, command @ ..] if group == "workflow" => workflow_command(command).await,
        [group, command @ ..] if group == "roster" => howl::enrollment::roster_cli::run(command),
        [command, state, channel, peer, route] if command == "send" => {
            let (Ok(channel), Ok(peer), Some(route)) =
                (parse_id(channel), parse_id(peer), route.to_str())
            else {
                return invalid_arguments();
            };
            let mut message = String::new();
            match io::stdin()
                .take((node::CHAT_LIMIT + 1) as u64)
                .read_to_string(&mut message)
            {
                Ok(_) => node::send(Path::new(state), channel, peer, route, &message)
                    .await
                    .map(|receipt| println!("{receipt}")),
                Err(error) => Err(error),
            }
        }
        [command, state, channel] if command == "read" => {
            parse_id(channel).and_then(|channel| node::read(Path::new(state), channel))
        }
        [command, state, channel, message] if command == "status" => {
            parse_id(channel).and_then(|channel| {
                parse_id(message)
                    .and_then(|message| node::status(Path::new(state), channel, message))
            })
        }
        _ => return invalid_arguments(),
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("howl: {error}");
            ExitCode::FAILURE
        }
    }
}

async fn mailbox_deposit(
    state: &OsStr,
    recipient: &OsStr,
    cursor: Option<&OsString>,
) -> io::Result<()> {
    let recipient = parse_id(recipient)?;
    let after = match cursor {
        Some(cursor) => required_text(cursor)?
            .parse::<i64>()
            .map_err(|_| invalid_input("invalid mailbox cursor"))?,
        None => 0,
    };
    let report = mailbox_client::deposit(Path::new(state), recipient, after).await?;
    println!(
        "Mailbox deposited {}, previously accepted {}, and skipped {} message(s).",
        report.stored, report.already_stored, report.skipped,
    );
    if let Some(next) = report.next {
        println!("More retained messages after mailbox cursor {next}.");
    }
    Ok(())
}

async fn workflow_command(args: &[OsString]) -> io::Result<()> {
    match args {
        [command, state, role] if command == "id" => {
            let id = workflow::agent_id(Path::new(state), parse_role(role)?)?;
            println!("{}", hex::encode(id));
        }
        [command, state, channel, sender, role, generation] if command == "grant" => {
            let state = Path::new(state);
            let channel = parse_id(channel)?;
            let sender = parse_id(sender)?;
            let target = workflow::agent_id(state, parse_role(role)?)?;
            let generation = required_text(generation)?
                .parse::<u64>()
                .ok()
                .filter(|generation| *generation > 0)
                .ok_or_else(|| invalid_input("grant generation must be a positive integer"))?;
            node::grant_wake(state, channel, sender, target, generation).await?;
            println!("Wake grant installed for {}.", hex::encode(target));
        }
        [command, state, channel, peer, route, target, lifetime] if command == "wake" => {
            let channel = parse_id(channel)?;
            let peer = parse_id(peer)?;
            let route = required_text(route)?;
            let target = parse_id(target)?;
            let lifetime = required_text(lifetime)?
                .parse::<u16>()
                .ok()
                .filter(|lifetime| *lifetime > 0)
                .ok_or_else(|| {
                    invalid_input("wake lifetime must be a positive number of seconds")
                })?;
            let mut text = String::new();
            io::stdin()
                .take((node::WAKE_LIMIT + 1) as u64)
                .read_to_string(&mut text)?;
            if text.len() > node::WAKE_LIMIT {
                return Err(invalid_input("wake text is too large"));
            }
            let receipt = node::send_wake(
                Path::new(state),
                channel,
                peer,
                route,
                target,
                lifetime,
                &text,
            )
            .await?;
            println!("{receipt}");
        }
        [command, state, channel, role] if command == "next" => {
            let job = workflow::claim(Path::new(state), parse_id(channel)?, parse_role(role)?)?;
            if let Some(job) = job {
                println!("Execution {}", hex::encode(job.claim.execution));
                println!("Sender {}", hex::encode(job.claim.stream.sender.device));
                println!("Source {}", hex::encode(job.claim.message));
                println!("Expires {}", job.claim.expires_at);
                println!("Preview {}", serde_json::to_string(&job.text)?);
            } else {
                println!("No pending wakes.");
            }
        }
        [command, state] if command == "recover" => {
            let count = workflow::recover(Path::new(state))?;
            println!("Recovered {count} interrupted workflow jobs.");
        }
        [command, options @ ..] if command == "run" => run_workflow(options).await?,
        _ => return Err(invalid_input("invalid workflow arguments; run howl --help")),
    }
    Ok(())
}

async fn run_workflow(args: &[OsString]) -> io::Result<()> {
    let [
        state,
        channel,
        role,
        execution,
        route,
        driver,
        repo,
        commit,
        image,
        options @ ..,
    ] = args
    else {
        return Err(invalid_input(
            "invalid workflow run arguments; run howl --help",
        ));
    };
    let separator = options
        .iter()
        .position(|arg| arg == "--")
        .ok_or_else(|| invalid_input("select at least one snapshot path after --"))?;
    let (flags, paths) = options.split_at(separator);
    let paths = paths[1..].iter().map(PathBuf::from).collect::<Vec<_>>();
    if paths.is_empty() {
        return Err(invalid_input("select at least one snapshot path after --"));
    }
    let mut context = Vec::new();
    let mut cause = None;
    for option in flags.chunks(2) {
        match option {
            [flag, message] if flag == "--context" => context.push(parse_id(message)?),
            [flag, turn] if flag == "--cause" && cause.is_none() => cause = Some(parse_id(turn)?),
            _ => return Err(invalid_input("invalid workflow context or cause")),
        }
    }
    let request = RunTurn {
        state: Path::new(state),
        channel: parse_id(channel)?,
        role: parse_role(role)?,
        execution: parse_id(execution)?,
        route: required_text(route)?,
        context: &context,
        cause,
    };
    let driver = required_text(driver)?;
    let harness = host_harness(driver, required_text(image)?.to_owned())?;
    let snapshot = Snapshot::from_commit(Path::new(repo), required_text(commit)?, &paths)
        .map_err(io::Error::other)?;
    let observer = ObserverProvider::connect(&configured_path("HOWL_OBSERVER_DOCKER_SOCKET")?)
        .map_err(io::Error::other)?;
    eprintln!(
        "The signed-in {driver} agent may send selected repository files, the wake text, and supplied context to its model provider. Its reply will be shared in the channel."
    );
    let reply = workflow::run_turn(request, &observer, snapshot, harness).await?;
    println!("Execution {}", hex::encode(reply.execution));
    println!("Turn {}", hex::encode(reply.turn));
    println!("Message {}", serde_json::to_string(&reply.message)?);
    Ok(())
}

fn host_harness(driver: &str, image: String) -> io::Result<Harness> {
    let node = configured_path("HOWL_HOST_NODE")?;
    let harness = match driver {
        "claude" => Harness::host_claude(
            image,
            HostClaude::new(
                node,
                configured_path("HOWL_HOST_CLAUDE_ADAPTER")?,
                configured_path("HOWL_HOST_CLAUDE")?,
                configured_path("HOME")?,
            )
            .map_err(io::Error::other)?,
        ),
        "grok" => Harness::host_grok(
            image,
            HostGrok::new(
                node,
                configured_path("HOWL_HOST_GROK")?,
                configured_path("HOWL_HOST_GROK_AUTH_PATH")?,
            )
            .map_err(io::Error::other)?,
        ),
        "codex" => {
            let mut codex = HostCodex::new(
                node,
                configured_path("HOWL_HOST_CODEX")?,
                configured_path("HOME")?,
            )
            .map_err(io::Error::other)?;
            if let Some(path) = env::var_os("CODEX_HOME") {
                codex = codex
                    .with_state_home(path.into())
                    .map_err(io::Error::other)?;
            }
            Harness::host_codex(image, codex)
        }
        _ => return Err(invalid_input("driver must be claude, grok, or codex")),
    };
    Ok(harness)
}

fn parse_role(value: &OsStr) -> io::Result<AgentRole> {
    match value.to_str() {
        Some("architect") => Ok(AgentRole::Architect),
        Some("reviewer") => Ok(AgentRole::Reviewer),
        _ => Err(invalid_input("role must be architect or reviewer")),
    }
}

fn configured_path(name: &str) -> io::Result<PathBuf> {
    env::var_os(name)
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
        .ok_or_else(|| invalid_input(format!("set {name} to an absolute path")))
}

fn required_text(value: &OsStr) -> io::Result<&str> {
    value
        .to_str()
        .ok_or_else(|| invalid_input("expected UTF-8 argument"))
}

fn invalid_input(message: impl Into<Box<dyn std::error::Error + Send + Sync>>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

fn show_identity(state: &Path) -> io::Result<()> {
    let certificate = LocalIdentity::load_or_create(state)?.certificate();
    println!("Certificate {}", hex::encode(certificate.as_bytes()));
    println!("Fingerprint {}", hex::encode(certificate.fingerprint()));
    println!("Device {}", hex::encode(certificate.device_id()));
    Ok(())
}

fn pin_peer(state: &Path, certificate: &str, fingerprint: &str) -> io::Result<()> {
    let mut bytes = [0; howl::identity::CERTIFICATE_LEN];
    let mut confirmed = [0; 32];
    hex::decode_to_slice(certificate, &mut bytes)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid certificate hex"))?;
    hex::decode_to_slice(fingerprint, &mut confirmed)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid fingerprint hex"))?;
    let certificate = PeerCertificate::from_bytes(bytes)?;
    PeerTrust::open(state)?.pin(&certificate, &confirmed)?;
    println!("Peer trusted.");
    Ok(())
}

fn create_channel(state: &Path, peers: &[OsString]) -> io::Result<()> {
    let peers = peers
        .iter()
        .map(|peer| {
            let mut id = [0; 32];
            hex::decode_to_slice(peer.as_encoded_bytes(), &mut id).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidInput, "invalid member device ID")
            })?;
            Ok(id)
        })
        .collect::<io::Result<Vec<_>>>()?;
    let identity = LocalIdentity::load_or_create(state)?;
    let channel = Channel::create(state, &identity, &peers)?;
    println!("Channel {}", hex::encode(channel.id()));
    println!("Manifest {}", hex::encode(channel.manifest()));
    Ok(())
}

fn join_channel(state: &Path, manifest: &str) -> io::Result<()> {
    if manifest.len() > MAX_MANIFEST_LEN * 2 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "channel manifest is too large",
        ));
    }
    let manifest = hex::decode(manifest)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid channel manifest hex"))?;
    let identity = LocalIdentity::load_or_create(state)?;
    let channel = Channel::join(state, &identity, &manifest)?;
    println!("Channel {}", hex::encode(channel.id()));
    Ok(())
}

fn parse_id(value: &OsStr) -> io::Result<[u8; 32]> {
    let mut id = [0; 32];
    hex::decode_to_slice(value.as_encoded_bytes(), &mut id)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid hex ID"))?;
    Ok(id)
}

fn invalid_arguments() -> ExitCode {
    eprintln!("Invalid arguments. Run howl --help.");
    ExitCode::from(2)
}
