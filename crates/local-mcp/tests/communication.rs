use howl_local_mcp::{
    Agent, AgentKind, AgentPrincipal, Authority, Call, Channel, ChannelArgs, Client,
    Communications, Credential, Daemon, DirectArgs, Empty, Failure, Message, PostArgs, ReadArgs,
    Reply, Scope, Tool,
};
use serde_json::{Value, json};
use std::{
    io,
    os::unix::fs::PermissionsExt,
    path::PathBuf,
    process::Stdio,
    sync::{Arc, Mutex},
    time::Duration,
};
use tempfile::TempDir;
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    net::UnixStream,
    process::Command,
    task::JoinHandle,
    time::timeout,
};

type Calls = Arc<Mutex<Vec<(AgentPrincipal, Call)>>>;

struct Fixture {
    directory: TempDir,
    socket: PathBuf,
    authority: Authority,
    server: JoinHandle<io::Result<()>>,
    calls: Calls,
}

impl Fixture {
    fn start() -> Self {
        let directory = tempfile::tempdir_in("/tmp").unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let socket = directory.path().join("mesh.sock");
        let calls = Arc::new(Mutex::new(Vec::new()));
        let (daemon, authority) = Daemon::bind(&socket, Fake(calls.clone())).unwrap();
        let server = tokio::spawn(daemon.serve());
        authority.activate_session("session", 1).unwrap();
        Self {
            directory,
            socket,
            authority,
            server,
            calls,
        }
    }

    fn issue(&self, principal: AgentPrincipal, tools: &[Tool]) -> Credential {
        let scope = Scope {
            tools: tools.iter().copied().collect(),
            channels: [
                (Tool::ListChannels, ["general".to_owned()].into()),
                (Tool::Post, ["general".to_owned()].into()),
                (
                    Tool::Read,
                    ["general".to_owned(), "visible-read-only".to_owned()].into(),
                ),
                (Tool::Pass, ["general".to_owned()].into()),
            ]
            .into(),
            agents: [
                (Tool::ListAgents, ["bob".to_owned()].into()),
                (Tool::Dm, ["bob".to_owned()].into()),
            ]
            .into(),
        };
        self.authority.issue(principal, scope).unwrap()
    }

    fn client(&self, credential: Credential) -> Client {
        Client::new(&self.socket, credential)
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.server.abort();
    }
}

struct Fake(Calls);

impl Communications for Fake {
    fn invoke(&mut self, caller: &AgentPrincipal, call: &Call) -> Result<Reply, Failure> {
        self.0.lock().unwrap().push((caller.clone(), call.clone()));
        Ok(match call {
            Call::ListAgents(_) => Reply::Agents {
                agents: ["bob", "hidden"]
                    .map(|id| Agent {
                        id: id.into(),
                        name: id.into(),
                    })
                    .to_vec(),
            },
            Call::ListChannels(_) => Reply::Channels {
                channels: ["general", "private"]
                    .map(|id| Channel {
                        id: id.into(),
                        name: id.into(),
                    })
                    .to_vec(),
            },
            Call::Read(_) => Reply::Messages {
                messages: ["private", "general", "general"]
                    .map(|id| Message {
                        channel: id.into(),
                        sender: "bob".into(),
                        text: "hello".into(),
                    })
                    .to_vec(),
            },
            Call::Post(_) | Call::Dm(_) => Reply::Posted {
                id: "receipt".into(),
            },
            Call::Pass(_) => Reply::Passed,
            Call::Status(_) => panic!("status must come from the daemon credential"),
        })
    }
}

fn principal(agent: &str, kind: AgentKind, generation: u64) -> AgentPrincipal {
    AgentPrincipal {
        agent: agent.into(),
        session: "session".into(),
        generation,
        kind,
    }
}

fn post(channel: &str) -> Call {
    Call::Post(PostArgs {
        channel: channel.into(),
        text: "hello".into(),
    })
}

#[tokio::test]
async fn checks_scope_and_uses_daemon_issued_identity_for_managed_and_external_agents() {
    let fixture = Fixture::start();
    let managed = principal("alice", AgentKind::Managed, 1);
    let managed_token = fixture.issue(
        managed.clone(),
        &[
            Tool::ListAgents,
            Tool::ListChannels,
            Tool::Read,
            Tool::Dm,
            Tool::Post,
            Tool::Pass,
            Tool::Status,
        ],
    );
    let client = fixture.client(managed_token);
    let slow = UnixStream::connect(&fixture.socket).await.unwrap();
    assert_eq!(
        timeout(Duration::from_secs(2), client.call(Call::Status(Empty {})))
            .await
            .unwrap(),
        Ok(Reply::Status {
            principal: managed.clone()
        })
    );
    drop(slow);
    assert_eq!(client.call(post("private")).await, Err(Failure::Denied));
    assert_eq!(
        client.call(post("visible-read-only")).await,
        Err(Failure::Denied)
    );
    assert_eq!(
        client
            .call(Call::Read(ReadArgs {
                channel: "private".into(),
                limit: None
            }))
            .await,
        Err(Failure::Denied)
    );
    assert_eq!(
        client
            .call(Call::Dm(DirectArgs {
                agent: "hidden".into(),
                text: "hello".into()
            }))
            .await,
        Err(Failure::Denied)
    );

    let Reply::Agents { agents } = client.call(Call::ListAgents(Empty {})).await.unwrap() else {
        panic!()
    };
    assert_eq!(
        agents
            .iter()
            .map(|agent| agent.id.as_str())
            .collect::<Vec<_>>(),
        ["bob"]
    );
    let Reply::Channels { channels } = client.call(Call::ListChannels(Empty {})).await.unwrap()
    else {
        panic!()
    };
    assert_eq!(
        channels
            .iter()
            .map(|channel| channel.id.as_str())
            .collect::<Vec<_>>(),
        ["general"]
    );
    let Reply::Messages { messages } = client
        .call(Call::Read(ReadArgs {
            channel: "general".into(),
            limit: Some(1),
        }))
        .await
        .unwrap()
    else {
        panic!()
    };
    assert_eq!(messages.len(), 1);
    assert_eq!(messages[0].channel, "general");
    assert_eq!(
        client
            .call(Call::Pass(ChannelArgs {
                channel: "general".into()
            }))
            .await,
        Ok(Reply::Passed)
    );
    assert!(
        client
            .call(Call::Dm(DirectArgs {
                agent: "bob".into(),
                text: "hello".into()
            }))
            .await
            .is_ok()
    );

    let external = principal("guest", AgentKind::External, 1);
    let client = fixture.client(fixture.issue(external.clone(), &[Tool::Post, Tool::Status]));
    assert_eq!(
        client.call(Call::Status(Empty {})).await,
        Ok(Reply::Status {
            principal: external.clone()
        })
    );
    assert_eq!(
        client.call(Call::ListChannels(Empty {})).await,
        Err(Failure::Denied)
    );
    assert!(client.call(post("general")).await.is_ok());

    let calls = fixture.calls.lock().unwrap();
    assert_eq!(calls.len(), 6);
    assert!(calls[..5].iter().all(|(caller, _)| caller == &managed));
    assert_eq!(calls.last(), Some(&(external, post("general"))));
}

#[tokio::test]
async fn revokes_credentials_and_session_generations_and_rejects_forged_requests() {
    let fixture = Fixture::start();
    let token = fixture.issue(
        principal("guest", AgentKind::External, 1),
        &[Tool::Post, Tool::Status],
    );
    let client = fixture.client(token.clone());
    let credential_path = fixture.directory.path().join("credential");
    token.write_new_file(&credential_path).unwrap();
    let secret = zeroize::Zeroizing::new(std::fs::read(&credential_path).unwrap());
    for input in [
        json!({"tool":"post","channel":"general","text":"x","sender":"human"}),
        json!({"tool":"promote","channel":"general"}),
    ] {
        let mut stream = UnixStream::connect(&fixture.socket).await.unwrap();
        let payload = serde_json::to_vec(&input).unwrap();
        stream.write_u8(1).await.unwrap();
        stream.write_all(&secret).await.unwrap();
        stream.write_u32(payload.len() as u32).await.unwrap();
        stream.write_all(&payload).await.unwrap();
        stream.shutdown().await.unwrap();
        assert_eq!(stream.read_u8().await.unwrap(), 1);
        let len = stream.read_u32().await.unwrap() as usize;
        let mut reply = vec![0; len];
        stream.read_exact(&mut reply).await.unwrap();
        assert_eq!(
            serde_json::from_slice::<Result<Reply, Failure>>(&reply).unwrap(),
            Err(Failure::Invalid)
        );
    }
    assert!(fixture.calls.lock().unwrap().is_empty());
    assert!(client.call(Call::Status(Empty {})).await.is_ok());

    std::fs::set_permissions(&credential_path, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(Credential::read_file(&credential_path).is_err());
    std::fs::set_permissions(&credential_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    std::fs::write(&credential_path, [0; 32]).unwrap();
    let wrong = fixture.client(Credential::read_file(&credential_path).unwrap());
    assert_eq!(wrong.call(post("general")).await, Err(Failure::Denied));
    assert!(fixture.authority.revoke(&token).unwrap());
    assert_eq!(client.call(post("general")).await, Err(Failure::Denied));

    let old =
        fixture.client(fixture.issue(principal("guest", AgentKind::External, 1), &[Tool::Post]));
    fixture.authority.activate_session("session", 2).unwrap();
    assert_eq!(old.call(post("general")).await, Err(Failure::Denied));
    assert!(fixture.authority.activate_session("session", 1).is_err());
    let latest =
        fixture.client(fixture.issue(principal("guest", AgentKind::External, 2), &[Tool::Post]));
    assert!(fixture.authority.close_session("session", 1).is_err());
    assert!(latest.call(post("general")).await.is_ok());
    fixture.authority.close_session("session", 2).unwrap();
    assert_eq!(latest.call(post("general")).await, Err(Failure::Denied));
    assert_eq!(fixture.calls.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn real_stdio_mcp_shim_has_stable_tools_and_obeys_live_revocation() {
    timeout(Duration::from_secs(15), async {
        let fixture = Fixture::start();
        let actor = principal("managed-agent", AgentKind::Managed, 1);
        let token = fixture.issue(actor.clone(), &[Tool::Post]);
        let credential = fixture.directory.path().join("credential");
        token.write_new_file(&credential).unwrap();

        let mut process = Command::new(env!("CARGO_BIN_EXE_howl-mcp"))
            .arg(&fixture.socket).arg(&credential)
            .stdin(Stdio::piped()).stdout(Stdio::piped()).kill_on_drop(true)
            .spawn().unwrap();
        let mut input = process.stdin.take().unwrap();
        let mut output = BufReader::new(process.stdout.take().unwrap()).lines();
        send(&mut input, json!({"id":1,"method":"initialize","params":{
            "protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"test","version":"1"}
        }})).await;
        let init: Value = receive(&mut output).await;
        assert_eq!(init["result"]["protocolVersion"], "2025-11-25");
        send(&mut input, json!({"method":"notifications/initialized"})).await;

        let expected = ["dm","list_agents","list_channels","pass","post","read","status"];
        let list = json!({"id":2,"method":"tools/list","params":{}});
        send(&mut input, list.clone()).await;
        assert_tools(receive(&mut output).await, &expected);
        let call = json!({"id":3,"method":"tools/call","params":{"name":"post","arguments":{"channel":"general","text":"hello"}}});
        send(&mut input, call.clone()).await;
        let reply = receive(&mut output).await;
        assert_eq!(reply["result"]["structuredContent"]["reply"]["id"], "receipt");
        assert_eq!(fixture.calls.lock().unwrap().as_slice(), &[(actor, post("general"))]);

        send(&mut input, json!({"id":4,"method":"tools/call","params":{"name":"post","arguments":{"channel":"general","text":"hello","sender":"human"}}})).await;
        let tampered = receive(&mut output).await;
        assert!(tampered["error"].is_object() || tampered["result"]["isError"] == true);
        fixture.authority.revoke(&token).unwrap();
        send(&mut input, list).await;
        assert_tools(receive(&mut output).await, &expected);
        send(&mut input, call).await;
        let denied = receive(&mut output).await;
        assert_eq!(denied["result"]["isError"], true);
        assert_eq!(denied["result"]["content"][0]["text"], "operation denied");
        assert_eq!(fixture.calls.lock().unwrap().len(), 1);
        drop(input);
        assert!(process.wait().await.unwrap().success());
    }).await.unwrap();
}

fn assert_tools(value: Value, expected: &[&str]) {
    let mut names: Vec<_> = value["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|tool| tool["name"].as_str().unwrap())
        .collect();
    names.sort_unstable();
    assert_eq!(names, expected);
}

async fn send(input: &mut tokio::process::ChildStdin, mut message: Value) {
    message["jsonrpc"] = "2.0".into();
    let bytes = serde_json::to_vec(&message).unwrap();
    input.write_all(&bytes).await.unwrap();
    input.write_all(b"\n").await.unwrap();
}

async fn receive(output: &mut tokio::io::Lines<BufReader<tokio::process::ChildStdout>>) -> Value {
    serde_json::from_str(&output.next_line().await.unwrap().unwrap()).unwrap()
}
