use serde_json::Value;
use std::{path::Path, process::Command};

#[test]
fn exercises_acp_lifecycle_against_fixture_and_calls_the_stdio_mcp_tool() {
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixture.py");
    let result = Command::new(env!("CARGO_BIN_EXE_howl-harness-spike"))
        .args(["--exercise", "--authenticate", "fixture", "--", "python3"])
        .arg(fixture)
        .output()
        .unwrap();
    assert!(result.status.success(), "{:?}", result);
    let stdout = String::from_utf8(result.stdout).unwrap();
    let events: Vec<Value> = stdout
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    let data = |stage| {
        &events
            .iter()
            .find(|event| event["stage"] == stage)
            .unwrap_or_else(|| panic!("missing {stage} in {stdout}"))["data"]
    };
    for stage in [
        "initialize",
        "authenticate",
        "session/new",
        "session/prompt",
        "session/load",
        "session/resume",
        "session/close",
    ] {
        assert_eq!(data(stage)["status"], "ok");
    }
    assert_eq!(data("permission")["decision"], "reject_once");
    assert_eq!(data("permissions")["requests"], 1);
    assert_eq!(data("prompt_result")["message_chunks"], 1);
    assert_eq!(data("session/cancel")["status"], "sent");
    assert_eq!(data("cancel_prompt")["status"], "cancelled");
    assert_eq!(data("mcp")["starts"], 1);
    assert_eq!(data("mcp")["initialized"], 1);
    assert_eq!(data("mcp")["calls"], 1);
}
