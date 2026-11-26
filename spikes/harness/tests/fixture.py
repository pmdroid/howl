import json
import os
import subprocess
import sys


def send(message):
    print(json.dumps({"jsonrpc": "2.0", **message}), flush=True)


def success(request, result=None):
    send({"id": request["id"], "result": result or {}})


def mcp_request(process, method, params, request_id=None):
    message = {"jsonrpc": "2.0", "method": method, "params": params}
    if request_id is not None:
        message["id"] = request_id
    process.stdin.write(json.dumps(message) + "\n")
    process.stdin.flush()
    if request_id is None:
        return None
    reply = json.loads(process.stdout.readline())
    assert reply["id"] == request_id
    return reply["result"]


def call_probe(server):
    assert server["name"] == "howl_probe"
    environment = {**os.environ, **{item["name"]: item["value"] for item in server["env"]}}
    with subprocess.Popen(
        [server["command"], *server["args"]],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        text=True,
        env=environment,
    ) as process:
        mcp_request(process, "initialize", {
            "protocolVersion": "2025-11-25",
            "capabilities": {},
            "clientInfo": {"name": "fixture", "version": "1"},
        }, 1)
        mcp_request(process, "notifications/initialized", {})
        tools = mcp_request(process, "tools/list", {}, 2)
        assert [tool["name"] for tool in tools["tools"]] == ["howl_probe"]
        reply = mcp_request(process, "tools/call", {"name": "howl_probe", "arguments": {}}, 3)
        assert reply["content"] == [{"type": "text", "text": "howl-probe-ok"}]
        process.stdin.close()


def run():
    servers = []
    first_prompt = None
    cancel_prompt = None
    for line in sys.stdin:
        message = json.loads(line)
        method = message.get("method")
        params = message.get("params", {})
        if method == "initialize":
            assert params["protocolVersion"] == 1
            success(message, {
                "protocolVersion": 1,
                "agentCapabilities": {
                    "loadSession": True,
                    "sessionCapabilities": {"resume": {}, "close": {}},
                },
                "authMethods": [{"id": "fixture", "name": "Fixture"}],
            })
        elif method == "authenticate":
            assert params["methodId"] == "fixture"
            success(message)
        elif method == "session/new":
            assert os.path.samefile(params["cwd"], os.getcwd())
            servers = params["mcpServers"]
            success(message, {"sessionId": "fixture-session"})
        elif method == "session/prompt" and first_prompt is None:
            first_prompt = message
            send({"id": "permission", "method": "session/request_permission", "params": {
                "sessionId": "fixture-session",
                "toolCall": {"toolCallId": "example-tool"},
                "options": [
                    {"optionId": "always", "name": "Always allow", "kind": "allow_always"},
                    {"optionId": "once", "name": "Reject once", "kind": "reject_once"},
                ],
            }})
        elif message.get("id") == "permission":
            assert message["result"]["outcome"] == {"outcome": "selected", "optionId": "once"}
            call_probe(servers[0])
            send({"method": "session/update", "params": {
                "sessionId": "fixture-session",
                "update": {
                    "sessionUpdate": "agent_message_chunk",
                    "content": {"type": "text", "text": "howl-probe-ok"},
                },
            }})
            success(first_prompt, {"stopReason": "end_turn"})
        elif method == "session/prompt":
            cancel_prompt = message
        elif method == "session/cancel":
            assert params["sessionId"] == "fixture-session"
            success(cancel_prompt, {"stopReason": "cancelled"})
        elif method in {"session/load", "session/resume", "session/close"}:
            assert params["sessionId"] == "fixture-session"
            success(message)
        else:
            raise AssertionError(method)


run()
