import { createServer } from "node:http";

const [auth = "howl-local", port = "17861", model = "howl-fixture-model", session = ""] = process.argv.slice(2);
const label = "howl-responses-fixture-ok";

const server = createServer(async (request, response) => {
  if (request.headers.authorization !== `Bearer ${auth}`) {
    response.writeHead(401).end();
    return;
  }
  if (request.method === "GET" && request.url === "/v1/models") {
    response.writeHead(200, { "Content-Type": "application/json" }).end(JSON.stringify({
      object: "list",
      data: [{ id: model, object: "model", created: 1, owned_by: "fixture" }],
    }));
    return;
  }
  const chatPath = session ? "/inference/go/openai/v1/chat/completions" : "/v1/chat/completions";
  if (request.method === "POST" && request.url === chatPath) {
    const agent = request.headers["user-agent"];
    if (session && (request.headers["x-opencode-session"] !== session || !agent?.startsWith("Howl/"))) {
      response.writeHead(403).end();
      return;
    }
    const input = JSON.parse(await new Promise((resolve, reject) => {
      const chunks = [];
      request.on("data", chunk => chunks.push(chunk));
      request.on("end", () => resolve(Buffer.concat(chunks).toString()));
      request.on("error", reject);
    }));
    if (input.model !== model || input.stream !== true) {
      response.writeHead(400).end();
      return;
    }
    response.writeHead(200, { "Content-Type": "text/event-stream" });
    for (const choice of [
      { delta: { role: "assistant", content: label }, finish_reason: null },
      { delta: {}, finish_reason: "stop" },
    ]) {
      response.write(`data: ${JSON.stringify({ id: "chatcmpl-fixture", object: "chat.completion.chunk",
        created: 1, model, choices: [{ index: 0, ...choice }] })}\n\n`);
    }
    response.end("data: [DONE]\n\n");
    return;
  }
  if (request.method !== "POST" || request.url !== "/v1/responses") {
    response.writeHead(404).end();
    return;
  }
  const chunks = [];
  let size = 0;
  for await (const chunk of request) {
    size += chunk.length;
    if (size > 1024 * 1024) {
      response.writeHead(413).end();
      return;
    }
    chunks.push(chunk);
  }
  let input;
  try {
    input = JSON.parse(Buffer.concat(chunks, size));
  } catch {
    response.writeHead(400).end();
    return;
  }
  if (input?.model !== model || input.stream !== true ||
      input.tools?.some((tool) => tool.type?.startsWith("web_search"))) {
    response.writeHead(400).end();
    return;
  }

  response.writeHead(200, { "Content-Type": "text/event-stream" });
  const message = {
    id: "msg_howl_fixture",
    type: "message",
    role: "assistant",
    status: "completed",
    content: [{ type: "output_text", text: label, annotations: [] }],
  };
  const reply = {
    id: "resp_howl_fixture",
    object: "response",
    created_at: 1,
    status: "completed",
    model,
    output: [message],
    usage: {
      input_tokens: 1,
      output_tokens: 1,
      total_tokens: 2,
      input_tokens_details: { cached_tokens: 0 },
      output_tokens_details: { reasoning_tokens: 0 },
    },
  };
  const events = [
    { type: "response.created", response: { ...reply, status: "in_progress", output: [] } },
    { type: "response.output_item.added", output_index: 0, item: { ...message, status: "in_progress", content: [] } },
    { type: "response.output_text.delta", output_index: 0, content_index: 0, item_id: message.id, delta: label },
    { type: "response.output_item.done", output_index: 0, item: message },
    { type: "response.completed", response: reply },
  ];
  for (const [sequence_number, event] of events.entries()) {
    response.write(`event: ${event.type}\ndata: ${JSON.stringify({ ...event, sequence_number })}\n\n`);
  }
  response.end();
});

server.listen(Number(port), "127.0.0.1", () => process.stdout.write(`Ready ${server.address().port}\n`));
