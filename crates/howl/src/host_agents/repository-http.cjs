const { createServer } = require("node:http");
const { createConnection } = require("node:net");
const { timingSafeEqual } = require("node:crypto");
const { createInterface } = require("node:readline");

const repository = process.argv[1];
const token = process.env.HOWL_REPOSITORY_MCP_TOKEN;
if (!/^[0-9a-f]{64}$/.test(token ?? "")) process.exit(64);
const authorization = Buffer.from("Bearer " + token);
delete process.env.HOWL_REPOSITORY_MCP_TOKEN;
let origin;

function approved(request) {
  const supplied = Buffer.from(request.headers.authorization ?? "");
  return request.headers.host === new URL(origin).host
    && (!request.headers.origin || request.headers.origin === origin)
    && supplied.length === authorization.length
    && timingSafeEqual(supplied, authorization);
}

async function readRequest(request) {
  const chunks = [];
  let size = 0;
  for await (const chunk of request) {
    size += chunk.length;
    if (size > 16384) throw new Error("Request exceeds limit");
    chunks.push(chunk);
  }
  return JSON.parse(Buffer.concat(chunks, size));
}

const bridge = createConnection(repository);
const replies = createInterface({ input: bridge })[Symbol.asyncIterator]();
bridge.on("error", () => {});
let queue = Promise.resolve();
let pending = 0;

function exchange(request) {
  const exchange = queue.then(async () => {
    if (bridge.destroyed) throw new Error("Repository disconnected");
    const timer = setTimeout(() => bridge.destroy(), 8000);
    try {
      bridge.write(JSON.stringify(request) + "\n");
      const { value, done } = await replies.next();
      if (done || Buffer.byteLength(value) > 400000) throw new Error("Invalid repository response");
      return value;
    } finally {
      clearTimeout(timer);
    }
  });
  queue = exchange.catch(() => {});
  return exchange;
}

const server = createServer({ maxHeaderSize: 8192 }, async (request, response) => {
  if (!approved(request)) {
    response.writeHead(403).end();
    return;
  }
  if (request.url !== "/mcp") {
    response.writeHead(404).end();
    return;
  }
  if (request.method !== "POST") {
    response.writeHead(405, { Allow: "POST" }).end();
    return;
  }
  if (pending >= 8) {
    response.writeHead(429).end();
    return;
  }
  pending++;
  try {
    const message = await readRequest(request);
    if (message?.jsonrpc !== "2.0" || typeof message.method !== "string") {
      response.writeHead(400).end();
      return;
    }
    if (!Object.hasOwn(message, "id")) {
      response.writeHead(202).end();
      return;
    }
    const reply = await exchange(message);
    response.writeHead(200, { "Content-Type": "application/json", "Cache-Control": "no-store" }).end(reply);
  } catch {
    response.writeHead(502).end();
  } finally {
    pending--;
  }
});

server.maxConnections = 8;
server.requestTimeout = 10000;
server.headersTimeout = 5000;
server.keepAliveTimeout = 3000;
server.listen(0, "127.0.0.1", () => {
  const port = server.address().port;
  origin = "http://127.0.0.1:" + port;
  process.stdout.write(port + "\n");
});
process.stdin.on("end", () => {
  server.close();
  bridge.destroy();
});
process.stdin.resume();
