const http = require("node:http");
const readline = require("node:readline");
const { once } = require("node:events");

const lines = readline.createInterface({ input: process.stdin, crlfDelay: Infinity });
const replies = lines[Symbol.asyncIterator]();
let queue = Promise.resolve();
let pending = 0;
let nextId = 0;

async function receive() {
  const { done, value } = await replies.next();
  if (done) throw new Error("provider bridge disconnected");
  return JSON.parse(value);
}

const server = http.createServer((request, response) => {
  if (pending >= 4) {
    request.resume();
    response.writeHead(503).end();
    return;
  }
  pending++;
  const id = ++nextId;
  let active = false;
  response.on("close", () => {
    if (active && !response.writableEnded) process.stdout.write(JSON.stringify({ cancel: id }) + "\n");
  });
  const body = readBody(request);
  body.catch(() => {});
  queue = queue.then(async () => {
    let payload;
    try {
      payload = await body;
    } catch {
      response.writeHead(413).end();
      return;
    }
    if (response.destroyed) return;
    active = true;
    const frame = JSON.stringify({ id, method: request.method, path: request.url, body: payload });
    if (!process.stdout.write(frame + "\n")) await once(process.stdout, "drain");
    const header = await receive();
    if (header.end) return;
    if (!response.destroyed) response.writeHead(header.status, { "content-type": header.content_type });
    for (;;) {
      const reply = await receive();
      if (reply.end) break;
      if (!response.destroyed && !response.write(Buffer.from(reply.chunk, "base64"))) {
        await new Promise(resolve => {
          function ready() {
            response.off("drain", ready);
            response.off("close", ready);
            resolve();
          }
          response.once("drain", ready);
          response.once("close", ready);
        });
      }
    }
    active = false;
    response.end();
  }).catch(() => {
    response.destroy();
    process.exit(1);
  }).finally(() => { pending--; });
});

async function readBody(request) {
  const chunks = [];
  let total = 0;
  for await (const chunk of request) {
    total += chunk.length;
    if (total > 2 * 1024 * 1024) throw new Error("provider request exceeds limit");
    chunks.push(chunk);
  }
  return new TextDecoder("utf-8", { fatal: true }).decode(Buffer.concat(chunks, total));
}

server.requestTimeout = 15_000;
server.headersTimeout = 10_000;
server.listen(17861, "127.0.0.1", () => process.stdout.write("ready\n"));
lines.on("close", () => {
  server.close();
  queue.finally(() => process.exit(0));
});
