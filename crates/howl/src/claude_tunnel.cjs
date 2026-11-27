const http = require("node:http");

const OPEN = 1;
const DATA = 2;
const END = 3;
const CLOSE = 4;
const OPENED = 5;
const FAILED = 6;
const CHUNK = 16 * 1024;
const OUTPUT_BUFFER = 512 * 1024;
const EMPTY = Buffer.alloc(0);
const sessions = new Map();
let nextId = 1;

function send(kind, id, data = EMPTY) {
  const header = Buffer.alloc(9);
  header.writeUInt8(kind, 0);
  header.writeUInt32BE(id, 1);
  header.writeUInt32BE(data.length, 5);
  return process.stdout.write(Buffer.concat([header, data]));
}

function sendData(id, socket, data) {
  let ready = true;
  for (let offset = 0; offset < data.length; offset += CHUNK) {
    if (!send(DATA, id, data.subarray(offset, offset + CHUNK))) ready = false;
  }
  if (!ready) {
    socket.pause();
    process.stdout.once("drain", () => socket.resume());
  }
  return ready;
}

const proxy = http.createServer({ maxHeaderSize: 8192 }, (_, response) => {
  response.writeHead(405).end();
});
proxy.headersTimeout = 8000;
proxy.requestTimeout = 8000;
proxy.maxConnections = 16;

proxy.on("connect", (request, socket, head) => {
  socket.on("error", () => socket.destroy());
  if (sessions.size >= 8 || nextId > 128 || !/^[a-z.]{1,59}:443$/.test(request.url)) {
    socket.end("HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n");
    return;
  }
  const id = nextId++;
  const session = { socket, head };
  sessions.set(id, session);
  socket.pause();
  socket.once("end", () => {
    if (sessions.has(id)) send(END, id);
  });
  socket.once("close", () => {
    if (sessions.delete(id)) send(CLOSE, id);
  });
  send(OPEN, id, Buffer.from(request.url));
});

function receive(kind, id, data) {
  const session = sessions.get(id);
  if (!session) return;
  const { socket } = session;
  switch (kind) {
    case OPENED:
      if (session.head === null || data.length !== 0) throw new Error("Invalid Claude proxy response");
      socket.write("HTTP/1.1 200 Connection Established\r\n\r\n");
      socket.on("data", data => sendData(id, socket, data));
      if (sendData(id, socket, session.head)) socket.resume();
      session.head = null;
      break;
    case DATA:
      if (session.head !== null || data.length === 0) throw new Error("Invalid Claude proxy data");
      if (socket.writableLength > OUTPUT_BUFFER) socket.destroy();
      else socket.write(data);
      break;
    case END:
      socket.end();
      break;
    case CLOSE:
    case FAILED:
      sessions.delete(id);
      socket.setTimeout(1000, () => socket.destroy());
      socket.end(kind === FAILED ? "HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n" : undefined);
      break;
    default:
      throw new Error("Invalid Claude proxy response");
  }
}

async function read() {
  let pending = EMPTY;
  for await (const chunk of process.stdin) {
    pending = Buffer.concat([pending, chunk]);
    while (pending.length >= 9) {
      const size = pending.readUInt32BE(5);
      if (size > CHUNK) throw new Error("Claude proxy frame is too large");
      if (pending.length < size + 9) break;
      receive(pending.readUInt8(0), pending.readUInt32BE(1), pending.subarray(9, 9 + size));
      pending = pending.subarray(9 + size);
    }
  }
}

proxy.listen(17862, "127.0.0.1", () => process.stdout.write("+"));
read().finally(() => {
  for (const { socket } of sessions.values()) socket.destroy();
  sessions.clear();
  proxy.close();
}).catch(() => { process.exitCode = 1; });
