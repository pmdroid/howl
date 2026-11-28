const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8", { fatal: true });
const hex = Array.from({ length: 256 }, (_, byte) => byte.toString(16).padStart(2, "0"));

export class HttpError extends Error {
  constructor(readonly status: number) {
    super(String(status));
  }
}

export function requireValue(valid: unknown, status = 400): asserts valid {
  if (!valid) throw new HttpError(status);
}

export function encodeHex(bytes: Uint8Array) {
  let encoded = "";
  for (const byte of bytes) encoded += hex[byte];
  return encoded;
}

export function decodeHex(encoded: string) {
  const bytes = new Uint8Array(encoded.length / 2);
  for (let i = 0; i < bytes.length; i++)
    bytes[i] = Number.parseInt(encoded.slice(i * 2, i * 2 + 2), 16);
  return bytes;
}

export function randomId() {
  return encodeHex(crypto.getRandomValues(new Uint8Array(32)));
}

export async function digest(value: string | Uint8Array<ArrayBuffer>) {
  const bytes = typeof value === "string" ? encoder.encode(value) : value;
  return encodeHex(new Uint8Array(await crypto.subtle.digest("SHA-256", bytes)));
}

export async function jsonBody<T>(request: Request, limit = 4096, array = false) {
  requireValue(request.body, 400);
  const reader = request.body.getReader();
  const bytes = new Uint8Array(limit);
  let length = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    if (length + value.length > limit) {
      await reader.cancel();
      throw new HttpError(413);
    }
    bytes.set(value, length);
    length += value.length;
  }
  const raw = bytes.subarray(0, length);
  let parsed;
  try {
    parsed = JSON.parse(decoder.decode(raw));
  } catch {
    throw new HttpError(400);
  }
  requireValue(parsed && typeof parsed === "object" && Array.isArray(parsed) === array);
  return { parsed: parsed as T, raw };
}

export function reply(value: unknown, status = 200) {
  const headers = { "Cache-Control": "no-store" };
  return status === 204
    ? new Response(null, { status, headers })
    : Response.json(value, { status, headers });
}
