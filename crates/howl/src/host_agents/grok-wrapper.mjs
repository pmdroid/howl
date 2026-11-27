import { spawn, spawnSync } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { lstatSync, mkdirSync, mkdtempSync, realpathSync, rmSync, writeFileSync } from 'node:fs';
import { isAbsolute, join } from 'node:path';

const maxLine = 256 * 1024;
const tools = ['search_tool', 'use_tool'];
const mcpName = 'howl_repository';
const names = ['read_file', 'list_directory'];
if (process.env.HOWL_EDITABLE_WORKSPACE === '1') names.push('write_file', 'delete_file', 'run_tests');
const mcpTools = names.map(name => mcpName + '__' + name);
const registeredTools = new Set([...tools, ...mcpTools]);
const stopReasons = new Set(['end_turn', 'max_tokens', 'max_turn_requests', 'refusal', 'cancelled']);
const grok = process.env.HOWL_GROK_EXECUTABLE;
const auth = process.env.HOWL_GROK_AUTH_PATH;
let session;
let active;

function ensure(condition) {
  if (!condition) throw new Error('Grok adapter policy rejected the operation');
}

function absent(path) {
  try {
    lstatSync(path);
    return false;
  } catch (error) {
    return error.code === 'ENOENT';
  }
}

async function* lines(stream) {
  let pending = Buffer.alloc(0);
  for await (const chunk of stream) {
    pending = Buffer.concat([pending, chunk]);
    let newline;
    while ((newline = pending.indexOf(10)) >= 0) {
      ensure(newline <= maxLine);
      const line = pending.subarray(0, newline);
      pending = pending.subarray(newline + 1);
      yield JSON.parse(line);
    }
    ensure(pending.length <= maxLine);
  }
  ensure(pending.length === 0);
}

function send(frame) {
  process.stdout.write(JSON.stringify({ jsonrpc: '2.0', ...frame }) + '\n');
}

function reject(id, code, message) {
  if (id !== undefined) send({ id, error: { code, message } });
}

function configure(servers, profile) {
  ensure(Array.isArray(servers) && servers.length === 1);
  const { name, type, command, args, env } = servers[0];
  ensure(name === mcpName && (type === undefined || type === 'stdio') &&
    typeof command === 'string' && isAbsolute(command) &&
    realpathSync(command) === realpathSync(process.execPath) &&
    Array.isArray(args) && args.length === 3 && args[0] === '-e' &&
    args.every(value => typeof value === 'string' && !value.includes('\0') &&
      !value.includes('$' + '{')) &&
    isAbsolute(args[2]) && lstatSync(args[2]).isSocket() &&
    Array.isArray(env) && env.length === 0);
  const config = [
    '[cli]', 'auto_update = false',
    '[session]', 'load_envrc = false',
    '[mcp_servers.' + mcpName + ']',
    'command = ' + JSON.stringify(command),
    'args = ' + JSON.stringify(args),
    '[mcp_servers.' + mcpName + '.env]',
    'GROK_AUTH_PATH = ""',
  ].join('\n') + '\n';
  writeFileSync(profile, config, { flag: 'wx', mode: 0o600 });
}

function stop(turn) {
  if (!turn || turn.timer) return;
  const signal = (name) => {
    if (!turn.child.pid) return;
    try {
      process.kill(-turn.child.pid, name);
    } catch (error) {
      if (error.code !== 'ESRCH') turn.child.kill(name);
    }
  };
  signal('SIGTERM');
  turn.timer = setTimeout(() => signal('SIGKILL'), 250);
  turn.timer.unref();
}

async function readReply(turn, id, sessionId) {
  let registered = false;
  let reason;
  const exit = new Promise(resolve => {
    turn.child.once('error', () => resolve(1));
    turn.child.once('close', code => resolve(code));
  });
  try {
    for await (const event of lines(turn.child.stdout)) {
      if (event.type === 'available_commands') {
        ensure(Array.isArray(event.tools) && tools.every(tool => event.tools.includes(tool)) &&
          event.tools.every(tool => registeredTools.has(tool)));
        registered = true;
      } else if (event.type === 'tool_call') {
        ensure(registered && registeredTools.has(event.toolName) &&
          (event.toolName !== 'use_tool' || mcpTools.includes(event.rawInput?.tool_name)));
      } else if (event.type === 'text' && typeof event.data === 'string') {
        ensure(registered);
        if (!turn.cancelled) send({
          method: 'session/update',
          params: { sessionId, update: {
            sessionUpdate: 'agent_message_chunk', content: { type: 'text', text: event.data },
          } },
        });
      } else if (event.type === 'end') {
        ensure(registered && stopReasons.has(event.stopReason));
        reason = event.stopReason;
      }
    }
  } catch {
    reason = undefined;
    stop(turn);
  }
  const code = await exit;
  if (turn.timer) clearTimeout(turn.timer);
  if (turn.cancelled) send({ id, result: { stopReason: 'cancelled' } });
  else if (code === 0 && reason) send({ id, result: { stopReason: reason } });
  else reject(id, -32603, 'Grok headless turn failed');
}

async function serve() {
  ensure(process.platform !== 'win32' && typeof grok === 'string' && isAbsolute(grok) &&
    typeof auth === 'string' && isAbsolute(auth));
  ensure(['/etc/grok/managed_config.toml', '/etc/grok/requirements.toml',
    '/etc/claude-code/managed-settings.json', '/etc/claude-code/managed-settings.d',
    '/Library/Application Support/ClaudeCode/managed-settings.json',
    '/Library/Application Support/ClaudeCode/managed-settings.d'].every(absent));

  const root = mkdtempSync(join(process.cwd(), 'grok-headless-'));
  const grokHome = join(root, '.grok');
  const config = join(grokHome, 'config.toml');
  mkdirSync(grokHome, { mode: 0o700 });
  const work = join(root, 'workspace');
  mkdirSync(work, { mode: 0o700 });
  const git = join(work, '.git');
  mkdirSync(join(git, 'objects'), { mode: 0o700, recursive: true });
  mkdirSync(join(git, 'refs'), { mode: 0o700 });
  writeFileSync(join(git, 'HEAD'), 'ref: refs/heads/main\n', { mode: 0o600 });
  const env = {
    HOME: root, GROK_HOME: grokHome, GROK_CONFIG_PATH: config,
    TMPDIR: root, PATH: '/usr/bin:/bin', LANG: 'C.UTF-8',
    GROK_FEEDBACK_ENABLED: '0', GROK_WORKFLOWS: '0', GROK_GOAL: '0',
    GROK_MANAGED_MCPS_ENABLED: '0', GROK_MANAGED_MCP_GATEWAY_TOOLS_ENABLED: '0',
  };
  for (const client of ['CURSOR', 'CLAUDE', 'CODEX']) {
    for (const kind of ['SKILLS', 'RULES', 'AGENTS', 'MCPS', 'HOOKS', 'SESSIONS']) {
      env['GROK_' + client + '_' + kind + '_ENABLED'] = '0';
    }
  }
  let initialized = false;
  try {
    const version = spawnSync(grok, ['--version'], {
      cwd: work, env, timeout: 5000, maxBuffer: 8192, encoding: 'utf8',
    });
    ensure(version.status === 0 && /^grok 1\.0\.92 \(b06756fd6256\)(?: \[stable\])?\s*$/.test(version.stdout));
    for await (const { id, method, params } of lines(process.stdin)) {
      try {
        if (method === 'initialize' && Number.isSafeInteger(params?.protocolVersion) && params.protocolVersion >= 1) {
          initialized = true;
          send({ id, result: {
            protocolVersion: 1,
            agentInfo: { name: 'Howl Grok headless', version: '1' },
            agentCapabilities: { sessionCapabilities: { close: {} } },
          } });
        } else if (initialized && method === 'session/new' && !session) {
          configure(params?.mcpServers, config);
          session = randomUUID();
          send({ id, result: { sessionId: session } });
        } else if (session && params?.sessionId === session && method === 'session/cancel') {
          if (active) {
            active.cancelled = true;
            stop(active);
          }
        } else if (session && params?.sessionId === session && method === 'session/close' && !active) {
          send({ id, result: {} });
          break;
        } else if (session && params?.sessionId === session && method === 'session/prompt' && !active) {
          ensure(Array.isArray(params.prompt) && params.prompt.length > 0 &&
            params.prompt.every(item => item.type === 'text' && typeof item.text === 'string'));
          const prompt = params.prompt.map(item => item.text).join('\n');
          ensure(prompt.length > 0 && Buffer.byteLength(prompt) <= 64 * 1024);
          const path = join(root, 'prompt');
          writeFileSync(path, prompt, { mode: 0o600 });
          const child = spawn(grok, [
            '--no-auto-update', '--no-memory', '--no-subagents', '--disable-web-search',
            '--permission-mode', 'dontAsk', '--tools', tools.join(','),
            ...mcpTools.flatMap(tool => ['--allow', 'MCPTool(' + tool + ')']),
            '--session-id', session, '--verbatim', '--output-format', 'streaming-json',
            '--prompt-file', path,
          ], {
            cwd: work, env: { ...env, GROK_AUTH_PATH: auth }, detached: true, stdio: ['ignore', 'pipe', 'ignore'],
          });
          const turn = { child, cancelled: false, timer: undefined };
          active = turn;
          turn.done = readReply(turn, id, session).finally(() => { active = undefined; });
        } else {
          reject(id, -32601, 'Unavailable Grok session operation');
        }
      } catch {
        reject(id, -32602, 'Invalid Grok session request');
      }
    }
  } finally {
    if (active) {
      active.cancelled = true;
      stop(active);
      await active.done;
    }
    rmSync(root, { recursive: true, force: true });
  }
}

function shutdown() {
  process.stdin.destroy();
}

process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);
serve().catch(() => { process.exitCode = 1; });
