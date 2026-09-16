// Trusted host-side supervisor. Child commands receive the kernel-enforced policy.
import fs from 'node:fs';
import path from 'node:path';
import { constants as osConstants } from 'node:os';
import { fileURLToPath } from 'node:url';
import { spawn, spawnSync } from 'node:child_process';
import { SandboxManager } from './runtime/node_modules/@anthropic-ai/sandbox-runtime/dist/index.js';
import { SandboxRuntimeConfigSchema } from './runtime/node_modules/@anthropic-ai/sandbox-runtime/dist/sandbox/sandbox-config.js';

const quote = s => "'" + s.replaceAll("'", "'\\''") + "'";

let diagnosticPhase = 'policy-load';
async function main() {
  const [policyPath, separator, ...command] = process.argv.slice(2);
  if (separator !== '--' || command.length === 0 || process.platform !== 'darwin') throw new Error('invalid invocation');
  const result = SandboxRuntimeConfigSchema.safeParse(JSON.parse(fs.readFileSync(policyPath, 'utf8')));
  if (!result.success) throw new Error('invalid policy');
  diagnosticPhase = 'sandbox-initialize';
  await SandboxManager.initialize(result.data, undefined, false);
  try {
    diagnosticPhase = 'sandbox-profile';
    const wrapped = await SandboxManager.wrapWithSandbox(command.map(quote).join(' '), '/bin/bash', undefined, undefined,
                                                        {commandId: 'agent-guard'});
    // SRT 0.0.75 returns a shell-quoted argv. Parse it without evaluating a host shell.
    const parsed = spawnSync('/usr/bin/python3', ['-I', '-c',
      'import json,shlex,sys; print(json.dumps(shlex.split(sys.stdin.read())))'],
      {input: wrapped, encoding: 'utf8', maxBuffer: 4 * 1024 * 1024});
    if (parsed.status !== 0) throw new Error('profile parsing failed');
    const argv = JSON.parse(parsed.stdout);
    const index = argv.indexOf('/usr/bin/sandbox-exec');
    if (argv[0] !== 'env' || index < 1 || argv[index + 1] !== '-p' || !argv[index + 2].startsWith('(version 1)')) {
      throw new Error('unexpected sandbox invocation');
    }
    if (process.env.AGENT_GUARD_BOOTSTRAP === 'zcode') {
      diagnosticPhase = 'zcode-config-write';
      // Trusted supervisor writes the runtime config BEFORE entering Seatbelt.
      // The child policy denies writes/renames to this file and its ancestors.
      const root = path.dirname(fileURLToPath(import.meta.url));
      const config = JSON.parse(fs.readFileSync(path.join(root, 'state/zcode-agent-config.json'), 'utf8'));
      const generatedEnv = Object.fromEntries(argv.slice(1, index).filter(x => x.includes('='))
        .map(x => [x.slice(0, x.indexOf('=')), x.slice(x.indexOf('=') + 1)]));
      if (!generatedEnv.HTTPS_PROXY) throw new Error('missing restricted proxy');
      const home = process.env.HOME;
      // The parents of the config live inside the child-writable isolated home. A
      // link planted by a previous session would make this trusted write land on
      // a host path, so every ancestor below HOME must be a real directory.
      for (const relative of ['.zcode', '.zcode/cli']) {
        const candidate = path.join(home, relative);
        const info = fs.lstatSync(candidate, {throwIfNoEntry: false});
        if (!info || !info.isDirectory() || info.isSymbolicLink()) {
          throw new Error('zcode config parent is missing or is a link');
        }
        if (fs.realpathSync(candidate) !== path.join(fs.realpathSync(home), relative)) {
          throw new Error('zcode config parent does not resolve inside the isolated home');
        }
      }
      // 감독자가 브로커 포트를 열어 준 세션(AutoClaw 모델 브로커)은 루프백을 프록시로 보내면 안 된다.
      // 프록시는 도메인 허용 목록만 알고, Seatbelt 가 그 포트 하나만 직접 연결로 허용한다.
      const loopbackBypass = Number(process.env.AGENT_GUARD_BROKER_PORT || 0) ? '127.0.0.1,localhost' : '';
      config.network = {...config.network, httpProxy: generatedEnv.HTTPS_PROXY, noProxy: loopbackBypass,
                        caCertFile: '/private/etc/ssl/cert.pem'};
      config.storage = {dir: path.join(home, '.zcode'),
                        sessionDbPath: path.join(home, '.zcode/cli/db/db.sqlite')};
      const descriptor = fs.openSync(path.join(home, '.zcode/cli/config.json'),
        fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_TRUNC | fs.constants.O_NOFOLLOW, 0o600);
      try { fs.writeFileSync(descriptor, JSON.stringify(config)); }
      finally { fs.closeSync(descriptor); }
    }
    // SRT permits SecurityServer for compatibility. These agents must not query
    // the user's unlocked Keychain or delegate execution to desktop services.
    argv[index + 2] += `
; Permit only these system symlink vnodes, never their directory trees.
(allow file-read-data file-read-metadata
  (literal "/etc") (literal "/var") (literal "/tmp")
  (literal "/private/var/select/sh"))
(deny user-preference-read)
(deny mach-lookup
  (global-name "com.apple.SecurityServer")
  (global-name "com.apple.securityd.xpc")
  (global-name "com.apple.cfprefsd.agent")
  (global-name "com.apple.cfprefsd.daemon")
  (global-name "com.apple.coreservices.launchservicesd")
  (global-name "com.apple.CoreServices.coreservicesd")
  (global-name "com.apple.coreservices.appleevents"))
(deny appleevent-send)
; Clipboard. Every reader and writer (NSPasteboard via the bundled native binding,
; pbcopy/pbpaste, osascript JXA) goes through the pasteboard server, so denying the
; service name closes all of them at once. SRT's default-deny already leaves it closed;
; this explicit rule keeps it closed even if a runtime upgrade widens the allow list.
; Universal Clipboard (Handoff) relays are covered by the prefix.
(deny mach-lookup
  (global-name "com.apple.pasteboard.1")
  (global-name-prefix "com.apple.coreservices.uasharedpasteboard"))
; Certificate trust evaluation only. Clients that use the macOS verifier (Go's
; net/http, Dart) cannot complete a TLS handshake without it, and curl's own CA
; bundle hid that until now. Keychain item access stays denied above: trustd
; answers "is this chain valid", it does not hand out stored secrets.
(allow mach-lookup (global-name "com.apple.trustd.agent"))
`;
    // Python's FileFinder must list the module directory; grant only the
    // directory vnode, not the state/auth subtree beneath it.
    const moduleRoot = path.dirname(fileURLToPath(import.meta.url));
    argv[index + 2] += '\n(allow file-read-data file-read-metadata (literal ' + JSON.stringify(moduleRoot) + '))\n';
    diagnosticPhase = 'terminal-capabilities';
    const terminals = JSON.parse(process.env.AGENT_GUARD_TTY_PATHS || '[]');
    if (!Array.isArray(terminals)) throw new Error('invalid terminal capability');
    const inheritedDevices = new Set([0, 1, 2].flatMap(fd => {
      try { const info = fs.fstatSync(fd); return info.isCharacterDevice() ? [info.rdev] : []; }
      catch { return []; }
    }));
    for (const terminal of terminals) {
      if (typeof terminal !== 'string' || !/^\/dev\/ttys[0-9]+$/.test(terminal) ||
          fs.realpathSync(terminal) !== terminal || !inheritedDevices.has(fs.statSync(terminal).rdev)) {
        throw new Error('terminal does not match an inherited descriptor');
      }
    }
    // Darwin SDK ttycom.h: termios get/set, window-size query, FIONREAD.
    // Do not enable SRT allowPty: that grants access to every /dev/ttys* device.
    const terminalIoctls = [1078490131, 2152231956, 2152231957, 2152231958,
                           1074295912, 1074030207];
    argv[index + 2] += '\n(deny file-ioctl (literal "/dev/tty"))\n';
    if (terminals.length) {
      argv[index + 2] += '(allow file-ioctl (require-all\n  (require-any\n' +
        [...new Set(terminals)].map(p => '    (literal ' + JSON.stringify(p) + ')').join('\n') +
        ')\n  (require-any\n' + terminalIoctls.map(n => '    (ioctl-command ' + n + ')').join('\n') + ')))\n';
    }
    // TIOCSTI can inject input into an unsandboxed parent shell. Always deny it,
    // including through the generic controlling-terminal alias /dev/tty.
    argv[index + 2] += '(deny file-ioctl (ioctl-command 2147578994))\n';
    // Per-workspace opt-in: re-allow only the file named gradle.keystore inside
    // the workspace. Gradle TestKit and the configuration cache create it for
    // integrity checks and its *.keystore name trips the secret deny. denyWrite
    // beats allowWrite in the policy, so this is appended AFTER the SRT profile
    // where SBPL's last matching rule wins; every other *.keystore stays denied.
    const keystoreRoot = process.env.AGENT_GUARD_GRADLE_KEYSTORE_ROOT;
    if (keystoreRoot) {
      if (!path.isAbsolute(keystoreRoot) || fs.realpathSync(keystoreRoot) !== keystoreRoot) {
        throw new Error('invalid gradle keystore root');
      }
      const escaped = keystoreRoot.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      const pattern = '^' + escaped + '/(.*/)?gradle\\.keystore$';
      // SRT 의 keystore deny 는 file-write-create 등 구체 op 라, 와일드카드 file-write* allow 로는 못 이긴다
      // (Seatbelt 는 더 구체적인 op 규칙을 우선한다). 같은 구체 op 를 나열해야 이 파일명만 re-allow 된다.
      const ops = 'file-read-data file-read-metadata file-read-xattr file-write-create file-write-data '
        + 'file-write-flags file-write-mode file-write-owner file-write-setugid file-write-times file-write-unlink';
      argv[index + 2] += '\n(allow ' + ops + ' (regex ' + JSON.stringify(pattern) + '))\n';
    }
    // Writable roots themselves must not be renamed/replaced by a child. This
    // keeps subsequent launches from resolving a replaced HOME/workspace root.
    const writableRoots = result.data.filesystem.allowWrite;
    if (writableRoots.length) {
      argv[index + 2] += '\n(deny file-write-unlink file-write-create\n' +
        writableRoots.map(p => '  (literal ' + JSON.stringify(p) + ')').join('\n') + '\n)\n';
    }
    // A supervisor-owned loopback port for status relay. The child may reach
    // this single address; every other local service stays denied, and the
    // supervisor is what actually holds the destination's credentials.
    const brokerPort = Number(process.env.AGENT_GUARD_BROKER_PORT || 0);
    if (brokerPort) {
      if (!Number.isInteger(brokerPort) || brokerPort < 1024 || brokerPort > 65535) {
        throw new Error('invalid broker port');
      }
      argv[index + 2] += '\n(allow network-outbound (remote ip "localhost:' + brokerPort + '"))\n';
    }
    const devPorts = JSON.parse(process.env.AGENT_GUARD_DEV_PORTS || '[]');
    if (!Array.isArray(devPorts) || devPorts.some(p => !Number.isInteger(p) || p < 1024 || p > 65535)) {
      throw new Error('invalid development ports');
    }
    // Explicit opt-in: Seatbelt also accepts wildcard binds on these ports.
    // Browser clients run outside this backend. Besides listening, the child may
    // connect to its own port: dart test --coverage talks to its VM service over
    // a loopback websocket and hung without this. Outbound stays limited to the
    // declared ports, never to arbitrary services in the user's session.
    for (const port of new Set(devPorts)) {
      argv[index + 2] += '\n(allow network-bind network-inbound (local ip "localhost:' + port + '"))\n';
      argv[index + 2] += '\n(allow network-outbound (remote ip "localhost:' + port + '"))\n';
    }
    // No inherited file descriptors beyond stdin/stdout/stderr.
    diagnosticPhase = 'child-spawn';
    const child = spawn('/usr/bin/env', argv.slice(1), {stdio: 'inherit', env: process.env});
    const forward = signal => child.kill(signal);
    const onInt = () => forward('SIGINT');
    const onTerm = () => forward('SIGTERM');
    process.on('SIGINT', onInt);
    process.on('SIGTERM', onTerm);
    const status = await new Promise((resolve, reject) => {
      child.once('error', reject);
      child.once('exit', (code, signal) => {
        if (signal) console.error('agent-guard: child terminated by ' + signal);
        resolve(code ?? (128 + (osConstants.signals[signal] ?? 15)));
      });
    });
    process.off('SIGINT', onInt);
    process.off('SIGTERM', onTerm);
    return status;
  } finally {
    await SandboxManager.reset();
  }
}

main().then(code => { process.exitCode = code; }).catch(error => {
  if (process.env.AGENT_GUARD_BOOTSTRAP === 'zcode') {
    try {
      const directory = path.join(path.dirname(fileURLToPath(import.meta.url)), 'state/runtime');
      fs.mkdirSync(directory, {recursive: true, mode: 0o700});
      const code = typeof error?.code === 'string' && /^[A-Z_]{1,40}$/.test(error.code) ? error.code : 'UNCLASSIFIED';
      fs.writeFileSync(path.join(directory, 'zcode-supervisor-error.json'), JSON.stringify({phase: diagnosticPhase, code}), {mode: 0o600});
    } catch {}
  }
  // Do not print command text, environment values or config parse contents.
  console.error('agent-guard: sandbox initialization failed; no unrestricted fallback.');
  process.exitCode = 125;
});
