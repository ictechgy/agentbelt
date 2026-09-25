"""kimi mode (`safekimi`) that runs the Kimi Code CLI (Moonshot `kimi`) confined.

Why confine it. The native Kimi Code CLI is a Node SEA binary that reads and writes the system clipboard through
native clipboard bindings (`@mariozechner/clipboard`, NSPasteboard), `pbcopy`, and osascript (JXA), and it has
paths for telemetry (`telemetry-logs.kimi.*`), auto-update (`code.kimi.*`), the plugin market, WebBridge/Computer-Use
binary downloads (`cdn.kimi.com`), and launchd service registration (`ai.kimi.cu.service`). It is wrapped in the same
Seatbelt boundary as safecode (one workspace + a per-project isolated home + a domain allow list), and the clipboard is
blocked at native services (`sandbox_runner.mjs`) and at the host terminal relay (`terminal_proxy.py`).

Why login works inside the session. The login of Kimi is a device code flow (`auth.kimi.*/api/oauth/device_authorization`),
so it needs no local callback port. Opening the browser automatically (`open`) fails in the sandbox, but the URL is printed
on screen so the user opens it directly. The token is stored in `<isolated home>/.kimi-code/credentials/` and is refreshed
with a temporary file + rename, which splits hard-link sharing -- so log in once per workspace (the host `~/.kimi-code` is
not even opened for reading).
"""
import json
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]  # install/repo root; this file lives in adapters/
sys.path.insert(0, str(ROOT))
import agentbelt  # noqa: E402

# Policy file for kimi mode. Change the region and the reachable domains only here.
PROFILE_PATH = ROOT / 'state/kimi-profile.json'
# Home subdirectory where Kimi keeps settings, credentials, sessions, and caches (`KIMI_CODE_HOME`). Keep it inside the isolated home.
KIMI_HOME_RELATIVE = '.kimi-code'
# Region marker. Before the first login Kimi picks the OAuth/API host from this file. The supervisor writes it and locks it.
REGION_MARKER_RELATIVE = KIMI_HOME_RELATIVE + '/region'
# Global instruction file Kimi reads at startup. Put the environment notice here so the session knows its own boundary.
INSTRUCTIONS_RELATIVE = KIMI_HOME_RELATIVE + '/AGENTS.md'
# Reviewed hosts per region. Only the login (OAuth) and the coding API are opened. Telemetry, CDN, update, and market hosts are not included.
REGION_DOMAINS = {
    'global': ['auth.kimi.ai:443', 'api.kimi.ai:443'],
    'mainland-cn': ['auth.kimi.com:443', 'api.kimi.com:443'],
}

# Preload that runs directory fs.watch without FSEvents (the explanation is at the head of that file). Injected into the child Node through NODE_OPTIONS.
WATCH_BOOTSTRAP = ROOT / 'kimi_watch_bootstrap.cjs'

# Kimi-only section appended to the session start notice. Makes the agent aware of the clipboard block and the login procedure.
KIMI_NOTICE = ('## Kimi Code\n\n'
               '- Native clipboard access is blocked by the kernel, and the host terminal relay removes OSC 52 and passthrough strings. Pasting images, `/copy`,\n'
               '  `pbpaste`, `pbcopy`, and osascript clipboard access all fail; that is by design, not a failure. Do not look for a workaround.\n'
               '- Log in inside this session with `/login`. When the device code URL is printed on screen, the user opens it in a browser\n'
               '  (automatic opening does not work here). The token stays only in `$KIMI_CODE_HOME/credentials/`.\n'
               '- Auto-update, telemetry, the plugin market, WebBridge, and Computer-Use are turned off or outside the domain list. Do not try to install them.\n'
               '- The verified Kimi runtime disables diagnostic feedback uploads and remote banners, and refuses non-loopback web binding even when re-executed without the preload.\n'
               '- The Kimi settings home is `$KIMI_CODE_HOME`. The `~/.kimi-code` of the host is not visible.\n'
               '- `NODE_OPTIONS` carries the supervisor preload (so that directory watching runs without FSEvents). Do not remove it.\n'
               '  Kimi 2.1 disables config and workspace file watching by default; changes may require a restart.\n'
               '  When watching is enabled, the guard keeps the polling/FSEvents restrictions in place.\n')


def default_profile():
    """Reviewed default policy. The same global region as the region marker of the host installation (`~/.kimi-code/region`)."""
    return {'region': 'global', 'domains': list(REGION_DOMAINS['global'])}


def load_profile():
    """Read the policy file. If it is missing, create the default with mode 0600. If the region or the domains do not match the format, fail closed."""
    if not PROFILE_PATH.is_file():
        agentbelt.private_dir(PROFILE_PATH.parent)
        agentbelt.write_private_json(PROFILE_PATH, default_profile())
    profile = json.loads(PROFILE_PATH.read_text())
    if profile.get('region') not in REGION_DOMAINS:
        raise agentbelt.GuardError('state/kimi-profile.json region must be "global" or "mainland-cn".')
    domains = profile.get('domains')
    reviewed = set(REGION_DOMAINS[profile['region']])
    # Reject wildcards, other ports, and hosts outside the review (review LOW: `*.kimi.ai:443` would reopen the telemetry and update hosts).
    if not isinstance(domains, list) or not domains or not all(isinstance(d, str) and d in reviewed for d in domains):
        raise agentbelt.GuardError('state/kimi-profile.json domains must be a non-empty subset of the reviewed Kimi hosts: '
                                     + ', '.join(sorted(reviewed)) + '.')
    return profile


def kimi_environment(home, binary=None):
    """Environment passed to the child Kimi process. Turns off telemetry and auto-update and pins the settings home inside the isolated home.

    binary is the (staged) Kimi path that actually runs. The preload replaces fs.watch only when `process.execPath` equals this
    value -- NODE_OPTIONS is also inherited by other node tools the agent launches, so their watching is left alone.
    """
    return {
        'KIMI_CODE_HOME': str(Path(home) / KIMI_HOME_RELATIVE),
        'AGENTBELT_KIMI_BINARY': str(binary if binary is not None else agentbelt.KIMI),
        'KIMI_DISABLE_TELEMETRY': '1',
        'KIMI_CODE_NO_AUTO_UPDATE': '1',
        'KIMI_CLI_NO_AUTO_UPDATE': '1',
        'KIMI_SHELL_PATH': '/bin/bash',
        # Directory watching: FSEvents is blocked in the sandbox (allowing it leaks file names from read-denied paths), and the
        # internal FSWatcher of chokidar has no error listener, so that EMFILE kills the process. chokidar switches to stat polling
        # and the preload turns the remaining directory fs.watch into an inert watcher. With only one of the two it still dies or is noisy.
        'CHOKIDAR_USEPOLLING': '1',
        'NODE_OPTIONS': '--require ' + json.dumps(str(WATCH_BOOTSTRAP), ensure_ascii=False),
    }


def prepare_kimi_home(region, binary=None):
    """Build the preparation function that writes the region marker into the isolated home link-safely and adds the Kimi environment variables before launch.

    The isolated home path decided by run_confined arrives through a callback. Calling persistent_home here in advance would create an
    empty home under `state/homes/kimi/` even without a launch (for example a wiring test). run_confined locks the region marker with denyWrite.
    """
    def prepare(home, env):
        agentbelt.write_private_file(home, REGION_MARKER_RELATIVE, region + '\n')
        env.update(kimi_environment(home, binary))
    return prepare


def run_kimi(arguments):
    """Entry point for `agentbelt kimi -- <kimi args>`. The current directory is the workspace."""
    workspace = agentbelt.workspace_path(os.getcwd())
    agentbelt.verify_kimi_binary()
    profile = load_profile()
    development = agentbelt.development_options()
    publish = agentbelt.pub_publish_grant(workspace)
    publish_credentials = [('dart/pub-credentials.json', agentbelt.PUB_CREDENTIALS)] if publish is not None else []
    publish_notice = ('\n## Publishing to pub.dev\n\nThis workspace is allowed to run `dart pub publish`. Use `--dry-run` freely; '
                      'publish for real only when the user asks for it.\n' if publish is not None else '')
    domains = sorted(set(profile['domains'] + development['packageDomains']
                         + (agentbelt.PUB_PUBLISH_DOMAINS if publish is not None else [])))
    # To block a swap between verification and launch, verify a guard-owned copy and run only that. The read allowance is for the copy too.
    staged = agentbelt.stage_kimi_binary()
    try:
        return launch_kimi(workspace, staged, arguments, domains, profile, development, publish_credentials,
                           KIMI_NOTICE + publish_notice)
    finally:
        agentbelt.discard_staged_binary(staged)


def launch_kimi(workspace, binary, arguments, domains, profile, development, publish_credentials, notice):
    """Call run_confined with the verified copy. Split out of run_kimi so the cleanup (finally) and the wiring can be checked separately."""
    # 브라우저가 없는 자식을 위한 호스트 스크린샷 큐 — 이미 떠 있으면 재사용한다.
    agentbelt.ensure_shot_watcher(workspace)
    return agentbelt.run_confined(
        'kimi', workspace, [str(binary), *arguments], domains,
        extra_reads=[binary, WATCH_BOOTSTRAP],
        prepare_home=prepare_kimi_home(profile['region'], binary),
        read_only_home_paths=[REGION_MARKER_RELATIVE],
        dev_ports=development['devPorts'],
        instruction_files=[INSTRUCTIONS_RELATIVE],
        notice_extra=notice,
        loopback_port=True, github=True,
        config_credentials=publish_credentials,
        loopback_all=agentbelt.loopback_grant(workspace),
        allow_gradle_keystore=agentbelt.gradle_keystore_grant(workspace))
