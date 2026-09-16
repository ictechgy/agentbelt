#!/usr/bin/python3
"""Install the AutoClaw coding runtime so that it runs through the agent-guard launcher.

What it does: (1) record the reviewed AutoClaw app and bundled Zcode CLI in the profile and the compatibility baseline,
(2) install the `~/.local/bin/autoclaw-zcode-safe` launcher, (3) change the `command` of the zcode-runtime plugin in
`~/.openclaw-autoclaw/openclaw.json` to the launcher and have the two model broker address variables passed through with
envPassthrough. Other settings (models, API keys and so on) are read but not changed. It is safe to run again, and the
original is kept in state/backups only once. A binary that differs from the already recorded baseline is not blessed
without `--rebaseline`. `--deny-host-exec` blocks the outer agent's host exec through the tool policy, and
`--discord-guild`/`--discord-dm` open Discord remote control to your own ID only.
"""
import argparse
import fcntl
import json
import os
import pwd
from pathlib import Path
import re
import shlex
import sys
import time

ROOT = Path(__file__).resolve().parents[1]  # install/repo root; this file lives in adapters/
sys.path.insert(0, str(ROOT))
import agent_guard
from adapters import compatibility_check
from adapters.configure_existing import publish_settings

HOME = Path(pwd.getpwuid(os.getuid()).pw_dir)  # The home from the account database (not the environment variable)
STATE = ROOT / 'state'
OPENCLAW_STATE = HOME / '.openclaw-autoclaw'
BROKER_VARIABLES = ['AUTOCLAW_MODEL_BROKER_OPENAI_BASE_URL', 'AUTOCLAW_MODEL_BROKER_ANTHROPIC_BASE_URL']


def launcher_path():
    """The path of the launcher the AutoClaw plugin calls as `command`."""
    return HOME / '.local/bin/autoclaw-zcode-safe'


def launcher_exec_line():
    """The last line of the launcher. It passes on the arguments the plugin hands over (version / agent-server) unchanged."""
    return 'exec /usr/bin/python3 -I ' + shlex.quote(str(ROOT / 'agent_guard.py')) + ' autoclaw-backend "$@"\n'


def launcher_text():
    """The launcher body. For an `agent-server` call the shell records `sh-start` before Python is reached.

    In one Discord channel incident the launcher started by the gateway never reached even Python's first line
    (`started`), while every reproduction on the supervisor side was normal. Only when the shell itself leaves evidence
    can we tell whether it stopped during shell startup, the python3 shuttle or Python startup. The pid carries through
    exec, so it is the same pid as the Python stage. A failed record does not block execution. If the log slot or
    `state/runtime` is a link it is not written (the same intent as O_NOFOLLOW and private_dir on the Python side), and
    if the log is not a regular file it is skipped (with a FIFO, `>>` waits for a reader and stalls before exec). A new
    file is made 0600 through the subshell umask (the child's umask is left alone). The version probe is not recorded --
    recording it would be misread as "no python-start". The decision on the Python side
    (`is_autoclaw_agent_server_call`) uses the same criterion (the first argument only).
    """
    log = shlex.quote(str(ROOT / 'state/runtime/autoclaw-launches.log'))
    return ('#!/bin/sh\n'
            'log=' + log + '\n'
            '[ "$1" = agent-server ] && [ ! -L "${log%/*}" ] && [ ! -L "$log" ] && { [ ! -e "$log" ] || [ -f "$log" ]; } && '
            '( umask 077; printf \'%s pid=%s stage=sh-start cwd=%s\\n\' '
            '"$(/bin/date +%Y-%m-%dT%H:%M:%S)" "$$" "$PWD" >> "$log" ) 2>/dev/null\n'
            + launcher_exec_line())


def previous_launcher_texts():
    """Earlier guard launcher bodies that a reinstall may recognize and replace. Anything not listed here is treated as an unfamiliar launcher and refused.

    Every time the body changes, add the immediately preceding body here (2026-09-15: the two-line original, the first sh-start edition).
    """
    log = shlex.quote(str(ROOT / 'state/runtime/autoclaw-launches.log'))
    first_stage_logging = ('#!/bin/sh\n'
                           'log=' + log + '\n'
                           '[ "$1" = agent-server ] && [ ! -L "$log" ] && ( umask 077; printf \'%s pid=%s stage=sh-start cwd=%s\\n\' '
                           '"$(/bin/date +%Y-%m-%dT%H:%M:%S)" "$$" "$PWD" >> "$log" ) 2>/dev/null\n'
                           + launcher_exec_line())
    return ['#!/bin/sh\n' + launcher_exec_line(), first_stage_logging]


def read_bundle():
    """Read the version and the bundled CLI hash from the installed AutoClaw app. If the app is missing, refuse to install."""
    bundle = compatibility_check.autoclaw_candidate(agent_guard.AUTOCLAW_APP)
    if bundle is None:
        raise RuntimeError('AutoClaw.app is not installed; nothing to protect.')
    return bundle


def check_launcher_directory(directory):
    """The launcher directory must not be a link, must be owned by me and must not be writable by group or others. Otherwise the launcher gets swapped out."""
    if directory.is_symlink():
        raise RuntimeError('Refusing a symlinked launcher directory')
    info = directory.stat()
    if not directory.is_dir() or info.st_uid != os.getuid() or info.st_mode & 0o022:
        raise RuntimeError('The launcher directory must be a private directory owned by you (no group/other write).')


def install_launcher():
    """Create the launcher with mode 0700. Identical content is left alone, an earlier guard launcher at 0700 is replaced, and any other file is not overwritten.

    The replacement writes everything to a temporary file in the same directory, fsyncs it and then renames -- unlinking
    and creating anew would, if the gateway started the launcher in between, run a missing or empty script. A temporary
    file left behind by an earlier failure is cleared away before continuing.
    """
    path = launcher_path()
    check_launcher_directory(path.parent)
    if path.is_symlink():
        raise RuntimeError('Refusing a symlinked launcher path')
    temporary = '.' + path.name + '.tmp'
    directory = os.open(str(path.parent), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        if path.exists():
            current = path.read_text()
            if current == launcher_text() and path.stat().st_mode & 0o777 == 0o700:
                return
            if current not in previous_launcher_texts() or path.stat().st_mode & 0o777 != 0o700:
                raise RuntimeError('A different autoclaw-zcode-safe launcher already exists; remove it first.')
        if (path.parent / temporary).is_symlink() or (path.parent / temporary).exists():
            os.unlink(temporary, dir_fd=directory)
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o700, dir_fd=directory)
        with os.fdopen(descriptor, 'w') as stream:
            stream.write(launcher_text())
            stream.flush()
            os.fsync(stream.fileno())
        os.rename(temporary, path.name, src_dir_fd=directory, dst_dir_fd=directory)
    finally:
        os.close(directory)


def load_openclaw_config():
    """Read the AutoClaw configuration file. Refuse if it is a link or missing (that is, if the app has never been launched)."""
    path = OPENCLAW_STATE / 'openclaw.json'
    if path.is_symlink():
        raise RuntimeError('Refusing a symlinked openclaw.json')
    if not path.is_file():
        raise RuntimeError('openclaw.json is missing; launch AutoClaw once and quit it first.')
    return path, json.loads(path.read_text())


def patched_plugin_entry(entry):
    """A copy of the zcode-runtime entry with the launcher and envPassthrough put in. Other keys are kept."""
    entry = dict(entry or {})
    config = dict(entry.get('config') or {})
    config.update({'command': str(launcher_path()), 'args': [], 'envPassthrough': list(BROKER_VARIABLES),
                   'runtimeEnabled': True,
                   # The default 30 second handshake cannot wait out the hard link check on a large workspace (900,000 files = 25 seconds) plus the first startup.
                   'requestTimeoutMs': 180000})
    entry.update({'enabled': True, 'config': config})
    return entry


def backup_once(path, data):
    """Keep the original in state/backups only once. If a kept copy already exists, do not make a new one."""
    backups = agent_guard.private_dir(STATE / 'backups')
    if any(backups.glob(path.name + '.*')):
        return
    target = backups / (path.name + '.' + time.strftime('%Y%m%d-%H%M%S'))
    descriptor = os.open(str(target), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, 'wb') as stream:
        stream.write(data)


def reviewed_baseline(existing, bundle, rebaseline):
    """If there is a recorded baseline and it differs from the current bundle, do not change it without an explicit --rebaseline."""
    if existing and existing != bundle and not rebaseline:
        raise RuntimeError('AutoClaw bundle differs from the reviewed baseline (recorded ' + existing.get('zcodeSha256', '?')[:12]
                           + ', installed ' + bundle['zcodeSha256'][:12] + '). Review the update, then rerun with --rebaseline.')
    return bundle


# exec/process: the host shell. gateway: a tool with which the agent can edit openclaw.json through config.patch/apply or
# restart it, so it can undo this lockdown itself (2026-09-14: observed a model digging through the settings with config.schema.lookup).
HOST_EXEC_TOOLS = {'exec', 'process', 'gateway'}
# AutoClaw's zcode-runtime exposes zcode_run only to this agent id (extensions/zcode-runtime/agent-context.js).
ZCODE_OWNER_AGENT_ID = 'auto-coder'
DISCORD_USER_ID = re.compile(r'^[0-9]{17,20}$')


def deny_host_exec_tools(tools):
    """A copy of tools with the outer OpenClaw agent's host exec, process and gateway tools blocked. Coding then goes only through the zcode path.

    AutoClaw's remote settings refresh puts `exec.security` back to `full`, so the real lock is the tool policy `deny`
    (OpenClaw documentation: "To hard-disable exec, deny it via tool policy"). elevated is turned off as well so that
    `/elevated` from a channel cannot revive it.
    """
    tools = dict(tools or {})
    tools['exec'] = dict(tools.get('exec') or {}, security='deny')
    tools['deny'] = sorted(set(tools.get('deny') or []) | HOST_EXEC_TOOLS)
    tools['elevated'] = dict(tools.get('elevated') or {}, enabled=False)
    return tools


def deny_host_exec_agents(agents):
    """A copy of agents with the same deny put into each agent's tool policy as well. Even if the global policy is reverted, the agent-scoped one remains."""
    agents = dict(agents or {})
    entries = []
    for agent in agents.get('list') or []:
        agent = dict(agent)
        tools = dict(agent.get('tools') or {})
        tools['deny'] = sorted(set(tools.get('deny') or []) | HOST_EXEC_TOOLS)
        tools['elevated'] = dict(tools.get('elevated') or {}, enabled=False)
        agent['tools'] = tools
        entries.append(agent)
    agents['list'] = entries
    return agents


def discord_accounts(channels):
    """A copy of the dictionary of configured Discord accounts. If there is none, the bot has to be connected in the app first."""
    channels = dict(channels or {})
    discord = dict(channels.get('discord') or {})
    accounts = dict(discord.get('accounts') or {})
    if not accounts:
        raise RuntimeError('No Discord account is configured in AutoClaw; connect the bot in the app first.')
    return channels, discord, accounts


def snowflakes(values, what):
    """Only Discord IDs (17-20 digit numbers) are accepted. `*`, access groups and names are rejected because they enlarge the remote control surface."""
    if isinstance(values, (str, bytes)):
        raise RuntimeError('Discord ' + what + ' must be a list of IDs, not a single string.')
    values = [str(value) for value in (values or [])]
    if not values or any(not DISCORD_USER_ID.match(value) for value in values):
        raise RuntimeError('Discord ' + what + ' must be numeric Discord IDs (17-20 digits).')
    return values


def discord_dm_allowlist(channels, user_ids):
    """A copy of channels in which DMs on every Discord account are allowed only from the given user IDs. Server policy and tokens are left as they are."""
    users = snowflakes(user_ids, 'user IDs')
    channels, discord, accounts = discord_accounts(channels)
    for name, account in accounts.items():
        accounts[name] = dict(account or {}, dmPolicy='allowlist', allowFrom=users)
    discord['accounts'] = accounts
    channels['discord'] = discord
    return channels


def discord_guild_allowlist(channels, user_ids, guild_id, channel_id=None):
    """A copy of channels for driving the agent from a private server channel. DMs are not touched (they stay off).

    Only one server goes on the allowlist, and inside it `users` pins the sender to your own ID. Even if somebody else
    is invited to the server, that person's messages are ignored. If a channel ID is given, anything outside that
    channel is refused. Since you are the only one in the server, a mention is not required.
    """
    users = snowflakes(user_ids, 'user IDs')
    guild = snowflakes([guild_id], 'server ID')[0]
    entry = {'requireMention': False, 'users': users}
    if channel_id is not None:
        entry['channels'] = {snowflakes([channel_id], 'channel ID')[0]: {'allow': True}}
    channels, discord, accounts = discord_accounts(channels)
    for name, account in accounts.items():
        accounts[name] = dict(account or {}, groupPolicy='allowlist', guilds={guild: entry})
    discord['accounts'] = accounts
    channels['discord'] = discord
    return channels


AGENT_TOOLS_NOTE = """# TOOLS.md - Local Notes

### Execution rules for this environment (agent-guard)

- This installation has **no** host shell tools: `exec`, `process` and `gateway` were removed on purpose. Do not ask for them to be enabled.
- This workspace is only the coordinator's notes folder. The project repository is not here. Send every read, edit and command
  against the repository (including `git status`, tests, builds and file deletion) through **`zcode_run`**. The session is already bound to the project.
  Example: prompt="Run `git status` and `git diff --stat` and report the output verbatim."
- Do not hand repository work to a subagent (`sessions_spawn`). A subagent session has no workspace binding, so
  `zcode_run` is refused there. Call it directly from this session.
- The Zcode inside `zcode_run` runs in the macOS sandbox and no approval dialog appears. Wait for the result and report it verbatim.
"""


def private_agent_workspace_path(agent_id):
    """The agent's private notes folder (the same location as AutoClaw's default layout)."""
    if not re.match(r'^[A-Za-z0-9_-]{1,64}$', agent_id or ''):
        raise RuntimeError('Agent id must be a short identifier.')
    return OPENCLAW_STATE / 'agents' / agent_id / 'workspace'


def relocate_agent_workspace(agents, agent_id):
    """A copy of agents with that agent's workspace changed to the private folder. Other keys and other agents are left as they are."""
    agents = dict(agents or {})
    entries = []
    found = False
    for agent in agents.get('list') or []:
        agent = dict(agent)
        if agent.get('id') == agent_id:
            agent['workspace'] = str(private_agent_workspace_path(agent_id))
            found = True
        entries.append(agent)
    if not found:
        raise RuntimeError('No agent with id ' + agent_id + ' in openclaw.json.')
    agents['list'] = entries
    return agents


def seed_private_workspace(agent_id):
    """Create the private folder with mode 0700 and plant the execution rules note (TOOLS.md). If it already exists, only make sure the note is there."""
    directory = private_agent_workspace_path(agent_id)
    directory.mkdir(parents=True, exist_ok=True)
    directory.chmod(0o700)
    note = directory / 'TOOLS.md'
    if note.is_symlink():
        raise RuntimeError('Refusing a symlinked TOOLS.md')
    if not note.is_file() or 'Execution rules for this environment (agent-guard)' not in note.read_text():
        with open(note, 'a', encoding='utf-8') as stream:
            stream.write(('' if not note.exists() or note.stat().st_size == 0 else '\n') + AGENT_TOOLS_NOTE)


def rebind_discord_agent(config, agent_id):
    """A copy of bindings with the agentId of the Discord channel binding changed. Other channel bindings are left as they are.

    AutoClaw's zcode-runtime exposes `zcode_run` only to the agent id `auto-coder` (hard coded in agent-context.js), so
    binding Discord to a different agent makes confined coding impossible.
    """
    if not any(agent.get('id') == agent_id for agent in (config.get('agents') or {}).get('list') or []):
        raise RuntimeError('No agent with id ' + agent_id + ' in openclaw.json.')
    if agent_id != ZCODE_OWNER_AGENT_ID:
        raise RuntimeError('zcode_run is only exposed to agent ' + ZCODE_OWNER_AGENT_ID + '; binding Discord to ' + agent_id + ' disables guarded coding.')
    bindings = []
    changed = False
    for binding in config.get('bindings') or []:
        binding = dict(binding)
        if (binding.get('match') or {}).get('channel') == 'discord':
            binding['agentId'] = agent_id
            changed = True
        bindings.append(binding)
    if not changed:
        raise RuntimeError('No Discord binding found in openclaw.json; connect the bot in the app first.')
    return bindings


def install(rebaseline=False, deny_host_exec=True, discord_users=None, discord_dm=False, discord_guild=None, discord_channel=None,
            private_agent_workspace=None, discord_agent=None):
    """Carry out the actual installation inside the lock. Blocking host exec is the default (no fail-open install)."""
    if discord_dm and discord_guild is not None:
        raise RuntimeError('Choose one Discord path: --discord-guild or --discord-dm, not both.')
    if discord_users is not None and not discord_users:
        raise RuntimeError('--discord-users needs at least one numeric Discord user ID.')
    bundle = read_bundle()
    config_path, config = load_openclaw_config()
    plugins = dict(config.get('plugins') or {})
    entries = dict(plugins.get('entries') or {})
    entries['zcode-runtime'] = patched_plugin_entry(entries.get('zcode-runtime'))
    plugins['entries'] = entries
    updated = dict(config, plugins=plugins)
    if deny_host_exec:
        updated['tools'] = deny_host_exec_tools(config.get('tools'))
        updated['agents'] = deny_host_exec_agents(config.get('agents'))
    if private_agent_workspace is not None:
        updated['agents'] = relocate_agent_workspace(updated.get('agents') or config.get('agents'), private_agent_workspace)
        seed_private_workspace(private_agent_workspace)
    if discord_agent is not None:
        updated['bindings'] = rebind_discord_agent(config, discord_agent)
    if discord_users is not None:
        if discord_guild is not None:
            updated['channels'] = discord_guild_allowlist(config.get('channels'), discord_users, discord_guild, discord_channel)
        elif discord_dm:
            updated['channels'] = discord_dm_allowlist(config.get('channels'), discord_users)
        else:
            raise RuntimeError('Choose the Discord path: --discord-guild SERVER_ID (private server channel) or --discord-dm.')
    existing_profile = STATE / 'autoclaw-profile.json'
    profile = json.loads(existing_profile.read_text()) if existing_profile.is_file() else {'domains': []}
    profile.update({'reviewedAppVersion': bundle['version'], 'zcodeCliVersion': bundle['zcodeCliVersion']})
    baseline_path = STATE / 'compatibility.json'
    baseline = json.loads(baseline_path.read_text()) if baseline_path.is_file() else {}
    baseline['autoclaw'] = reviewed_baseline(baseline.get('autoclaw'), bundle, rebaseline)
    install_launcher()
    if updated != config:
        backup_once(config_path, config_path.read_bytes())
    publish_settings({existing_profile: profile, baseline_path: baseline, config_path: updated})
    print('AutoClaw zcode-runtime now launches ' + str(launcher_path()))
    print('Reviewed AutoClaw ' + bundle['version'] + ' with bundled Zcode CLI ' + bundle['zcodeCliVersion'])


def main(rebaseline=False, deny_host_exec=True, discord_users=None, discord_dm=False, discord_guild=None, discord_channel=None,
         private_agent_workspace=None, discord_agent=None):
    """Install while holding the same lock as the other settings publishers (configure_existing, verify-updates)."""
    state = agent_guard.private_dir(STATE)
    descriptor = os.open(str(state / '.settings-import.lock'), os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, 'w') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        install(rebaseline, deny_host_exec, discord_users, discord_dm, discord_guild, discord_channel, private_agent_workspace,
                discord_agent)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--rebaseline', action='store_true', help='Accept a bundle whose hash differs from the recorded baseline.')
    parser.add_argument('--deny-host-exec', action='store_true', default=True,
                        help='(default) Deny the exec/process/gateway tools (global and per agent) and elevated exec for the outer AutoClaw agent.')
    parser.add_argument('--allow-host-exec', dest='deny_host_exec', action='store_false',
                        help='Leave the outer agent host exec/gateway tools as they are (not recommended).')
    parser.add_argument('--discord-users', metavar='USER_ID[,USER_ID]',
                        help='Numeric Discord user IDs allowed to drive the agent (required with --discord-guild or --discord-dm).')
    parser.add_argument('--discord-guild', metavar='SERVER_ID',
                        help='Private server path: groupPolicy=allowlist for this server only, senders limited to --discord-users; DMs stay as they are.')
    parser.add_argument('--discord-channel', metavar='CHANNEL_ID', help='With --discord-guild: allow only this channel in the server.')
    parser.add_argument('--discord-dm', action='store_true', help='DM path: dmPolicy=allowlist with --discord-users on every account.')
    parser.add_argument('--private-agent-workspace', metavar='AGENT_ID',
                        help='Move this agent\'s workspace off the repository to ~/.openclaw-autoclaw/agents/<id>/workspace and seed TOOLS.md.')
    parser.add_argument('--discord-agent', metavar='AGENT_ID',
                        help='Route the Discord channel binding to this agent (zcode_run is only exposed to auto-coder).')
    options = parser.parse_args()
    users = [part.strip() for part in options.discord_users.split(',') if part.strip()] if options.discord_users is not None else None
    try:
        main(options.rebaseline, options.deny_host_exec, users, options.discord_dm, options.discord_guild, options.discord_channel,
             options.private_agent_workspace, options.discord_agent)
    except RuntimeError as error:
        # Show only wording the guard produced. Configuration parser exceptions can have fragments of credentials mixed in.
        raise SystemExit('install_autoclaw: ' + str(error))
    except Exception:
        raise SystemExit('install_autoclaw: failed; no credential values are shown. Inspect the local setup before retrying.')
