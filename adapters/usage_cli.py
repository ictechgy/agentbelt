"""usage mode that runs the Token Plan usage CLI (`bl`, bailian-cli) confined.

Why confine it. Through `bl config agent`, `bl` can touch the settings of other agents such as
`CLAUDE_CONFIG_DIR` and `CODEX_HOME`, and it keeps the console login token. Instead of installing it
globally on the host, it is installed only inside a guard-owned isolated home, so user projects, the real
home, other isolated homes, and the Keychain stay invisible under the existing Seatbelt policy.

Console login stays inside Seatbelt too. A scoped preload maps the CLI's random loopback callback to
the one port granted by the supervisor. The CLI prints its login URL when browser opening is denied;
the operator opens that URL manually. No executable from the writable isolated home runs on the host.
"""
import hashlib
import json
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]  # install/repo root; this file lives in adapters/
sys.path.insert(0, str(ROOT))
import agentbelt  # noqa: E402

# Policy file for usage mode. Change the domains, the CLI version, and the console site/region only here.
PROFILE_PATH = ROOT / 'state/usage-profile.json'
# Install prefix for bl inside the isolated home. With npm --prefix it lands in node_modules under this.
CLI_PREFIX = 'bl-prefix'


def default_profile():
    """Reviewed default policy. Allows only the international site console gateway and the Token Plan host.

    The mainland China gateway is not included. The Token Plan endpoint of the user is ap-southeast-1.
    """
    return {
        'cliVersion': '1.21.0',
        'consoleSite': 'international',
        'consoleRegion': 'ap-southeast-1',
        'domains': [
            'bailian-singapore-cs.alibabacloud.com:443',   # ap-southeast-1 international console gateway
            'bailian-cs.console.alibabacloud.com:443',     # cn-beijing international console gateway
            'modelstudio.console.alibabacloud.com:443',    # international console (login redirect)
            'token-plan.ap-southeast-1.maas.aliyuncs.com:443',
        ],
    }


def load_profile():
    """Read the policy file. If it is missing, create the default with mode 0600."""
    if not PROFILE_PATH.is_file():
        agentbelt.private_dir(PROFILE_PATH.parent)
        agentbelt.write_private_json(PROFILE_PATH, default_profile())
    profile = json.loads(PROFILE_PATH.read_text())
    if not isinstance(profile.get('domains'), list) or not profile['domains']:
        raise agentbelt.GuardError('state/usage-profile.json needs a non-empty domains list.')
    return profile


def usage_workspace():
    """Guard-owned empty workspace. A user project is never used."""
    return agentbelt.private_dir(agentbelt.private_dir(ROOT / 'state') / 'usage-workspace')


def usage_home():
    """The same path as the persistent isolated home run_confined uses for mode='usage'."""
    identity = hashlib.sha256(str(usage_workspace()).encode()).hexdigest()[:20]
    state = ROOT / 'state'
    return agentbelt.private_dir(agentbelt.private_dir(agentbelt.private_dir(state / 'homes') / 'usage') / identity)


def bl_entry(home):
    """The bl entry script installed inside the isolated home."""
    return home / CLI_PREFIX / 'node_modules/bailian-cli/dist/bailian.mjs'


def install_command(profile):
    """Shell command that installs the pinned version of bailian-cli into the isolated home prefix."""
    version = profile['cliVersion']
    if not all(part.isdigit() for part in version.split('.')):
        raise agentbelt.GuardError('usage-profile cliVersion must be a plain semantic version.')
    return ['/bin/bash', '--noprofile', '--norc', '-c',
            'mkdir -p "$HOME/' + CLI_PREFIX + '" && npm install --prefix "$HOME/' + CLI_PREFIX
            + '" --no-audit --no-fund --loglevel=error bailian-cli@' + version]


def query_command(home, profile, extra):
    """The bl command to run inside the sandbox. With no arguments it is the Token Plan summary."""
    entry = bl_entry(home)
    if not entry.is_file():
        raise agentbelt.GuardError('bl is not installed in the isolated home yet; run agentbelt usage setup first.')
    if extra:
        return [str(agentbelt.NODE), str(entry), *extra]
    return [str(agentbelt.NODE), str(entry), 'usage', 'token-plan',
            '--console-site', profile['consoleSite'], '--console-region', profile['consoleRegion']]


def host_time_zone():
    """The time zone name of the host. The sandbox cannot read zoneinfo files and prints UTC, so only the name is passed.

    Node resolves a TZ name with its built-in ICU data, so no file access is needed.
    """
    try:
        target = os.readlink('/etc/localtime')
    except OSError:
        return 'UTC'
    marker = 'zoneinfo/'
    name = target.split(marker, 1)[1] if marker in target else ''
    return name if name and all(c.isalnum() or c in '/_-+' for c in name) else 'UTC'


def run_sandboxed(command, domains):
    """Run bl inside Seatbelt with the guard-owned workspace and the persistent isolated home."""
    # On every run bl prints two lines of the Node experimental feature warning (UNDICI-EHPA) that hide the result.
    status = agentbelt.run_confined('usage', usage_workspace(), command, sorted(set(domains)),
                                      extra_env={'TZ': host_time_zone(), 'NODE_OPTIONS': '--no-warnings'},
                                      github=False, short_tmpdir=True)
    if status == 3:
        # Exit code 3 from bl means an authentication problem. The guidance of bl (`bl auth login --console`) stores into the
        # host home, so point at our command that uses the isolated home instead.
        print('token-usage: the console login is missing or expired. Log in again with `token-usage login`.', file=sys.stderr)
    return status


def login_in_sandbox(home):
    """Keep even a modified CLI confined; open only its one browser callback port."""
    entry = bl_entry(home)
    if not entry.is_file():
        raise agentbelt.GuardError('bl is not installed in the isolated home yet; run agentbelt usage setup first.')
    profile = load_profile()
    bootstrap = ROOT / 'usage_login_bootstrap.cjs'
    print('Open the login URL printed below in your browser. Login stays inside the sandbox.', file=sys.stderr)
    return agentbelt.run_confined(
        'usage', usage_workspace(),
        [str(agentbelt.NODE), str(entry), 'auth', 'login', '--console', '--console-site', profile['consoleSite']],
        domains=profile['domains'], extra_reads=[bootstrap],
        extra_env={'BAILIAN_CONFIG_DIR': str(home / '.bailian'), 'TZ': host_time_zone(),
                   'AGENTBELT_USAGE_LOGIN_ENTRY': str(entry),
                   'NODE_OPTIONS': '--no-warnings --import ' + bootstrap.as_uri()},
        loopback_port=True, github=False, short_tmpdir=True)


def run_usage(arguments):
    """Entry point for `agentbelt usage [setup|login|-- <bl args>]`."""
    profile = load_profile()
    home = usage_home()
    if arguments == ['setup']:
        development = agentbelt.development_options()
        status = run_sandboxed(install_command(profile), profile['domains'] + development['packageDomains'])
        if status != 0:
            raise agentbelt.GuardError('bailian-cli install failed inside the isolated home; see npm output above.')
        return login_in_sandbox(home)
    if arguments == ['login']:
        return login_in_sandbox(home)
    return run_sandboxed(query_command(home, profile, arguments), profile['domains'])
