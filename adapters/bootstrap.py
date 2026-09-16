"""`agentbelt init`: create the state a fresh installation needs, for the agents that are actually installed.

Why. `install.sh` copies code and pins Node, but every mode also needs state under `<install>/state/`: the reviewed
package-domain list, the riskgate policy used by the Zcode hook, the Zcode profiles and Safe app, the packet-ask
version gate, and the compatibility baseline (binary hashes) that every launch is checked against. Those used to
exist only on the original operator's machine, so a second installation had no path to a working `doctor`.

Trust on first install. The baseline recorded here is the hash of whatever is installed right now; it is the
operator's job to install the agents from trusted sources first. Afterwards a changed binary refuses to launch until
`agentbelt verify-updates` re-runs the test suite and records the new hash. `init` never overwrites an existing
file, so re-running it after an upgrade is safe and only fills in what is missing.
"""
import json
import os
from pathlib import Path
import shutil
import sys

ROOT = Path(__file__).resolve().parents[1]  # install/repo root; this file lives in adapters/
sys.path.insert(0, str(ROOT))
import agentbelt  # noqa: E402

# Shipped example policy, installed only when the operator has none.
EXAMPLE_RISKGATE_POLICY = ROOT / 'examples/riskgate.yaml'


def default_development_options():
    """Public defaults: every reviewed package registry, no development ports, no temp-folder grants."""
    return {'devPorts': [], 'packageDomains': sorted(agentbelt.PUBLIC_PACKAGE_DOMAINS), 'darwinTempDirectories': []}


def ensure_json(path, value, created):
    """Write `value` as 0600 JSON unless `path` already exists (never overwrite operator edits)."""
    if path.is_symlink():
        raise agentbelt.GuardError('Refusing a symlink at a state file: ' + str(path))
    if path.exists():
        return False
    agentbelt.write_private_json(path, value)
    created.append(path)
    return True


def ensure_riskgate(state, created):
    """Install the example policy when the operator has none and point the manifest at the policy path.

    The Zcode hook refuses to run without a policy, so a missing policy closes the Zcode modes rather than opening them.
    """
    policy = agentbelt.OWNER_HOME / '.config/riskgate/riskgate.yaml'
    if policy.is_symlink():
        raise agentbelt.GuardError('The riskgate policy path is a symlink; refusing to use it.')
    if not policy.is_file() and EXAMPLE_RISKGATE_POLICY.is_file():
        policy.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        shutil.copyfile(str(EXAMPLE_RISKGATE_POLICY), str(policy))
        os.chmod(policy, 0o600)
        created.append(policy)
    ensure_json(state / 'riskgate.json', {'enabled': policy.is_file(), 'policy': str(policy)}, created)
    return policy.is_file()


def packet_ask_version():
    """Version of an installed packet-ask tool from its dist-info name, or None when it is not installed."""
    for entry in sorted(agentbelt.PACKET_VENV.glob('lib/python*/site-packages/packet_ask-*.dist-info')):
        version = entry.name[len('packet_ask-'):-len('.dist-info')]
        if version.count('.') == 2 and all(part.isdigit() for part in version.split('.')):
            return version
    return None


def ensure_zcode_profiles(state, created, report):
    """Create the Zcode profiles, backend launcher and Safe app when Zcode is installed and they do not exist yet."""
    if not Path('/Applications/ZCode.app/Contents/Info.plist').is_file():
        report.append('zcode: not installed; Zcode Safe modes stay closed')
        return
    if (state / 'zcode-profile.json').is_file():
        report.append('zcode: profiles present')
        return
    if not (ROOT / 'native/ZcodeSafeLauncher').is_file():
        report.append('zcode: native launcher missing (install.sh builds it when swiftc is available); profiles not created')
        return
    from adapters import install_profiles
    try:
        install_profiles.main()
    except RuntimeError as error:
        # A Zcode Safe.app or backend launcher from another installation root already exists; never replace it here.
        report.append('zcode: not initialized (' + str(error) + '); remove the previous Zcode Safe installation first')
        return
    created.extend([state / 'zcode-profile.json', state / 'zcode-agent-config.json'])
    report.append('zcode: profiles, backend launcher and Zcode Safe.app created')


def ensure_baseline(state, created, report):
    """Record hashes for installed agents that have no baseline yet; existing entries are never replaced here."""
    from adapters.compatibility_check import candidate, merged_baseline
    current = candidate()
    path = state / 'compatibility.json'
    saved = json.loads(path.read_text()) if path.is_file() else {}
    added = [name for name in current if name not in saved]
    if not current and not saved:
        report.append('baseline: no supported agent installed (OpenCode, Zcode, AutoClaw, Kimi Code)')
        return
    if added:
        merged = merged_baseline(current, saved)
        for name in saved:
            merged[name] = saved[name]  # existing reviewed entries win; verify-updates is the only path that changes them
        if path.exists():
            path.unlink()
        agentbelt.write_private_json(path, merged)
        created.append(path)
        report.append('baseline: recorded ' + ', '.join(added) + ' (trust on first install; verify-updates re-checks later)')
    else:
        report.append('baseline: present for ' + ', '.join(sorted(current)) if current else 'baseline: present')


def initialize():
    """Entry point of `agentbelt init`. Prints what was created and what each agent still needs."""
    state = agentbelt.private_dir(ROOT / 'state')
    created, report = [], []
    if ensure_json(state / 'development.json', default_development_options(), created):
        report.append('development.json: reviewed package registries enabled, no ports, no temp grants')
    riskgate = ensure_riskgate(state, created)
    report.append('riskgate: policy ' + ('present' if riskgate else 'missing; Zcode modes closed'))
    version = packet_ask_version()
    if version is not None:
        if ensure_json(state / 'packet-ask-version.json', {'version': version}, created):
            report.append('packet-ask: pinned installed version ' + version)
    else:
        report.append('packet-ask: not installed; packet modes closed')
    ensure_zcode_profiles(state, created, report)
    ensure_baseline(state, created, report)
    for line in report:
        print(line)
    print('created:', ', '.join(str(path) for path in created) if created else '(nothing; already initialized)')
    print('next: agentbelt doctor; then adapters/configure_existing.py --authorized-live-settings for OpenCode, or cd <project> && safekimi')
    return 0
