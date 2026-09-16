"""Preserve the host supervisor's restricted proxy through packet-ask's env reset."""
import os
import sys
from importlib.metadata import version

# The supervisor passes the reviewed version through an environment variable. If it is missing or different, the adapter is not loaded (fail closed).
_expected = os.environ.get('AGENTBELT_PACKET_ASK_VERSION', '')
if not _expected or version('packet-ask') != _expected:
    sys.exit('agentbelt: packet-ask version is not the reviewed one; review the confinement adapter before launching.')

import packet_ask.paths as paths

# Only the names the product hook allows. The child gets the supervisor's
# restricted proxy set (8 names), git gets DEVELOPER_DIR. No value validation:
# the hook runs in-process, so the caller owns the values. os.environ is read
# at call time, the same moment the old monkeypatch wrappers saw it. The
# product pins the isolated Claude tmp variables itself, so the adapter no
# longer repeats them. One registration covers every call site (paths, scope,
# launch, doctor) because those modules call the same paths functions.
_PROXY_NAMES = ('HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY', 'NO_PROXY',
                'http_proxy', 'https_proxy', 'all_proxy', 'no_proxy')
_DEVELOPER_DIR = '/Library/Developer/CommandLineTools'


def _proxy_extra():
    return {name: os.environ[name] for name in _PROXY_NAMES if name in os.environ}


def _git_extra():
    return {'DEVELOPER_DIR': _DEVELOPER_DIR}


paths.set_confined_env_hooks(child=_proxy_extra, git=_git_extra)
from packet_ask.cli import main

sys.exit(main())
