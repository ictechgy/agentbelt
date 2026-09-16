"""Host-side adapters and operator tools.

Everything here runs outside the sandbox (as the supervisor or as an operator command) and may import
`agentbelt`. Nothing in this package is read or executed by the confined child, with one exception:
`restore_history.py` re-executes itself inside a sandbox and therefore adds its own path to the read
allowance. The core (`agentbelt.py`, `sandbox_runner.mjs`, `environment_notice.py`, `zcode_hook.py`,
`riskgate_bridge.py`, `packet_entry.py`) stays at the repository root because the sandboxed hook imports
it by path.
"""
