"""Compose the existing risk policy with the OS guard, without shell rewrites."""
import json
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / 'vendor'))
from riskgate import judge, load_policy
from agent_guard import GuardError, riskgate_policy


def riskgate_decision(payload):
    try:
        path = riskgate_policy()
        if path.stat().st_size > 1024 * 1024:
            raise ValueError('policy too large')
        policy = load_policy(str(path))
        result = judge(policy, 'Bash', payload['tool_input'], cwd=payload['cwd'])
        verdict = {'allow': 'allow', 'prompt': 'ask', 'deny': 'deny'}[result.verdict]
        record = {'tool': 'Bash', 'decision': verdict}
        # Allowed and denied calls still record only the verdict. A prompted call
        # records what it was, because deciding which deterministic rule is
        # missing is impossible without it. The log stays on this host and is
        # written inside the isolated home, so treat it as untrusted input when
        # writing rules: the agent can read and forge entries there.
        if verdict == 'ask' and os.environ.get('AGENT_GUARD_PROMPT_TELEMETRY') == '1':
            record.update(command=str(payload['tool_input'].get('command', ''))[:4096],
                          risk=result.risk, rule=result.rule_id)
        audit = Path.home() / 'riskgate-decisions.jsonl'
        fd = os.open(str(audit), os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'w') as out:
            out.write(json.dumps(record, ensure_ascii=False) + '\n')
        return verdict
    except Exception:
        raise GuardError('riskgate verification failed. Check the policy and run it again.') from None
