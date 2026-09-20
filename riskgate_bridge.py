"""Compose the existing risk policy with the OS guard, without shell rewrites."""
import json
import os
from pathlib import Path
import stat
import sys

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / 'vendor'))
from riskgate import judge, load_policy
from agentbelt import GuardError, riskgate_policy


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
        if verdict == 'ask' and os.environ.get('AGENTBELT_PROMPT_TELEMETRY') == '1':
            record.update(command=str(payload['tool_input'].get('command', ''))[:4096],
                          risk=result.risk, rule=result.rule_id)
        audit = Path.home() / 'riskgate-decisions.jsonl'
        fd = -1
        try:
            fd = os.open(
                str(audit),
                os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK,
                0o600,
            )
            info = os.fstat(fd)
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) & 0o077
                or info.st_nlink != 1
            ):
                raise OSError('audit path is not a private regular file')
            out = os.fdopen(fd, 'a', encoding='utf-8')
            fd = -1
            with out:
                out.write(json.dumps(record, ensure_ascii=False) + '\n')
        finally:
            if fd != -1:
                os.close(fd)
        return verdict
    except Exception:
        raise GuardError('riskgate verification failed. Check the policy and run it again.') from None
