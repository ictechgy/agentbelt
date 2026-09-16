"""riskgate — declarative risk policies for coding-agent CLIs.

Like CI declares *what runs* in GitHub Actions YAML, riskgate declares
*what the agent may do* in one YAML policy — for any agent CLI.
"""

from .engine import Decision, judge, split_segments
from .policy import (Policy, PolicyError, Rule, TestCase, VERDICTS,
                     check_policy, load_policy)

__version__ = "0.5.0"

__all__ = [
    "Decision", "Policy", "PolicyError", "Rule", "TestCase", "VERDICTS",
    "check_policy", "judge", "load_policy", "split_segments",
    "__version__",
]
