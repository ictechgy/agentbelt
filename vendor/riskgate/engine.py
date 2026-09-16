"""Decision engine — a pure function, no I/O.

    (tool, tool_input, cwd, policy) -> Decision(verdict, rule, reason)

Judgment order (deterministic, most severe verdict wins):

1. Call rules (path/host) are judged once for the whole tool call.
2. If the tool input has a ``command`` string, it is split into shell
   segments (quote-aware; ``|``, ``&&``, ``||``, ``;``, ``&&``, newline).
   Each segment is judged independently against command rules; every
   segment must be approvable for the call to be approved — the highest
   risk across segments is adopted. Rules that only match the full
   command string (e.g. pipe-to-shell detectors spanning a ``|``) are
   judged as one extra unit.
3. Any unit not matched by a rule falls back to ``defaults``.

Safety caps applied by the engine itself (not policy):

* a segment containing command substitution (``$(...)``, backticks,
  ``<(...)``) can never be auto-allowed — its verdict is capped at
  ``prompt`` — because the substituted text is invisible to matching;
* the same cap applies to commands with unbalanced quotes, where
  segmentation cannot be trusted.

Segmentation logic is ported from the battle-tested
``~/.zcode/hooks/risk_gate.py`` prototype this project generalizes.
"""

from __future__ import annotations

import os
import re
import shlex
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Sequence, Tuple

from . import matchers
from .policy import SEVERITY, VERDICTS, Policy, Rule

_SUBSTITUTION_RE = re.compile(r"\$\(|`|<\(")
_ENV_PREFIX_RE = re.compile(r"^[A-Za-z_]\w*=.*$")


@dataclass(frozen=True)
class Decision:
    verdict: str                 # allow | prompt | deny
    rule_id: Optional[str]       # winning rule, None when defaults applied
    risk: Optional[str]          # risk-matrix level of the winning rule
    reason: str
    trace: Tuple[str, ...] = ()  # per-unit explanation, check --verbose


# ---------------------------------------------------------------------------
# command segmentation (ported from the risk_gate.py prototype)
# ---------------------------------------------------------------------------

def split_segments(cmd: str) -> Tuple[List[str], bool]:
    """Split a shell command on ``| ; && ||`` and newlines, honoring
    quotes and escapes. Redirection-style ``&`` (``2>&1``, ``&>file``) is
    kept inside the segment. Returns (segments, quotes_balanced)."""
    segments: List[str] = []
    buf: List[str] = []
    quote: Optional[str] = None
    i, n = 0, len(cmd)
    while i < n:
        ch = cmd[i]
        if quote:
            buf.append(ch)
            if ch == "\\" and quote == '"' and i + 1 < n:
                buf.append(cmd[i + 1])
                i += 2
                continue
            if ch == quote:
                quote = None
            i += 1
            continue
        if ch in ("'", '"'):
            quote = ch
            buf.append(ch)
            i += 1
            continue
        if ch == "\\" and i + 1 < n:
            buf.append(ch)
            buf.append(cmd[i + 1])
            i += 2
            continue
        pair = cmd[i:i + 2]
        if pair in ("&&", "||"):
            segments.append("".join(buf))
            buf = []
            i += 2
            continue
        if ch == "&":
            # keep 2>&1 / &>file together, split a real background `&`
            prev = buf[-1] if buf else ""
            nxt = cmd[i + 1] if i + 1 < n else ""
            if prev != ">" and nxt != ">":
                segments.append("".join(buf))
                buf = []
            else:
                buf.append(ch)
            i += 1
            continue
        if ch in ";|\n":
            segments.append("".join(buf))
            buf = []
            i += 1
            continue
        buf.append(ch)
        i += 1
    segments.append("".join(buf))
    balanced = quote is None
    stripped = [s.strip() for s in segments if s.strip()]
    return stripped, balanced


# ---------------------------------------------------------------------------
# judgment
# ---------------------------------------------------------------------------

def judge(policy: Policy, tool: str, tool_input: Dict[str, Any],
          cwd: Optional[str] = None) -> Decision:
    if not isinstance(tool_input, dict):
        tool_input = {}
    units: List[Tuple[str, Optional[str], Optional[str], str]] = []
    # unit = (verdict, rule_id, risk, reason)
    trace: List[str] = []

    command = tool_input.get("command")
    has_command = isinstance(command, str) and bool(command.strip())

    call_matches = [rule for rule in policy.rules
                    if not rule.is_command_rule
                    and matchers.call_rule_matches(rule, tool, tool_input, cwd)]
    if call_matches or not has_command:
        # Matched path/host rules always contribute. The defaults fallback
        # only applies when there is no command to judge per segment —
        # otherwise unmatched segments carry the fallback themselves.
        label = f"tool call {tool}"
        units.append(_unit(policy, call_matches, label))
        trace.append(_trace_line(label, units[-1], policy))

    if has_command:
        segments, balanced = split_segments(command)
        texts: List[str] = segments if (balanced and segments) else [command]
        capped = not balanced
        # The within-boundary is fixed where the judgment starts; the
        # resolution base follows `cd` segments (ported from the
        # prototype's cd tracking — `cd /tmp && rm x` must not inherit
        # the workspace boundary's trust).
        boundary = os.path.realpath(cwd) if cwd else None
        base = boundary
        for segment in texts:
            matches = [rule for rule in policy.rules
                       if rule.is_command_rule
                       and matchers.text_rule_matches(rule, tool, segment,
                                                      base, boundary)]
            unit = _unit(policy, matches, f"segment {segment!r}")
            if not capped and _SUBSTITUTION_RE.search(segment):
                capped = True
            if capped and unit[0] == "allow":
                unit = ("prompt", unit[1], unit[2],
                        "command substitution or unbalanced quotes — "
                        "auto-approval capped at prompt")
            units.append(unit)
            trace.append(_trace_line(f"segment {segment!r}", unit, policy))
            base = _advance_base(base, segment)
        if balanced and len(texts) > 1:
            spanning = [rule for rule in policy.rules
                        if rule.is_command_rule
                        and matchers.text_rule_matches(rule, tool, command,
                                                       boundary, boundary)
                        and not any(matchers.text_rule_matches(
                            rule, tool, s, boundary, boundary)
                            for s in texts)]
            if spanning:
                unit = _unit(policy, spanning, "compound command")
                units.append(unit)
                trace.append(_trace_line("compound command", unit, policy))

    best = units[0]
    for unit in units[1:]:
        if SEVERITY[unit[0]] > SEVERITY[best[0]]:
            best = unit
    return Decision(verdict=best[0], rule_id=best[1], risk=best[2],
                    reason=best[3], trace=tuple(trace))


def _advance_base(base: Optional[str], segment: str) -> Optional[str]:
    """Resolution base after a `cd` segment: the tracked directory when
    resolvable, else None (unknown base -> within checks fail closed).
    Non-cd segments leave the base unchanged."""
    try:
        tokens = shlex.split(segment)
    except ValueError:
        return None
    while len(tokens) > 1 and _ENV_PREFIX_RE.match(tokens[0]):
        tokens = tokens[1:]
    if not tokens or tokens[0].rsplit("/", 1)[-1] != "cd":
        return base
    target = next((t for t in tokens[1:] if not t.startswith("-")), None)
    if target is None or target == "":
        new = os.path.expanduser("~")  # bare `cd` goes home
    elif target == "-" or "$" in target:
        return None  # OLDPWD / variables cannot be tracked
    else:
        anchor = base if base else os.getcwd()
        new = target if os.path.isabs(target) else os.path.join(anchor, target)
    return os.path.realpath(new) if os.path.isdir(new) else None


def _unit(policy: Policy, rules: Sequence[Rule], label: str
          ) -> Tuple[str, Optional[str], Optional[str], str]:
    """Collapse matching rules to one unit: the most severe verdict wins;
    among equals the earliest rule in policy order is cited."""
    if not rules:
        verdict = policy.defaults
        return verdict, None, None, f"no rule matched — defaults: {verdict}"
    best_rule = rules[0]
    best_verdict = policy.rule_verdict(best_rule)
    for rule in rules[1:]:
        verdict = policy.rule_verdict(rule)
        if SEVERITY[verdict] > SEVERITY[best_verdict]:
            best_rule, best_verdict = rule, verdict
    risk = best_rule.risk if best_rule.risk not in VERDICTS else None
    origin = (f"{best_rule.risk} -> {best_verdict}"
              if risk else f"verdict {best_verdict}")
    reason = (best_rule.reason or f"rule '{best_rule.id}' ({label}): {origin}")
    return best_verdict, best_rule.id, risk, reason


def _trace_line(label: str, unit: Tuple[str, Optional[str], Optional[str], str],
                policy: Policy) -> str:
    verdict, rule_id, _risk, _reason = unit
    source = f"rule '{rule_id}'" if rule_id else "defaults"
    return f"[{label}] {verdict} ({source})"
