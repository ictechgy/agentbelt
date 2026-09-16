"""Pure matcher functions used by the engine.

Command rules (``cmd_regex``) are evaluated per shell segment and against
the full command string; call rules (``path_glob``, ``host_in``,
``host_not_in``) are evaluated once per tool call against the generic
field lists from :mod:`riskgate.policy`. Adapters never rewrite tool
semantics — they only move I/O.

``within`` / ``within_not`` constrain command rules by where their path
operands resolve, porting the prototype's workspace-boundary guard:
the boundary is fixed at the cwd the judgment started from, path
resolution follows ``cd`` segments, wildcards resolve to their parent
directory, and anything unresolvable (shell variables, unparsable
tokens) fails closed.
"""

from __future__ import annotations

import fnmatch
import os
import re
import shlex
from typing import Any, Dict, List, Optional, Sequence, Tuple
from urllib.parse import urlsplit

from .policy import PATH_FIELDS, URL_FIELDS, Rule

_GLOB_CHARS = "*?["
_ENV_PREFIX_RE = re.compile(r"^[A-Za-z_]\w*=.*$")


def tool_matches(pattern: Optional[str], tool: str,
                  tools: Sequence[str] = ()) -> bool:
    """`pattern` is the rule's `tool` value; `tools` is the same value
    pre-expanded through the policy's tool_aliases (empty for rules
    without a tool). A rule matches when the raw pattern matches OR any
    expanded alias member matches."""
    if pattern is None:
        return True
    if fnmatch.fnmatchcase(tool, pattern):
        return True
    return any(fnmatch.fnmatchcase(tool, member) for member in tools)


def text_rule_matches(rule: Rule, tool: str, text: str,
                      base: Optional[str] = None,
                      boundary: Optional[str] = None) -> bool:
    """Command rule vs one segment (or the full command string).

    `base` is the directory relative operands resolve against (it
    follows `cd` segments); `boundary` is the fixed workspace root they
    are compared to. Both matter only for within/within_not rules."""
    if rule.cmd_regex is None or not tool_matches(rule.tool, tool, rule.tools):
        return False
    if rule.cmd_regex.search(text) is None:
        return False
    if rule.within is not None and not within_matches(text, base, boundary):
        return False
    if rule.within_not is not None \
            and not within_not_matches(text, base, boundary):
        return False
    return True


def call_rule_matches(rule: Rule, tool: str, tool_input: Dict[str, Any],
                      cwd: Optional[str]) -> bool:
    """Call rule (path/host) vs a whole tool call. All given constraints
    must hold (AND semantics)."""
    if not tool_matches(rule.tool, tool, rule.tools):
        return False
    if rule.path_glob is not None:
        if not any(fnmatch.fnmatchcase(candidate, rule.path_glob)
                   for candidate in _path_candidates(tool_input, cwd)):
            return False
    if rule.host_in is not None or rule.host_not_in is not None:
        hosts = _hosts(tool_input)
        if rule.host_in is not None:
            if not any(host in rule.host_in for host in hosts):
                return False
        if rule.host_not_in is not None:
            if not any(host not in rule.host_not_in for host in hosts):
                return False
    return True


def _path_candidates(tool_input: Dict[str, Any], cwd: Optional[str]
                     ) -> List[str]:
    """Every string a path_glob may match: the raw field value and the
    cwd-resolved absolute path, both with forward slashes."""
    candidates: List[str] = []
    for field in PATH_FIELDS:
        value = tool_input.get(field)
        if not isinstance(value, str) or not value.strip():
            continue
        value = os.path.expanduser(value)
        candidates.append(value.replace(os.sep, "/"))
        base = cwd if cwd else "."
        resolved = os.path.normpath(os.path.join(base, value))
        candidates.append(resolved.replace(os.sep, "/"))
    return candidates


def _hosts(tool_input: Dict[str, Any]) -> List[str]:
    hosts: List[str] = []
    for field in URL_FIELDS:
        value = tool_input.get(field)
        if not isinstance(value, str) or not value.strip():
            continue
        try:
            host = urlsplit(value).hostname
        except ValueError:
            host = None
        if host:
            hosts.append(host.lower())
    return hosts


# ---------------------------------------------------------------------------
# within / within_not — path operands of a shell segment
# ---------------------------------------------------------------------------

def command_path_operands(segment: str) -> Optional[List[str]]:
    """Tokens treated as path operands: env prefixes and the command word
    are stripped, flags (until ``--``) are skipped. Returns None when the
    segment does not tokenize — callers fail closed on that."""
    try:
        tokens = shlex.split(segment)
    except ValueError:
        return None
    while len(tokens) > 1 and _ENV_PREFIX_RE.match(tokens[0]):
        tokens = tokens[1:]
    if not tokens:
        return []
    operands: List[str] = []
    only_paths = False
    for token in tokens[1:]:
        if not only_paths and token == "--":
            only_paths = True
            continue
        if not only_paths and token.startswith("-") and token != "-":
            continue
        operands.append(token)
    return operands


def _resolve_operand(token: str, base: Optional[str]) -> Optional[str]:
    """Absolute, symlink-resolved path for boundary comparison, or None
    when unresolvable (shell variables stay literal, so comparing them
    against the boundary would lie — fail closed instead)."""
    if "$" in token:
        return None
    token = os.path.expanduser(token)
    glob_at = min((i for i, ch in enumerate(token) if ch in _GLOB_CHARS),
                  default=-1)
    if glob_at >= 0:
        # a wildcard stands for its expansion; judging by the parent
        # directory is sound (parent inside the boundary -> expanded
        # paths inside too)
        token = os.path.dirname(token[:glob_at]) or "."
    if not os.path.isabs(token):
        if not base:
            return None
        token = os.path.join(base, token)
    return os.path.realpath(token)


def _strictly_inside(resolved: Optional[str], boundary: str) -> bool:
    return (resolved is not None and resolved != boundary
            and resolved.startswith(boundary + os.sep))


def within_matches(segment: str, base: Optional[str],
                   boundary: Optional[str]) -> bool:
    """True when the segment has path operands and all of them resolve
    strictly inside the boundary (the boundary root itself is not
    inside — `rm -rf .` must not qualify)."""
    operands = command_path_operands(segment)
    if not operands:
        return False
    if base is None or boundary is None:
        return False
    return all(_strictly_inside(_resolve_operand(op, base), boundary)
               for op in operands)


def within_not_matches(segment: str, base: Optional[str],
                       boundary: Optional[str]) -> bool:
    """True when the segment has path operands and at least one resolves
    outside the boundary (or is the boundary itself, or is unresolvable,
    or the resolution base is unknown after an untrackable cd)."""
    operands = command_path_operands(segment)
    if not operands:
        return False
    if base is None or boundary is None:
        return True
    return any(not _strictly_inside(_resolve_operand(op, base), boundary)
               for op in operands)
