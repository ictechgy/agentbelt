"""Policy model, loading and validation.

A policy is one YAML file: ``version``, ``defaults``, ``risk_matrix``,
``rules``, optional ``audit`` path and ``tests`` cases. Everything is
validated eagerly so a bad policy fails in ``riskgate lint`` (or CI),
never in the hook hot path.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Sequence, Tuple, Union

from . import yamlio

VERDICTS = ("allow", "prompt", "deny")
SEVERITY = {"allow": 0, "prompt": 1, "deny": 2}

MATCH_KEYS = ("tool", "cmd_regex", "path_glob", "host_in", "host_not_in",
              "within", "within_not")
COMMAND_ONLY_KEYS = ("cmd_regex",)
CALL_ONLY_KEYS = ("path_glob", "host_in", "host_not_in")
WITHIN_SCOPES = ("cwd",)

# tool_input fields treated as filesystem paths / URLs by the generic
# matchers (adapters never rewrite semantics, they only move I/O).
PATH_FIELDS = ("file_path", "path", "notebook_path", "filePath", "filepath")
URL_FIELDS = ("url", "uri")

TOP_KEYS = ("version", "defaults", "risk_matrix", "tool_aliases", "rules",
            "audit", "escalation", "tests")


class PolicyError(ValueError):
    """Raised when a policy fails validation (message joins all errors)."""


@dataclass(frozen=True)
class Rule:
    id: str
    tool: Optional[str]              # fnmatch pattern, None = any tool
    tools: Tuple[str, ...]           # tool expanded via tool_aliases
    cmd_regex: Optional[re.Pattern]  # command rules: matched per segment
    path_glob: Optional[str]         # call rules: matched against path fields
    host_in: Optional[Tuple[str, ...]]
    host_not_in: Optional[Tuple[str, ...]]
    within: Optional[str]            # command rules: all path operands inside
    within_not: Optional[str]        # command rules: any path operand outside
    risk: str                        # risk-matrix level name or direct verdict
    reason: Optional[str]            # overrides the default audit/prompt reason

    @property
    def is_command_rule(self) -> bool:
        return self.cmd_regex is not None


@dataclass(frozen=True)
class TestCase:
    name: str
    tool: str
    input: Dict[str, Any]
    expect: str
    rule: Optional[str]


@dataclass(frozen=True)
class Policy:
    path: Optional[str]
    defaults: str
    matrix: Tuple[Tuple[str, str], ...]  # risk level -> verdict, ordered
    rules: Tuple[Rule, ...]
    tests: Tuple[TestCase, ...]
    audit_path: Optional[str]
    tool_aliases: Tuple[Tuple[str, Tuple[str, ...]], ...] = ()

    @property
    def matrix_dict(self) -> Dict[str, str]:
        return dict(self.matrix)

    def rule_verdict(self, rule: Rule) -> str:
        """Resolve a rule's risk to a verdict via the matrix (or directly)."""
        if rule.risk in VERDICTS:
            return rule.risk
        return self.matrix_dict[rule.risk]


# ---------------------------------------------------------------------------
# loading
# ---------------------------------------------------------------------------

def load_policy(path: str) -> Policy:
    """Read and validate a policy file. Raises PolicyError / YAMLError."""
    try:
        with open(path, encoding="utf-8") as fh:
            text = fh.read()
    except OSError as exc:
        raise PolicyError(f"cannot read {path}: {exc}") from exc
    data = parse_policy_text(text, path)
    policy, errors, _warnings = check_policy(data, path)
    if errors:
        raise PolicyError("; ".join(errors))
    return policy


def parse_policy_text(text: str, path: str) -> Any:
    try:
        data = yamlio.parse(text)
    except yamlio.YAMLError as exc:
        raise PolicyError(f"{path}: syntax error: {exc}") from exc
    if not isinstance(data, dict):
        raise PolicyError(f"{path}: top level must be a mapping")
    return data


def build_policy(data: Any, path: Optional[str] = None) -> Policy:
    """Validate parsed data into a Policy or raise PolicyError."""
    policy, errors, _warnings = check_policy(data, path)
    if errors:
        raise PolicyError("; ".join(errors))
    return policy


def check_policy(data: Any, path: Optional[str] = None
                 ) -> Tuple[Optional[Policy], List[str], List[str]]:
    """Full validation. Returns (policy_or_None, errors, warnings)."""
    errors: List[str] = []
    warnings: List[str] = []

    def err(msg: str) -> None:
        errors.append(msg)

    if not isinstance(data, dict):
        err("top level must be a mapping")
        return None, errors, warnings

    for key in data:
        if key not in TOP_KEYS:
            err(f"unknown key {key!r} (known: {', '.join(TOP_KEYS)})")

    version = data.get("version")
    if version != 1:
        err(f"version must be 1, got {version!r}")

    defaults = data.get("defaults", "prompt")
    if defaults not in VERDICTS:
        err(f"defaults must be one of {VERDICTS}, got {defaults!r}")
    elif defaults == "allow":
        warnings.append(
            "defaults is 'allow': unmatched tool calls are auto-approved — "
            "make sure this policy really means it")

    matrix: Tuple[Tuple[str, str], ...] = ()
    raw_matrix = data.get("risk_matrix", {})
    if not isinstance(raw_matrix, dict):
        err("risk_matrix must be a mapping of risk level -> verdict")
    else:
        levels: List[Tuple[str, str]] = []
        for level, verdict in raw_matrix.items():
            if not isinstance(level, str) or not level.strip():
                err(f"risk_matrix level {level!r} must be a non-empty string")
                continue
            if verdict not in VERDICTS:
                err(f"risk_matrix.{level}: verdict must be one of {VERDICTS}, "
                    f"got {verdict!r}")
                continue
            if level in VERDICTS:
                err(f"risk_matrix level {level!r} collides with a direct "
                    "verdict name")
                continue
            levels.append((level, verdict))
        matrix = tuple(levels)

    audit_path = _check_audit(data, err)

    tool_aliases, alias_errors = _check_tool_aliases(data.get("tool_aliases"))
    errors.extend(alias_errors)
    alias_map = dict(tool_aliases)

    raw_rules = data.get("rules", [])
    if raw_rules is None:
        raw_rules = []
    if not isinstance(raw_rules, list):
        err("rules must be a list")
        raw_rules = []
    rules, rule_errors = _check_rules(raw_rules, matrix, alias_map)
    errors.extend(rule_errors)

    raw_tests = data.get("tests", [])
    if raw_tests is None:
        raw_tests = []
    if not isinstance(raw_tests, list):
        err("tests must be a list")
        raw_tests = []
    tests, test_errors = _check_tests(raw_tests, rules)
    errors.extend(test_errors)

    if errors:
        return None, errors, warnings
    policy = Policy(path=path, defaults=defaults, matrix=matrix, rules=rules,
                    tests=tests, audit_path=audit_path,
                    tool_aliases=tool_aliases)
    return policy, errors, warnings


def _check_tool_aliases(raw: Any) -> Tuple[Tuple[Tuple[str, Tuple[str, ...]], ...],
                                           List[str]]:
    """tool_aliases: alias name -> list of concrete tool names. A rule's
    `tool` equal to an alias name matches ANY of the listed tools."""
    if raw is None:
        return (), []
    errors: List[str] = []
    if not isinstance(raw, dict) or not raw:
        return (), ["tool_aliases must be a non-empty mapping of "
                    "alias -> [tool names]"]
    aliases: List[Tuple[str, Tuple[str, ...]]] = []
    for name, members in raw.items():
        if not isinstance(name, str) or not name.strip():
            errors.append(f"tool_aliases key {name!r} must be a non-empty "
                          "string")
            continue
        if (not isinstance(members, list) or not members
                or not all(isinstance(m, str) and m.strip() for m in members)):
            errors.append(f"tool_aliases.{name}: must be a non-empty list "
                          "of tool name strings")
            continue
        if name in ("Bash", "Read", "Edit", "Write", "WebFetch", "WebSearch"):
            errors.append(f"tool_aliases.{name}: alias name collides with a "
                          "common real tool name — pick another")
            continue
        aliases.append((name, tuple(members)))
    return tuple(aliases), errors


def _check_audit(data: Dict[str, Any], err) -> Optional[str]:
    top_audit = data.get("audit")
    escalation = data.get("escalation")
    esc_audit = None
    if escalation is not None:
        if not isinstance(escalation, dict):
            err("escalation must be a mapping")
        else:
            for key in escalation:
                if key != "audit":
                    err(f"escalation.{key} is not supported yet "
                        "(HITL routing arrives in v0.2)")
            esc_audit = escalation.get("audit")
    for value, label in ((top_audit, "audit"), (esc_audit, "escalation.audit")):
        if value is not None and not isinstance(value, str):
            err(f"{label} must be a path string")
    if top_audit is not None and esc_audit is not None:
        err("audit defined twice (top level and escalation.audit)")
    if top_audit is not None:
        return top_audit
    if isinstance(esc_audit, str):
        return esc_audit
    return None


def _check_rules(raw_rules: List[Any], matrix: Sequence[Tuple[str, str]],
                 alias_map: Dict[str, Tuple[str, ...]]
                 ) -> Tuple[Tuple[Rule, ...], List[str]]:
    errors: List[str] = []
    rules: List[Rule] = []
    seen_ids: Dict[str, int] = {}
    levels = {level for level, _ in matrix}
    for index, entry in enumerate(raw_rules):
        label = f"rules[{index}]"
        if not isinstance(entry, dict):
            errors.append(f"{label}: must be a mapping")
            continue
        for key in entry:
            if key not in ("id", "match", "risk", "reason"):
                errors.append(f"{label}: unknown key {key!r} "
                              "(known: id, match, risk, reason)")

        rule_id = entry.get("id", f"rule[{index}]")
        if not isinstance(rule_id, str) or not rule_id.strip():
            errors.append(f"{label}: id must be a non-empty string")
            continue
        if rule_id in seen_ids:
            errors.append(f"{label}: duplicate rule id {rule_id!r} "
                          f"(first used at rules[{seen_ids[rule_id]}])")
            continue
        seen_ids[rule_id] = index

        match = entry.get("match")
        if not isinstance(match, dict) or not match:
            errors.append(f"{label} ({rule_id}): match must be a non-empty "
                          "mapping")
            continue
        for key in match:
            if key not in MATCH_KEYS:
                errors.append(f"{label} ({rule_id}): unknown matcher "
                              f"{key!r} (known: {', '.join(MATCH_KEYS)})")

        tool = match.get("tool")
        if tool is not None and (not isinstance(tool, str) or not tool.strip()):
            errors.append(f"{label} ({rule_id}): tool must be a non-empty "
                          "pattern string")

        cmd_regex = None
        if "cmd_regex" in match:
            pattern = match["cmd_regex"]
            try:
                cmd_regex = re.compile(pattern)
            except (re.error, TypeError) as exc:
                errors.append(f"{label} ({rule_id}): bad cmd_regex: {exc}")
            for other in CALL_ONLY_KEYS:
                if other in match:
                    errors.append(
                        f"{label} ({rule_id}): cmd_regex cannot be combined "
                        f"with {other} — split into two rules")

        path_glob = _optional_str(match, "path_glob", label, rule_id, errors)
        host_in = _host_list(match, "host_in", label, rule_id, errors)
        host_not_in = _host_list(match, "host_not_in", label, rule_id, errors)
        within = _within_scope(match, "within", label, rule_id, errors)
        within_not = _within_scope(match, "within_not", label, rule_id, errors)
        if (within or within_not) and "cmd_regex" not in match:
            errors.append(f"{label} ({rule_id}): within/within_not apply to "
                          "command rules and require cmd_regex")

        if (cmd_regex is None and path_glob is None
                and host_in is None and host_not_in is None
                and within is None and within_not is None):
            errors.append(f"{label} ({rule_id}): match needs at least one of "
                          f"{', '.join(MATCH_KEYS)}")

        risk = entry.get("risk")
        if not isinstance(risk, str) or not risk.strip():
            errors.append(f"{label} ({rule_id}): risk is required (a "
                          f"risk_matrix level or one of {VERDICTS})")
            continue
        if risk not in VERDICTS and risk not in levels:
            known = ", ".join(sorted(levels) + list(VERDICTS))
            errors.append(f"{label} ({rule_id}): risk {risk!r} is neither a "
                          f"risk_matrix level nor a verdict (known: {known})")
            continue

        reason = entry.get("reason")
        if reason is not None and not isinstance(reason, str):
            errors.append(f"{label} ({rule_id}): reason must be a string")
            reason = None

        rules.append(Rule(id=rule_id, tool=tool,
                          tools=alias_map.get(tool, (tool,)) if tool
                          else (),
                          cmd_regex=cmd_regex,
                          path_glob=path_glob, host_in=host_in,
                          host_not_in=host_not_in, within=within,
                          within_not=within_not, risk=risk, reason=reason))
    return tuple(rules), errors


def _optional_str(match: Dict[str, Any], key: str, label: str, rule_id: str,
                  errors: List[str]) -> Optional[str]:
    if key not in match:
        return None
    value = match[key]
    if not isinstance(value, str) or not value.strip():
        errors.append(f"{label} ({rule_id}): {key} must be a non-empty string")
        return None
    return value


def _within_scope(match: Dict[str, Any], key: str, label: str, rule_id: str,
                  errors: List[str]) -> Optional[str]:
    if key not in match:
        return None
    value = match[key]
    if value not in WITHIN_SCOPES:
        known = ", ".join(repr(s) for s in WITHIN_SCOPES)
        errors.append(f"{label} ({rule_id}): {key} supports only {known} "
                      f"for now, got {value!r}")
        return None
    return value


def _host_list(match: Dict[str, Any], key: str, label: str, rule_id: str,
               errors: List[str]) -> Optional[Tuple[str, ...]]:
    if key not in match:
        return None
    value = match[key]
    if not isinstance(value, list) or not value:
        errors.append(f"{label} ({rule_id}): {key} must be a non-empty list "
                      "of hostnames")
        return None
    hosts: List[str] = []
    for item in value:
        if not isinstance(item, str) or not item.strip():
            errors.append(f"{label} ({rule_id}): {key} entries must be "
                          "hostname strings")
            return None
        hosts.append(item.strip().lower())
    return tuple(hosts)


def _check_tests(raw_tests: List[Any], rules: Sequence[Rule]
                 ) -> Tuple[Tuple[TestCase, ...], List[str]]:
    errors: List[str] = []
    known_ids = {rule.id for rule in rules}
    cases: List[TestCase] = []
    for index, entry in enumerate(raw_tests):
        label = f"tests[{index}]"
        if not isinstance(entry, dict):
            errors.append(f"{label}: must be a mapping")
            continue
        for key in entry:
            if key not in ("name", "tool", "input", "expect", "rule"):
                errors.append(f"{label}: unknown key {key!r} "
                              "(known: name, tool, input, expect, rule)")
        name = entry.get("name", f"case {index + 1}")
        if not isinstance(name, str) or not name.strip():
            errors.append(f"{label}: name must be a non-empty string")
            name = f"case {index + 1}"
        tool = entry.get("tool")
        if not isinstance(tool, str) or not tool.strip():
            errors.append(f"{label} ({name}): tool is required")
            continue
        tool_input = entry.get("input")
        if not isinstance(tool_input, dict):
            errors.append(f"{label} ({name}): input must be a mapping of "
                          "tool arguments")
            continue
        expect = entry.get("expect")
        if expect not in VERDICTS:
            errors.append(f"{label} ({name}): expect must be one of "
                          f"{VERDICTS}, got {expect!r}")
            continue
        rule_ref = entry.get("rule")
        if rule_ref is not None:
            if not isinstance(rule_ref, str) or rule_ref not in known_ids:
                errors.append(f"{label} ({name}): rule {rule_ref!r} does not "
                              "match any rule id")
                continue
        cases.append(TestCase(name=name, tool=tool, input=tool_input,
                              expect=expect, rule=rule_ref))
    return tuple(cases), errors
