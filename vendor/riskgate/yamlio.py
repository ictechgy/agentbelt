"""Minimal YAML-subset parser — riskgate is stdlib-only by design.

Policies are a constrained format, so instead of pulling in PyYAML the
loader accepts this subset (anything outside it is a lint error with a
line number, never a silent misparse):

* block mappings and sequences, space-indented (tabs are rejected)
* single-line flow mappings ``{k: v, ...}`` and sequences ``[a, b]``
* plain scalars, ``'single-quoted'`` and ``"double-quoted"`` strings
* ``#`` comments (outside quotes; plain scalars need whitespace before
  ``#`` so URLs and regexes starting with ``#`` stay valid)
* scalar typing: ``null``/``~`` -> None, ``true``/``false`` -> bool,
  integers -> int; everything else stays a string

Deliberately unsupported: anchors, tags, block scalars, multi-line
plain scalars, multi-line flow collections, complex keys.
"""

from __future__ import annotations

import re
from typing import Any, List, Optional, Tuple

_INT_RE = re.compile(r"^[+-]?\d+$")

_ESCAPES = {
    '"': '"', "\\": "\\", "/": "/",
    "n": "\n", "t": "\t", "r": "\r",
    "0": "\0", "b": "\b", "f": "\f",
}


class YAMLError(ValueError):
    """Syntax error, carrying the 1-based line where it was detected."""

    def __init__(self, message: str, lineno: int):
        super().__init__(f"line {lineno}: {message}")
        self.lineno = lineno
        self.message = message


class _Line:
    __slots__ = ("indent", "content", "lineno")

    def __init__(self, indent: int, content: str, lineno: int):
        self.indent = indent
        self.content = content
        self.lineno = lineno


def parse(text: str) -> Any:
    """Parse a YAML-subset document into Python objects.

    Returns None for an empty document. Raises YAMLError on anything the
    subset does not cover.
    """
    lines = _prepare(text)
    if not lines:
        return None
    value, idx = _parse_node(lines, 0, lines[0].indent)
    if idx != len(lines):
        raise YAMLError(
            "unexpected indentation (this line does not fit the structure above)",
            lines[idx].lineno,
        )
    return value


# ---------------------------------------------------------------------------
# line preparation
# ---------------------------------------------------------------------------

def _prepare(text: str) -> List[_Line]:
    out: List[_Line] = []
    for lineno, raw in enumerate(text.splitlines(), 1):
        stripped = _strip_comment(raw)
        if not stripped.strip():
            continue
        indent = 0
        for ch in stripped:
            if ch == " ":
                indent += 1
            elif ch == "\t":
                raise YAMLError("tab in indentation — use spaces", lineno)
            else:
                break
        content = stripped[indent:].rstrip()
        if content:
            out.append(_Line(indent, content, lineno))
    return out


def _strip_comment(line: str) -> str:
    quote: Optional[str] = None
    i, n = 0, len(line)
    while i < n:
        ch = line[i]
        if quote == "'":
            if ch == "'":
                quote = None
        elif quote == '"':
            if ch == "\\":
                i += 1
            elif ch == '"':
                quote = None
        else:
            if ch in "'\"":
                quote = ch
            elif ch == "#" and (i == 0 or line[i - 1] in " \t"):
                return line[:i]
        i += 1
    return line


# ---------------------------------------------------------------------------
# block structure
# ---------------------------------------------------------------------------

def _parse_node(lines: List[_Line], i: int, indent: int) -> Tuple[Any, int]:
    if _is_seq_item(lines[i]):
        return _parse_seq(lines, i, indent)
    return _parse_map(lines, i, indent)


def _is_seq_item(line: _Line) -> bool:
    return line.content == "-" or line.content.startswith("- ")


def _parse_map(lines: List[_Line], i: int, indent: int,
               first: Optional[_Line] = None) -> Tuple[Any, int]:
    result: dict = {}
    line = first if first is not None else lines[i]
    while True:
        key, rest = _split_key(line.content, line.lineno)
        if key in result:
            raise YAMLError(f"duplicate mapping key {key!r}", line.lineno)
        rest = rest.strip()
        nxt = i + 1  # `line` occupies lines[i] (or replaces it when virtual)
        if rest:
            value = _parse_inline(rest, line.lineno)
        elif nxt < len(lines):
            following = lines[nxt]
            if following.indent > indent or (
                    following.indent == indent and _is_seq_item(following)):
                value, nxt = _parse_node(lines, nxt, following.indent)
            else:
                value = None
        else:
            value = None
        result[key] = value

        if nxt >= len(lines):
            return result, nxt
        upcoming = lines[nxt]
        if upcoming.indent > indent:
            raise YAMLError("unexpected deeper indentation", upcoming.lineno)
        if upcoming.indent < indent or _is_seq_item(upcoming):
            return result, nxt
        line = upcoming
        i = nxt


def _parse_seq(lines: List[_Line], i: int, indent: int) -> Tuple[Any, int]:
    items: List[Any] = []
    n = len(lines)
    while i < n and lines[i].indent == indent and _is_seq_item(lines[i]):
        line = lines[i]
        after = line.content[1:]
        stripped = after.lstrip(" ")
        pad = len(after) - len(stripped)
        if not stripped:
            nxt = i + 1
            if nxt < n and lines[nxt].indent > indent:
                value, nxt = _parse_node(lines, nxt, lines[nxt].indent)
            else:
                value = None
        elif _is_kv(stripped):
            # "- key: value" starts a mapping item; continuation keys sit at
            # the column where the first key begins.
            child_indent = indent + 1 + pad
            virtual = _Line(child_indent, stripped, line.lineno)
            value, nxt = _parse_map(lines, i, child_indent, first=virtual)
        else:
            value = _parse_inline(stripped, line.lineno)
            nxt = i + 1
        items.append(value)
        i = nxt
    return items, i


def _is_kv(content: str) -> bool:
    if content[0] in "{[":
        return False
    if content[0] in "'\"":
        try:
            _, end = _read_quoted(content, 0, 0)
        except YAMLError:
            return False
        rest = content[end:].lstrip()
        return rest.startswith(":")
    pos = content.find(":")
    while pos != -1:
        if pos + 1 == len(content) or content[pos + 1] in " \t":
            return True
        pos = content.find(":", pos + 1)
    return False


def _split_key(content: str, lineno: int) -> Tuple[str, str]:
    if content[0] in "'\"":
        key, end = _read_quoted(content, 0, lineno)
        rest = content[end:].lstrip()
        if not rest.startswith(":"):
            raise YAMLError("expected ':' after quoted mapping key", lineno)
        return key, rest[1:]
    pos = content.find(":")
    while pos != -1:
        if pos + 1 == len(content) or content[pos + 1] in " \t":
            return content[:pos].strip(), content[pos + 1:]
        pos = content.find(":", pos + 1)
    raise YAMLError("expected a 'key: value' mapping entry", lineno)


# ---------------------------------------------------------------------------
# scalars and flow collections
# ---------------------------------------------------------------------------

def _parse_inline(text: str, lineno: int) -> Any:
    text = text.strip()
    if not text:
        return None
    head = text[0]
    if head in "'\"":
        value, end = _read_quoted(text, 0, lineno)
        if text[end:].strip():
            raise YAMLError(
                f"unexpected text after quoted scalar: {text[end:].strip()!r}",
                lineno)
        return value
    if head in "{[":
        value, end = _parse_flow(text, 0, lineno)
        if text[end:].strip():
            raise YAMLError(
                f"unexpected text after flow collection: {text[end:].strip()!r}",
                lineno)
        return value
    return _plain(text)


def _parse_flow(s: str, pos: int, lineno: int) -> Tuple[Any, int]:
    n = len(s)
    pos = _skip_ws(s, pos)
    if pos >= n:
        raise YAMLError("unexpected end of flow collection", lineno)
    head = s[pos]
    if head == "{":
        result: dict = {}
        pos += 1
        pos = _skip_ws(s, pos)
        if pos < n and s[pos] == "}":
            return result, pos + 1
        while True:
            pos = _skip_ws(s, pos)
            if pos < n and s[pos] in "'\"":
                key, pos = _read_quoted(s, pos, lineno)
            else:
                start = pos
                while pos < n and s[pos] not in ":,}":
                    pos += 1
                key = s[start:pos].strip()
            if not key:
                raise YAMLError("empty key in flow mapping", lineno)
            pos = _skip_ws(s, pos)
            if pos >= n or s[pos] != ":":
                raise YAMLError("expected ':' in flow mapping", lineno)
            pos += 1
            value, pos = _parse_flow(s, pos, lineno)
            if key in result:
                raise YAMLError(f"duplicate key {key!r} in flow mapping", lineno)
            result[key] = value
            pos = _skip_ws(s, pos)
            if pos < n and s[pos] == ",":
                pos = _skip_ws(s, pos + 1)
                if pos < n and s[pos] == "}":
                    return result, pos + 1
                continue
            if pos < n and s[pos] == "}":
                return result, pos + 1
            raise YAMLError("expected ',' or '}' in flow mapping", lineno)
    if head == "[":
        items: list = []
        pos += 1
        pos = _skip_ws(s, pos)
        if pos < n and s[pos] == "]":
            return items, pos + 1
        while True:
            value, pos = _parse_flow(s, pos, lineno)
            items.append(value)
            pos = _skip_ws(s, pos)
            if pos < n and s[pos] == ",":
                pos = _skip_ws(s, pos + 1)
                if pos < n and s[pos] == "]":
                    return items, pos + 1
                continue
            if pos < n and s[pos] == "]":
                return items, pos + 1
            raise YAMLError("expected ',' or ']' in flow sequence", lineno)
    if head in "'\"":
        return _read_quoted(s, pos, lineno)
    start = pos
    while pos < n and s[pos] not in ",}]":
        pos += 1
    return _plain(s[start:pos].strip()), pos


def _read_quoted(s: str, pos: int, lineno: int) -> Tuple[str, int]:
    quote = s[pos]
    i = pos + 1
    buf: List[str] = []
    n = len(s)
    while i < n:
        ch = s[i]
        if quote == "'":
            if ch == "'":
                if i + 1 < n and s[i + 1] == "'":
                    buf.append("'")
                    i += 2
                    continue
                return "".join(buf), i + 1
            buf.append(ch)
            i += 1
        else:
            if ch == "\\":
                if i + 1 >= n:
                    raise YAMLError(
                        "dangling backslash in double-quoted string", lineno)
                mapped = _ESCAPES.get(s[i + 1])
                if mapped is None:
                    raise YAMLError(
                        f"unsupported escape '\\{s[i + 1]}' in double-quoted "
                        "string — single-quote the value instead", lineno)
                buf.append(mapped)
                i += 2
                continue
            if ch == '"':
                return "".join(buf), i + 1
            buf.append(ch)
            i += 1
    raise YAMLError("unterminated quoted string", lineno)


def _skip_ws(s: str, pos: int) -> int:
    n = len(s)
    while pos < n and s[pos] in " \t":
        pos += 1
    return pos


def _plain(text: str) -> Any:
    if text in ("null", "Null", "NULL", "~", ""):
        return None
    if text in ("true", "True", "TRUE"):
        return True
    if text in ("false", "False", "FALSE"):
        return False
    if _INT_RE.match(text):
        return int(text)
    return text
