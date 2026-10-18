"""miniyaml — a tiny, dependency-free YAML loader for Keystone manifests.

The standard library ships no YAML parser, and a core design goal of Keystone is
"stdlib-only, runs on a closed box with no external deps". Rather than take a hard
dependency on PyYAML we implement the *restricted* subset of YAML that manifests
actually use:

  * block mappings (``key: value``) nested by 2-space indentation
  * block sequences (``- item``), both indented under a key and aligned with it
  * sequences of mappings (``- key: value`` with aligned continuation keys)
  * scalars typed as int / float / bool / null / string
  * single- and double-quoted strings
  * inline flow sequences (``[80, 443]``) and flow mappings (``{a: 1, b: 2}``)
  * ``#`` comments (honoured outside quotes)

What it deliberately does NOT support: anchors/aliases, multi-document streams,
block scalars (``|`` / ``>``), complex keys, tags. Manifests must stay within the
subset above; ``validate_manifest`` in :mod:`keystone.manifest` catches the rest.

This is intentionally small enough to audit in one sitting and is exercised by
tests/test_miniyaml.py.
"""
from __future__ import annotations

from typing import Any, List, Tuple


class YAMLError(ValueError):
    """Raised when the restricted-YAML input cannot be parsed."""


def _strip_comment(line: str) -> str:
    """Remove a trailing ``#`` comment, honouring quotes."""
    out = []
    quote = None
    i = 0
    while i < len(line):
        ch = line[i]
        if quote:
            out.append(ch)
            if ch == quote:
                quote = None
        else:
            if ch in ("'", '"'):
                quote = ch
                out.append(ch)
            elif ch == "#" and (i == 0 or line[i - 1] in " \t"):
                break
            else:
                out.append(ch)
        i += 1
    return "".join(out).rstrip()


def _find_top_colon(s: str) -> int:
    """Index of the first ``:`` that is a mapping separator (outside quotes/flow)."""
    quote = None
    depth = 0
    for i, ch in enumerate(s):
        if quote:
            if ch == quote:
                quote = None
            continue
        if ch in ("'", '"'):
            quote = ch
        elif ch in "[{":
            depth += 1
        elif ch in "]}":
            depth = max(0, depth - 1)
        elif ch == ":" and depth == 0:
            # A separator is ":" at end of string or ":" followed by whitespace.
            if i + 1 == len(s) or s[i + 1] in " \t":
                return i
    return -1


def _split_flow(body: str) -> List[str]:
    """Split a flow collection body on top-level commas."""
    parts: List[str] = []
    quote = None
    depth = 0
    cur = []
    for ch in body:
        if quote:
            cur.append(ch)
            if ch == quote:
                quote = None
            continue
        if ch in ("'", '"'):
            quote = ch
            cur.append(ch)
        elif ch in "[{":
            depth += 1
            cur.append(ch)
        elif ch in "]}":
            depth -= 1
            cur.append(ch)
        elif ch == "," and depth == 0:
            parts.append("".join(cur).strip())
            cur = []
        else:
            cur.append(ch)
    if "".join(cur).strip():
        parts.append("".join(cur).strip())
    return parts


def _is_block_indicator(tok: str) -> bool:
    """True for a block-scalar header: | |- |+ > >- >+ (optional indent digit)."""
    tok = tok.strip()
    if not tok or tok[0] not in "|>":
        return False
    rest = tok[1:]
    rest = rest.lstrip("+-")
    return rest.isdigit() or rest == ""


def _parse_scalar(tok: str) -> Any:
    tok = tok.strip()
    if tok == "" or tok in ("~", "null", "Null", "NULL"):
        return None
    if len(tok) >= 2 and tok[0] == tok[-1] and tok[0] in ("'", '"'):
        return tok[1:-1]
    if tok.startswith("[") and tok.endswith("]"):
        return [_parse_scalar(x) for x in _split_flow(tok[1:-1])]
    if tok.startswith("{") and tok.endswith("}"):
        out = {}
        for pair in _split_flow(tok[1:-1]):
            ci = _find_top_colon(pair)
            if ci < 0:
                raise YAMLError(f"bad flow mapping entry: {pair!r}")
            key = pair[:ci].strip().strip("'\"")
            out[key] = _parse_scalar(pair[ci + 1:])
        return out
    low = tok.lower()
    if low in ("true", "yes", "on"):
        return True
    if low in ("false", "no", "off"):
        return False
    try:
        return int(tok)
    except ValueError:
        pass
    try:
        return float(tok)
    except ValueError:
        pass
    return tok


class _Parser:
    def __init__(self, lines: List[Tuple[int, str]]):
        self.lines = lines
        self.i = 0

    def _peek(self):
        return self.lines[self.i] if self.i < len(self.lines) else None

    def parse(self, indent: int) -> Any:
        nxt = self._peek()
        if nxt is None:
            return None
        _ind, content = nxt
        if content == "-" or content.startswith("- "):
            return self._parse_seq(indent)
        return self._parse_map(indent)

    def _parse_map(self, indent: int) -> Any:
        result = {}
        while True:
            nxt = self._peek()
            if nxt is None:
                break
            ind, content = nxt
            if ind < indent:
                break
            if ind > indent:
                raise YAMLError(f"unexpected indent at {content!r}")
            ci = _find_top_colon(content)
            if ci < 0:
                raise YAMLError(f"expected 'key: value' but got {content!r}")
            key = content[:ci].strip().strip("'\"")
            val = content[ci + 1:].strip()
            self.i += 1
            if _is_block_indicator(val):
                result[key] = self._parse_block_scalar(indent, val)
            elif val == "":
                child = self._peek()
                if child is not None and child[0] > indent:
                    result[key] = self.parse(child[0])
                elif child is not None and child[0] == indent and (
                    child[1] == "-" or child[1].startswith("- ")
                ):
                    result[key] = self._parse_seq(indent)
                else:
                    result[key] = None
            else:
                result[key] = _parse_scalar(val)
        return result

    def _parse_block_scalar(self, key_indent: int, indicator: str) -> str:
        """Collect a ``|`` / ``>`` block scalar (with optional ``-``/``+`` chomp).

        Blank lines were dropped during preprocessing, so literal blocks do not
        preserve internal blank lines — adequate for manifest prose, which only
        uses folded (``>``) blocks for descriptions and evidence text.
        """
        literal = indicator[0] == "|"
        collected: List[str] = []
        while True:
            nxt = self._peek()
            if nxt is None or nxt[0] <= key_indent:
                break
            collected.append(nxt[1])
            self.i += 1
        sep = "\n" if literal else " "
        return sep.join(collected)

    def _parse_seq(self, indent: int) -> Any:
        result = []
        while True:
            nxt = self._peek()
            if nxt is None:
                break
            ind, content = nxt
            if ind < indent:
                break
            if ind != indent or not (content == "-" or content.startswith("- ")):
                break
            rest = content[1:].lstrip()
            consumed_prefix = len(content) - len(rest)
            self.i += 1
            if rest == "":
                child = self._peek()
                if child is not None and child[0] > indent:
                    result.append(self.parse(child[0]))
                else:
                    result.append(None)
            elif _find_top_colon(rest) >= 0:
                child_indent = ind + consumed_prefix
                # Re-inject the inline "key: value" as a mapping line and parse it.
                self.lines.insert(self.i, (child_indent, rest))
                result.append(self._parse_map(child_indent))
            else:
                result.append(_parse_scalar(rest))
        return result


def load(text: str) -> Any:
    """Parse a restricted-YAML document into Python objects."""
    lines: List[Tuple[int, str]] = []
    for raw in text.splitlines():
        stripped = _strip_comment(raw)
        if stripped.strip() == "":
            continue
        if stripped.lstrip().startswith("---"):
            continue
        lead = stripped[:len(stripped) - len(stripped.lstrip())]
        if "\t" in lead:
            raise YAMLError("tabs are not permitted for indentation")
        indent = len(stripped) - len(stripped.lstrip(" "))
        lines.append((indent, stripped.strip()))
    if not lines:
        return None
    parser = _Parser(lines)
    result = parser.parse(lines[0][0])
    if parser.i != len(parser.lines):
        leftover = parser.lines[parser.i]
        raise YAMLError(f"could not parse near: {leftover[1]!r}")
    return result


def load_file(path: str) -> Any:
    with open(path, "r", encoding="utf-8") as fh:
        return load(fh.read())
