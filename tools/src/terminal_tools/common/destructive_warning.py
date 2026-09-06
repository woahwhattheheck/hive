"""Detect potentially destructive commands and surface a warning string.

Informational only — the warning is included in the exec envelope, not
used to block execution. Lets the agent re-read its command before
trusting the result of an irreversible action. Catalog ported from
claudecode's BashTool/destructiveCommandWarning.ts.
"""

from __future__ import annotations

import re
import shlex
from collections.abc import Sequence

# Only the rm catalog uses command-position parsing. Other advisory patterns
# retain their existing matching and priority. No command is executed here.
_SHELL_TOKEN = re.compile(
    r"(?P<space>[ \t\r]+)|(?P<comment>\#[^\n]*)|(?P<separator>[;&|\n()]+)"
    r"|(?P<word>(?:[^\s'\"\\;&|()]+|\\[\s\S]|'[^']*'|\"(?:\\[\s\S]|[^\"\\])*\")+)"
)
_ASSIGNMENT = re.compile(r"^[A-Za-z_]\w*=")

# (no-operand short flags, operand short flags, no-operand long flags,
# operand long flags). Unsupported and lookup/list-only options are not
# assumed to execute the following word. This is intentionally not a shell
# evaluator or a complete option catalog for every platform.
_WRAPPER_OPTIONS = {
    "sudo": ("AbEHknPSis", "CDghprRTtu", (), ()),
    "doas": ("n", "u", (), ()),
    "nohup": ("", "", (), ()),
    "time": ("apqv", "fo", (), ()),
    "command": ("p", "", (), ()),
    "env": ("iv", "uC", ("ignore-environment", "debug"), ("unset", "chdir")),
    "xargs": ("0oprtx", "adEILnPs", (), ()),
}


_WORD_PART = re.compile(r"'[^']*'|\"(?:\\[\s\S]|[^\"\\])*\"|\\[\s\S]|[^'\"\\]+")
_CONTINUATION = re.compile(r"\\\\|\\\n")


def _decode_shell_word(raw: str) -> list[str]:
    """Remove escaped newlines outside single quotes before shlex decoding."""
    parts = []
    for match in _WORD_PART.finditer(raw):
        part = match.group()
        if not part.startswith("'"):
            part = _CONTINUATION.sub(lambda m: "" if m.group() == "\\\n" else m.group(), part)
        parts.append(part)
    return shlex.split("".join(parts), comments=False, posix=True)


def _shell_command(words: list[str], raw_words: list[str]) -> tuple[list[str], int]:
    """Keep Bash time-keyword assignments distinct from external time argv."""
    start = 0
    while start < len(raw_words) and raw_words[start] == "time":
        start += 1
        if start < len(raw_words) and raw_words[start] == "-p":
            start += 1
        if start < len(raw_words) and raw_words[start] == "--":
            start += 1
    assignments = 0
    for raw in raw_words[start:]:
        if not _ASSIGNMENT.match(raw):
            break
        assignments += 1
    return words[start:], assignments


def _shell_commands(text: str) -> list[tuple[list[str], int]]:
    """Read simple words and count initial *unquoted* shell assignments.

    Word spans retain their quotes until shlex decodes them, so quoted
    punctuation cannot become a separator and a quoted NAME=value cannot
    become a shell assignment. This is not a general shell evaluator.
    """
    commands: list[tuple[list[str], int]] = []
    words: list[str] = []
    raw_words: list[str] = []
    pos = 0
    while pos < len(text):
        match = _SHELL_TOKEN.match(text, pos)
        if match is None:
            return []
        pos = match.end()
        if match.lastgroup == "separator":
            if words:
                commands.append(_shell_command(words, raw_words))
                words = []
                raw_words = []
        elif match.lastgroup == "word":
            raw = match.group()
            try:
                word = _decode_shell_word(raw)
            except ValueError:
                return []
            if not word:
                continue  # An unquoted backslash-newline is not an argument.
            if len(word) != 1:
                return []
            raw_words.append(raw)
            words.append(word[0])
    if words:
        commands.append(_shell_command(words, raw_words))
    return commands


def _after_wrapper_options(words: list[str], start: int, program: str) -> int | None:
    """Skip only options with known arity; never consume a guessed operand."""
    flags, value_flags, long_flags, long_value_flags = _WRAPPER_OPTIONS[program]
    index = start
    while index < len(words):
        word = words[index]
        if word == "--":
            return index + 1
        if not word.startswith("-") or word == "-":
            return index
        if word.startswith("--"):
            option, equal, _value = word[2:].partition("=")
            if option in long_flags and not equal:
                index += 1
                continue
            if option not in long_value_flags:
                return None
            index += 1
            if not equal:
                if index >= len(words):
                    return None
                index += 1
            continue
        for position, flag in enumerate(word[1:], start=1):
            if flag in value_flags:
                if position == len(word) - 1:
                    index += 1
                    if index >= len(words):
                        return None
                break
            if flag not in flags:
                return None
        index += 1
    return index


def _rm_command(words: list[str], *, initial_assignments: int = 0) -> str | None:
    """Unwrap known execution prefixes while preserving argv word boundaries."""
    index = initial_assignments
    allow_assignments = False
    while index < len(words):
        if allow_assignments:
            while index < len(words) and _ASSIGNMENT.match(words[index]):
                index += 1
            if index == len(words):
                return None
        program = words[index]
        if program == "rm":
            return shlex.join(words[index:])
        if program not in _WRAPPER_OPTIONS:
            return None
        next_index = _after_wrapper_options(words, index + 1, program)
        if next_index is None:
            return None
        index = next_index
        # env and sudo accept NAME=value before their executable; e.g. nohup
        # and command instead treat NAME=value as the executable name itself.
        allow_assignments = program in ("env", "sudo")
    return None


_RM_WARNINGS = frozenset(
    ("may recursively force-remove files", "may recursively remove files", "may force-remove files")
)

_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    # Git — data loss / hard to reverse
    (re.compile(r"\bgit\s+reset\s+--hard\b"), "may discard uncommitted changes"),
    (
        re.compile(r"\bgit\s+push\b[^;&|\n]*[ \t](--force|--force-with-lease|-f)\b"),
        "may overwrite remote history",
    ),
    (
        re.compile(r"\bgit\s+clean\b(?![^;&|\n]*(?:-[a-zA-Z]*n|--dry-run))[^;&|\n]*-[a-zA-Z]*f"),
        "may permanently delete untracked files",
    ),
    (re.compile(r"\bgit\s+checkout\s+(--\s+)?\.[ \t]*($|[;&|\n])"), "may discard all working tree changes"),
    (re.compile(r"\bgit\s+restore\s+(--\s+)?\.[ \t]*($|[;&|\n])"), "may discard all working tree changes"),
    (re.compile(r"\bgit\s+stash[ \t]+(drop|clear)\b"), "may permanently remove stashed changes"),
    (
        re.compile(r"\bgit\s+branch\s+(-D[ \t]|--delete\s+--force|--force\s+--delete)\b"),
        "may force-delete a branch",
    ),
    # Git — safety bypass
    (re.compile(r"\bgit\s+(commit|push|merge)\b[^;&|\n]*--no-verify\b"), "may skip safety hooks"),
    (re.compile(r"\bgit\s+commit\b[^;&|\n]*--amend\b"), "may rewrite the last commit"),
    # File deletion — most specific patterns first so the warning is descriptive
    (
        re.compile(
            r"^rm\s+-[a-zA-Z]*[rR][a-zA-Z]*f"
            r"|^rm\s+-[a-zA-Z]*f[a-zA-Z]*[rR]"
        ),
        "may recursively force-remove files",
    ),
    (re.compile(r"^rm\s+-[a-zA-Z]*[rR]"), "may recursively remove files"),
    (re.compile(r"^rm\s+-[a-zA-Z]*f"), "may force-remove files"),
    # Database
    (
        re.compile(r"\b(DROP|TRUNCATE)\s+(TABLE|DATABASE|SCHEMA)\b", re.IGNORECASE),
        "may drop or truncate database objects",
    ),
    (re.compile(r"\bDELETE\s+FROM\s+\w+[ \t]*(;|\"|'|\n|$)", re.IGNORECASE), "may delete rows from a database table"),
    # Infrastructure
    (re.compile(r"\bkubectl\s+delete\b"), "may delete Kubernetes resources"),
    (re.compile(r"\bterraform\s+destroy\b"), "may destroy Terraform infrastructure"),
)


def get_warning(command: str | Sequence[str]) -> str | None:
    """Return the first matching advisory without executing the command.

    For rm warnings, parse shell-string boundaries or preserve supplied argv
    boundaries before unwrapping known prefixes. Other catalog behavior is
    unchanged, including its original space-joined argv representation.
    """
    if isinstance(command, (list, tuple)):
        words = [str(c) for c in command]
        text = " ".join(words)
        simple_commands = [(words, 0)]
    else:
        text = command
        simple_commands = _shell_commands(text)

    rm_commands = [
        parsed
        for words, assignments in simple_commands
        if (parsed := _rm_command(words, initial_assignments=assignments)) is not None
    ]
    for pattern, message in _PATTERNS:
        candidates = rm_commands if message in _RM_WARNINGS else (text,)
        if any(pattern.search(candidate) for candidate in candidates):
            return message
    return None


__all__ = ["get_warning"]
