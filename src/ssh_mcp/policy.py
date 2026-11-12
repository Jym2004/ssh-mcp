"""Input-shape checks for approval-gated ssh-mcp operations.

Dangerous remote commands are approved by the MCP client's per-call
permission prompt. This module deliberately does not replace that approval
with a command or path blacklist. It keeps only structural checks needed to
construct an unambiguous tool request safely.
"""
from __future__ import annotations

import posixpath
import re
import shlex
from collections.abc import Sequence

ANSI_ESCAPE_RE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
SHELL_QUOTES_RE = re.compile(r"['\"\\]")
WHITESPACE_RE = re.compile(r"\s+")
SUDO_RE = re.compile(
    r"(?<![\w./-])(?:/[\w./-]+/)?(?:sudo|doas|pkexec)\b",
    re.IGNORECASE,
)
SU_RE = re.compile(
    r"(?<![\w./-])(?:/[\w./-]+/)?su\s+(?:-|--|-\S)",
    re.IGNORECASE,
)

# Kept as classification helpers for diagnostics and tests. They are not
# consulted by the execution gates; the MCP client's approval is the gate.
DESTRUCTIVE_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"(?<![\w./-])(?:/[\w./-]+/)?(?:rm|rmdir|unlink)\b", re.IGNORECASE), "remove files"),
    (re.compile(r"(?<![\w./-])(?:/[\w./-]+/)?shred\b", re.IGNORECASE), "shred files"),
    (re.compile(r"(?<![\w./-])(?:/[\w./-]+/)?truncate\b", re.IGNORECASE), "truncate files"),
    (re.compile(r"\bfind\b[^\n]*(?:-delete\b|-exec\s+rm\b)", re.IGNORECASE), "find -delete"),
    (re.compile(r"\bdd\b[^\n]*\bof\s*=", re.IGNORECASE), "dd overwrite"),
    (re.compile(r"(?<![\w./-])(?:/[\w./-]+/)?mkfs(?:\.\w+)?\b", re.IGNORECASE), "format filesystem"),
    (re.compile(r"\b(?:wipefs|blkdiscard|sgdisk|fdisk|parted)\b", re.IGNORECASE), "partition/disk operation"),
    (re.compile(r"\bgit\s+clean\b[^\n]*\s-[a-zA-Z]*[fdx]", re.IGNORECASE), "git clean"),
    (re.compile(r"\brsync\b[^\n]*--delete", re.IGNORECASE), "rsync --delete"),
    (re.compile(r"\bdocker\s+(?:system|volume|container|image|network)\s+prune\b", re.IGNORECASE), "docker prune"),
    (re.compile(r"\bdocker\s+(?:rm|rmi)\b", re.IGNORECASE), "docker rm/rmi"),
    (re.compile(r"\bkubectl\s+delete\b", re.IGNORECASE), "kubectl delete"),
    (re.compile(r"\bhelm\s+uninstall\b", re.IGNORECASE), "helm uninstall"),
    (re.compile(r"\b(?:DROP\s+(?:TABLE|DATABASE)|TRUNCATE\s+TABLE)\b", re.IGNORECASE), "SQL destructive statement"),
)

ALLOWED_SESSION_MODES = frozenset({"safe", "admin"})
ALLOWED_SESSION_SHELLS = frozenset({"sh", "bash", "dash", "zsh", "fish"})
BLOCKED_SESSION_ENV = frozenset(
    {"BASH_ENV", "ENV", "PROMPT_COMMAND", "SHELLOPTS", "BASHOPTS", "PATH", "LD_PRELOAD"}
)


class PolicyViolation(Exception):
    """Raised when a tool call has invalid structure."""


def normalize_command(command: str) -> str:
    """Normalize text for diagnostic classification only."""
    text = ANSI_ESCAPE_RE.sub("", command)
    text = text.replace("\\\n", " ")
    text = SHELL_QUOTES_RE.sub("", text)
    return WHITESPACE_RE.sub(" ", text).strip()


def has_sudo(command: str) -> bool:
    normalized = normalize_command(command)
    return bool(SUDO_RE.search(normalized) or SU_RE.search(normalized))


def destructive_reason(command: str) -> str | None:
    normalized = normalize_command(command)
    for pattern, reason in DESTRUCTIVE_PATTERNS:
        if pattern.search(normalized):
            return reason
    return None


class Policy:
    def __init__(
        self,
        delete_roots: Sequence[str] | None = None,
        sudo_allowed_commands: Sequence[str] | None = None,
    ) -> None:
        # Keep the constructor compatible with older callers. These values no
        # longer decide whether an approved MCP call may execute.
        del delete_roots, sudo_allowed_commands

    def check_exec(self, command: str) -> None:
        """Leave command-content approval to the MCP client's permission prompt."""
        del command

    def authorize_sudo_exec(self, command: str) -> list[str]:
        try:
            tokens = shlex.split(command, posix=True)
        except ValueError as exc:
            raise PolicyViolation(f"invalid sudo command syntax: {exc}") from exc
        if not tokens:
            raise PolicyViolation("sudo command must not be empty")
        executable = posixpath.normpath(tokens[0])
        if not executable.startswith("/"):
            raise PolicyViolation("sudo executable must use an absolute path")
        tokens[0] = executable
        return tokens

    def check_session_input(self, input_text: str, *, mode: str) -> None:
        if mode not in ALLOWED_SESSION_MODES:
            raise PolicyViolation(f"unknown session policy mode: {mode!r}")
        if input_text in {"\x03", "\x04", "\x1a"}:
            return
        if any(char in input_text for char in ("\x03", "\x04", "\x1a")):
            raise PolicyViolation("send terminal control keys separately")
        if not input_text.endswith("\n"):
            raise PolicyViolation("submit a complete newline-terminated command or response")
        if len([line for line in input_text.splitlines() if line.strip()]) > 1:
            raise PolicyViolation("submit one command or response per tool call")

    def check_delete_paths(self, paths: Sequence[str]) -> None:
        if not paths:
            raise PolicyViolation("at least one path is required")
        for path in paths:
            if not path or "\x00" in path or "\n" in path or "\r" in path:
                raise PolicyViolation("delete paths must be non-empty and contain no NUL or newline characters")
            if path != "~" and not path.startswith("~/") and not path.startswith("/"):
                raise PolicyViolation("delete paths must be absolute or start with '~/'.")

    def check_sync_delete(self, delete: bool) -> None:
        del delete

    def check_session_options(self, *, shell: str | None, environment: dict[str, str]) -> None:
        if shell is not None and posixpath.basename(shell) not in ALLOWED_SESSION_SHELLS:
            raise PolicyViolation(
                "session shell must be a standard interactive shell (sh, bash, dash, zsh, or fish)"
            )
        blocked = sorted(name for name in environment if name.upper() in BLOCKED_SESSION_ENV)
        if blocked:
            raise PolicyViolation(
                f"session environment cannot override shell startup/security variables: {', '.join(blocked)}"
            )


def remote_path_expression(path: str) -> str:
    if path == "~":
        return '"$HOME"'
    if path.startswith("~/"):
        suffix = path[1:]
        return '"$HOME"' + shlex.quote(suffix)
    if path.startswith("/"):
        return shlex.quote(path)
    raise PolicyViolation(f"delete path must be absolute or start with '~/': {path!r}")


def build_delete_command(paths: Sequence[str], *, recursive: bool) -> str:
    mode = "rm -r --" if recursive else "rm --"
    return " ".join([mode, *(remote_path_expression(path) for path in paths)])
