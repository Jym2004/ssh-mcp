"""Local safety policy for ssh-mcp tools.

The policy is intentionally conservative.  It is a guardrail, not a security
boundary: a determined shell user can still hide commands in scripts or
interpreters.  Real privilege separation belongs on the remote host (sudoers,
restricted accounts, backups).
"""
from __future__ import annotations

import os
import posixpath
import json
import re
import shlex
from collections.abc import Sequence
from pathlib import Path

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

DEFAULT_DELETE_ROOTS: tuple[str, ...] = ("~/projects/", "~/scratch/", "/data/", "/scratch/", "/tmp/")
ALLOWED_SESSION_MODES = frozenset({"safe", "admin"})
ALLOWED_SESSION_SHELLS = frozenset({"sh", "bash", "dash", "zsh", "fish"})
BLOCKED_SESSION_ENV = frozenset(
    {"BASH_ENV", "ENV", "PROMPT_COMMAND", "SHELLOPTS", "BASHOPTS", "PATH", "LD_PRELOAD"}
)
CRITICAL_ROOTS: frozenset[str] = frozenset(
    {
        "/",
        "/etc",
        "/boot",
        "/dev",
        "/proc",
        "/sys",
        "/usr",
        "/bin",
        "/sbin",
        "/lib",
        "/lib64",
        "/var",
        "/root",
        "/home",
        "/data",
        "/scratch",
        "/tmp",
        "/mnt",
        "/opt",
    }
)


class PolicyViolation(Exception):
    """Raised when a tool call is denied by the local policy."""


def normalize_command(command: str) -> str:
    """Normalize a command just enough to catch trivial shell obfuscation."""
    text = ANSI_ESCAPE_RE.sub("", command)
    text = text.replace("\\\n", " ")
    text = SHELL_QUOTES_RE.sub("", text)
    text = WHITESPACE_RE.sub(" ", text).strip()
    return text


def has_sudo(command: str) -> bool:
    normalized = normalize_command(command)
    return bool(SUDO_RE.search(normalized) or SU_RE.search(normalized))


def destructive_reason(command: str) -> str | None:
    normalized = normalize_command(command)
    for pattern, reason in DESTRUCTIVE_PATTERNS:
        if pattern.search(normalized):
            return reason
    return None


def _default_delete_roots() -> tuple[str, ...]:
    raw = os.environ.get("SSH_MCP_DELETE_ROOTS", "").strip()
    if not raw:
        return DEFAULT_DELETE_ROOTS
    parts = [part.strip() for part in re.split(r"[:;]", raw) if part.strip()]
    return tuple(parts) or DEFAULT_DELETE_ROOTS


def _default_sudo_commands() -> tuple[str, ...]:
    raw = os.environ.get("SSH_MCP_SUDO_COMMANDS", "").strip()
    if not raw:
        return ()
    return tuple(part.strip() for part in raw.split(";") if part.strip())


def _load_policy_config() -> dict[str, object]:
    configured_path = os.environ.get("SSH_MCP_POLICY_CONFIG", "").strip()
    path = (
        Path(configured_path).expanduser()
        if configured_path
        else Path.home() / ".config" / "ssh-mcp-policy" / "policy.json"
    )
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"cannot read SSH MCP policy config {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise ValueError(f"SSH MCP policy config {path} must contain a JSON object")
    return data


def _delete_path_error(path: str, roots: Sequence[str]) -> str | None:
    if not path:
        return "path must not be empty"
    if "\x00" in path or "\n" in path or "\r" in path:
        return "path must not contain NUL or newlines"
    if any(char in path for char in "*?[]"):
        return "globs are not allowed; pass literal paths"
    if path == "/" or path == "~" or path == "~/":
        return "refusing to delete a root or home directory"

    if path.startswith("~/"):
        normalized = posixpath.normpath(path)
        if normalized in {"~", "~/", ".", ".."} or normalized.startswith("../"):
            return "path escapes the home directory"
        for root in roots:
            root = root.rstrip("/")
            if root in {"~", "~/"}:
                return None
            if root.startswith("~/"):
                normalized_root = posixpath.normpath(root)
                if normalized == normalized_root or normalized.startswith(normalized_root + "/"):
                    if normalized == normalized_root:
                        return "refusing to delete an allowed-root directory itself"
                    return None
        return "path is outside the allowed delete roots"

    if not path.startswith("/"):
        return "path must be absolute or start with '~/'"

    normalized = posixpath.normpath(path)
    if normalized in CRITICAL_ROOTS:
        return f"refusing to delete protected root {normalized}"
    if normalized.startswith("//") or "/../" in normalized or normalized.startswith("../"):
        return "path escapes the allowed delete roots"

    allowed = False
    for root in roots:
        if root == "~/":
            continue
        if not root.startswith("/"):
            continue
        root = root.rstrip("/") + "/"
        if normalized.startswith(root):
            relative = normalized[len(root):]
            if not relative:
                return f"refusing to delete protected root {normalized}"
            if root == "/home/" and "/" not in relative:
                return "refusing to delete a user's home directory root"
            allowed = True
            break
    if not allowed:
        return "path is outside the allowed delete roots"
    return None


class Policy:
    def __init__(
        self,
        delete_roots: Sequence[str] | None = None,
        sudo_allowed_commands: Sequence[str] | None = None,
    ) -> None:
        config = _load_policy_config()
        env_roots = os.environ.get("SSH_MCP_DELETE_ROOTS")
        configured_roots = config.get("delete_roots", DEFAULT_DELETE_ROOTS)
        if not isinstance(configured_roots, (list, tuple)) or not all(
            isinstance(root, str) for root in configured_roots
        ):
            raise ValueError("policy delete_roots must be an array of strings")
        if delete_roots is not None:
            selected_roots = delete_roots
        elif env_roots is not None:
            selected_roots = _default_delete_roots()
        else:
            selected_roots = configured_roots
        self.delete_roots = tuple(selected_roots)

        env_sudo = os.environ.get("SSH_MCP_SUDO_COMMANDS")
        configured_sudo = config.get("sudo_commands", [])
        if not isinstance(configured_sudo, (list, tuple)) or not all(
            isinstance(command, str) for command in configured_sudo
        ):
            raise ValueError("policy sudo_commands must be an array of strings")
        if sudo_allowed_commands is not None:
            raw_specs = sudo_allowed_commands
        elif env_sudo is not None:
            raw_specs = _default_sudo_commands()
        else:
            raw_specs = configured_sudo
        if "*" in raw_specs and len(raw_specs) != 1:
            raise ValueError("sudo command wildcard '*' must be the only sudo_commands entry")
        self.allow_any_sudo_command = raw_specs == ["*"] or raw_specs == ("*",)
        parsed_specs: list[tuple[str, ...]] = []
        for spec in raw_specs:
            if spec == "*":
                continue
            try:
                tokens = shlex.split(spec, posix=True)
            except ValueError as exc:
                raise ValueError(f"invalid SSH_MCP_SUDO_COMMANDS entry {spec!r}: {exc}") from exc
            if not tokens or not tokens[0].startswith("/"):
                raise ValueError("sudo allowlist entries must start with an absolute executable path")
            parsed_specs.append((posixpath.normpath(tokens[0]), *tokens[1:]))
        self.sudo_allowed_commands = tuple(parsed_specs)

    def check_exec(self, command: str) -> None:
        if has_sudo(command):
            raise PolicyViolation(
                "sudo is blocked in ssh_exec; use ssh_sudo_exec for a separate approval."
            )
        reason = destructive_reason(command)
        if reason:
            raise PolicyViolation(
                f"destructive command blocked ({reason}); use ssh_delete for a separate approval."
            )

    def authorize_sudo_exec(self, command: str) -> list[str]:
        reason = destructive_reason(command)
        if reason:
            raise PolicyViolation(
                f"destructive command blocked in ssh_sudo_exec ({reason}); "
                "use an approved admin session or a server-side safe wrapper."
            )
        if any(char in command for char in "\n\r;|&<>`$"):
            raise PolicyViolation(
                "ssh_sudo_exec accepts one executable and arguments only; shell operators are not allowed."
            )
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
        if not self.allow_any_sudo_command and not any(
            tokens[: len(spec)] == list(spec) for spec in self.sudo_allowed_commands
        ):
            allowed = "; ".join(shlex.join(spec) for spec in self.sudo_allowed_commands) or "none configured"
            raise PolicyViolation(
                f"sudo command {shlex.join(tokens)!r} is not allowed; configured command prefixes: {allowed}. "
                "Set SSH_MCP_SUDO_COMMANDS to an explicit absolute-path allowlist."
            )
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

        normalized = normalize_command(input_text)
        if not normalized:
            return
        if re.search(r";|&&|\|\||(?<!\|)\|(?!\|)|(?<!&)\&(?!&)|[<>]|`|\$\(", normalized):
            raise PolicyViolation(
                "interactive writes accept one command or response; shell chaining and substitutions are blocked"
            )
        reason = destructive_reason(normalized)
        if reason:
            raise PolicyViolation(
                f"destructive command blocked in an interactive session ({reason}); "
                "use ssh_delete for a separate approval."
            )
        if has_sudo(normalized):
            if mode == "admin":
                raise PolicyViolation(
                    "sudo is blocked in normal admin-session writes; use "
                    "ssh_admin_sudo_session_write for a separate approval."
                )
            raise PolicyViolation("sudo is blocked in a normal session; use ssh_sudo_exec.")

    def check_delete_paths(self, paths: Sequence[str]) -> None:
        if not paths:
            raise PolicyViolation("at least one path is required")
        for path in paths:
            error = _delete_path_error(path, self.delete_roots)
            if error:
                raise PolicyViolation(f"delete denied for {path!r}: {error}")

    def check_sync_delete(self, delete: bool) -> None:
        if delete:
            raise PolicyViolation(
                "rsync --delete is blocked; use ssh_delete for a separate approval."
            )

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
    if path.startswith("~/"):
        suffix = path[1:]
        return '"$HOME"' + shlex.quote(suffix)
    if path.startswith("/"):
        return shlex.quote(path)
    raise PolicyViolation(f"delete path must be absolute or start with '~/': {path!r}")


def build_delete_command(paths: Sequence[str], *, recursive: bool) -> str:
    mode = "rm -r --" if recursive else "rm --"
    return " ".join([mode, *(remote_path_expression(path) for path in paths)])
