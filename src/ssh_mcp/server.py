from __future__ import annotations

import json
import sys
import threading
import traceback
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from collections.abc import Callable, Mapping
from typing import Any

from . import __version__
from .policy import PolicyViolation
from .ssh import ForwardNotFoundError, RemoteFileError, SessionNotFoundError, SshToolService, ValidationError

SERVER_NAME = "ssh-mcp"
SUPPORTED_PROTOCOL_VERSIONS = ("2025-06-18", "2024-11-05")
DEFAULT_PROTOCOL_VERSION = SUPPORTED_PROTOCOL_VERSIONS[0]
SERVER_CAPABILITIES = {"tools": {"listChanged": False}}

JSONRPC_PARSE_ERROR = -32700
JSONRPC_INVALID_REQUEST = -32600
JSONRPC_METHOD_NOT_FOUND = -32601
JSONRPC_INVALID_PARAMS = -32602
JSONRPC_INTERNAL_ERROR = -32603
JSONRPC_SERVER_NOT_INITIALIZED = -32002


def _pretty_json(value: Any) -> str:
    return json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False)


def _tool_success(result: Mapping[str, Any]) -> dict[str, Any]:
    payload = dict(result)
    return {
        "content": [{"type": "text", "text": _pretty_json(payload)}],
        "structuredContent": payload,
        "isError": False,
    }


def _tool_error(message: str, *, error_type: str, details: Mapping[str, Any] | None = None) -> dict[str, Any]:
    structured: dict[str, Any] = {"ok": False, "error_type": error_type, "message": message}
    if details:
        structured["details"] = dict(details)
    return {
        "content": [{"type": "text", "text": message}],
        "structuredContent": structured,
        "isError": True,
    }


def _jsonrpc_error(code: int, message: str, *, request_id: Any, data: Mapping[str, Any] | None = None) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "jsonrpc": "2.0",
        "id": request_id,
        "error": {"code": code, "message": message},
    }
    if data:
        payload["error"]["data"] = dict(data)
    return payload


_EXTRA_SSH_ARGS_SCHEMA: dict[str, Any] = {
    "type": "array",
    "items": {"type": "string"},
    "description": (
        "Additional ssh(1) flags passed verbatim, e.g. [\"-J\", \"jumphost\"]. "
        "Prefer the dedicated port, identity_file, and strict_host_key_checking parameters."
    ),
}

_STRICT_HOST_KEY_CHECKING_SCHEMA: dict[str, Any] = {
    "description": "Boolean or one of yes, no, ask, accept-new, off.",
    # OpenAI function schemas support anyOf, but reject oneOf. Keep both
    # input types so existing boolean callers retain their SSH semantics.
    "anyOf": [{"type": "boolean"}, {"type": "string"}],
}

_SESSION_NAME_SCHEMA: dict[str, Any] = {
    "type": "string",
    "description": (
        "Stable name for this session, used for recovery and reuse across tool calls. "
        "Choose a short, descriptive kebab-case name reflecting the task, "
        "e.g. 'deploy-staging', 'tail-api-logs', 'debug-worker-3'. "
        "This name also appears in tmux session listings for human observers. "
        "Strongly recommended for any multi-step workflow."
    ),
}

TOOL_DEFINITIONS: list[dict[str, Any]] = [
    {
        "name": "ssh_exec",
        "description": (
            "Run a one-off remote SSH command and return stdout, stderr, and exit metadata. "
            "The command runs in a non-interactive context and is approval-gated by the MCP client. "
            "Use 'cwd' and 'env' for remote "
            "directory and environment setup (requires a POSIX shell on the remote). "
            "For interactive or long-running commands, use ssh_ensure_session instead."
        ),
        "inputSchema": {
            "type": "object",
            "additionalProperties": False,
            "required": ["target", "command"],
            "properties": {
                "target": {"type": "string", "description": "OpenSSH target such as host, alias, or user@host."},
                "command": {"type": "string", "description": "Remote command string to execute."},
                "cwd": {"type": "string", "description": "Remote directory to cd into before running the command."},
                "env": {
                    "type": "object",
                    "description": "Remote environment variables exported before the command runs.",
                    "additionalProperties": {"type": "string"},
                },
                "shell": {
                    "type": "string",
                    "description": "Remote shell executable used to wrap the command when shell/cwd/env behavior is needed.",
                },
                "timeout": {"type": "number", "description": "Local timeout in seconds."},
                "tty": {
                    "type": "boolean",
                    "description": (
                        "Request a remote TTY (ssh -tt). Required for interactive commands "
                        "(sudo with password prompt, etc.). Avoid for scripted commands: "
                        "stdout and stderr are merged and ANSI escape codes will be present in output. "
                        "Default: false."
                    ),
                },
                "port": {"type": "integer", "minimum": 1, "maximum": 65535},
                "identity_file": {"type": "string"},
                "known_hosts_file": {"type": "string"},
                "strict_host_key_checking": _STRICT_HOST_KEY_CHECKING_SCHEMA,
                "extra_ssh_args": _EXTRA_SSH_ARGS_SCHEMA,
            },
        },
    },
    {
        "name": "ssh_scp",
        "description": "Copy files or directories between the local machine and one remote target via the local scp client.",
        "inputSchema": {
            "type": "object",
            "additionalProperties": False,
            "required": ["target", "direction", "sources", "destination"],
            "properties": {
                "target": {"type": "string", "description": "OpenSSH target (host alias or user@host). Specifies the remote host — do not include the host in sources or destination."},
                "direction": {"type": "string", "enum": ["upload", "download"]},
                "sources": {
                    "type": "array",
                    "minItems": 1,
                    "items": {"type": "string"},
                    "description": "For upload: local file or directory paths. For download: remote paths (without host prefix — the host is set by 'target').",
                },
                "destination": {
                    "type": "string",
                    "description": "For upload: remote directory path. For download: local directory or file path.",
                },
                "recursive": {"type": "boolean", "description": "Copy directories recursively. Required when any source is a directory."},
                "preserve_times": {"type": "boolean", "description": "Preserve modification times and modes."},
                "timeout": {"type": "number", "description": "Local timeout in seconds."},
                "port": {"type": "integer", "minimum": 1, "maximum": 65535},
                "identity_file": {"type": "string"},
                "known_hosts_file": {"type": "string"},
                "strict_host_key_checking": _STRICT_HOST_KEY_CHECKING_SCHEMA,
                "extra_ssh_args": _EXTRA_SSH_ARGS_SCHEMA,
            },
        },
    },
    {
        "name": "ssh_sync",
        "description": "Approval-gated sync between the local machine and one remote target via rsync over SSH. Review source, destination, and delete behavior before approving.",
        "inputSchema": {
            "type": "object",
            "additionalProperties": False,
            "required": ["target", "direction", "source", "destination"],
            "properties": {
                "target": {"type": "string", "description": "OpenSSH target (host alias or user@host). Specifies the remote host — do not include the host in source or destination."},
                "direction": {"type": "string", "enum": ["upload", "download"]},
                "source": {
                    "type": "string",
                    "description": "For upload: local path. For download: remote path (without host prefix).",
                },
                "destination": {
                    "type": "string",
                    "description": "For upload: remote path. For download: local path.",
                },
                "delete": {"type": "boolean", "description": "Also delete destination files absent from the source. Review both paths and approve this destructive call carefully."},
                "compress": {"type": "boolean", "description": "Compress data during transfer. Default: true."},
                "dry_run": {"type": "boolean", "description": "Show what would be transferred without actually doing it."},
                "exclude": {"type": "array", "items": {"type": "string"}, "description": "Glob patterns to exclude from the sync."},
                "timeout": {"type": "number", "description": "Local timeout in seconds."},
                "extra_rsync_args": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Additional rsync flags passed verbatim.",
                },
                "port": {"type": "integer", "minimum": 1, "maximum": 65535},
                "identity_file": {"type": "string"},
                "known_hosts_file": {"type": "string"},
                "strict_host_key_checking": _STRICT_HOST_KEY_CHECKING_SCHEMA,
                "extra_ssh_args": _EXTRA_SSH_ARGS_SCHEMA,
            },
        },
    },
    {
        "name": "ssh_view",
        "description": (
            "Read a remote file or list a remote directory over SSH — the remote counterpart "
            "of the local file-viewing tool. For a file, returns its content plus 'size_bytes' "
            "and 'total_lines'. Content is truncated at 20KB by default when 'view_range' isn't "
            "given and 'force_read_large_files' isn't set; use 'view_range' to page through large "
            "files instead. For a directory, returns non-hidden entries up to 2 levels deep."
        ),
        "inputSchema": {
            "type": "object",
            "additionalProperties": False,
            "required": ["target", "path"],
            "properties": {
                "target": {"type": "string", "description": "OpenSSH target such as host, alias, or user@host."},
                "path": {"type": "string", "description": "Absolute (or login-directory-relative) remote path to a file or directory."},
                "view_range": {
                    "type": "array",
                    "items": {"type": "integer"},
                    "minItems": 2,
                    "maxItems": 2,
                    "description": "Optional [start_line, end_line] (1-based, inclusive). Use end_line -1 for 'to end of file'. Bypasses the 20KB truncation cutoff.",
                },
                "force_read_large_files": {
                    "type": "boolean",
                    "description": "Read the full file even if it exceeds the truncation cutoff. Ignored when 'view_range' is given. Default: false.",
                },
                "max_bytes": {
                    "type": "integer",
                    "minimum": 1,
                    "description": "Truncation cutoff in bytes for the default (no view_range, no force) read. Default: 20480 (20KB).",
                },
                "timeout": {"type": "number", "description": "Local timeout in seconds."},
                "port": {"type": "integer", "minimum": 1, "maximum": 65535},
                "identity_file": {"type": "string"},
                "known_hosts_file": {"type": "string"},
                "strict_host_key_checking": _STRICT_HOST_KEY_CHECKING_SCHEMA,
                "extra_ssh_args": _EXTRA_SSH_ARGS_SCHEMA,
            },
        },
    },
    {
        "name": "ssh_create",
        "description": (
            "Create a new remote file over SSH with the given content — the remote counterpart "
            "of the local file-creation tool. Fails if the path already exists (use ssh_edit to "
            "modify an existing file) or if the remote parent directory doesn't exist."
        ),
        "inputSchema": {
            "type": "object",
            "additionalProperties": False,
            "required": ["target", "path", "content"],
            "properties": {
                "target": {"type": "string", "description": "OpenSSH target such as host, alias, or user@host."},
                "path": {"type": "string", "description": "Absolute (or login-directory-relative) remote path to create. Must not already exist."},
                "content": {"type": "string", "description": "Full content to write to the new file."},
                "timeout": {"type": "number", "description": "Local timeout in seconds."},
                "port": {"type": "integer", "minimum": 1, "maximum": 65535},
                "identity_file": {"type": "string"},
                "known_hosts_file": {"type": "string"},
                "strict_host_key_checking": _STRICT_HOST_KEY_CHECKING_SCHEMA,
                "extra_ssh_args": _EXTRA_SSH_ARGS_SCHEMA,
            },
        },
    },
    {
        "name": "ssh_edit",
        "description": (
            "Replace exact text in an existing remote file over SSH — the remote counterpart of "
            "the local file-editing tool. Each edit's 'old_str' must match exactly one location "
            "in the file (as it stands after any earlier edits in the same call); ambiguous or "
            "missing matches fail without writing anything. Provide multiple {old_str, new_str} "
            "entries in 'edits' to batch several changes to the same file into a single "
            "read-then-write round trip instead of one SSH round trip per edit."
        ),
        "inputSchema": {
            "type": "object",
            "additionalProperties": False,
            "required": ["target", "path", "edits"],
            "properties": {
                "target": {"type": "string", "description": "OpenSSH target such as host, alias, or user@host."},
                "path": {"type": "string", "description": "Absolute (or login-directory-relative) remote path. Must already exist as a regular file."},
                "edits": {
                    "type": "array",
                    "minItems": 1,
                    "items": {
                        "type": "object",
                        "additionalProperties": False,
                        "required": ["old_str", "new_str"],
                        "properties": {
                            "old_str": {
                                "type": "string",
                                "description": "Exact text to replace; must match exactly one location (include surrounding context to disambiguate).",
                            },
                            "new_str": {"type": "string", "description": "Replacement text."},
                        },
                    },
                    "description": "One or more replacements, applied in order against the file's current remote content.",
                },
                "timeout": {"type": "number", "description": "Local timeout in seconds."},
                "port": {"type": "integer", "minimum": 1, "maximum": 65535},
                "identity_file": {"type": "string"},
                "known_hosts_file": {"type": "string"},
                "strict_host_key_checking": _STRICT_HOST_KEY_CHECKING_SCHEMA,
                "extra_ssh_args": _EXTRA_SSH_ARGS_SCHEMA,
            },
        },
    },
    {
        "name": "ssh_grep",
        "description": (
            "Search remote file contents over SSH — the remote counterpart of the local content-"
            "search tool. Backed by remote grep (PCRE-like -P when available, otherwise POSIX "
            "extended regex), recursing under 'path' while skipping .git/.hg/.svn. Defaults to "
            "'files_with_matches' mode for efficiency; use 'content' mode for matching lines with "
            "line numbers and optional context."
        ),
        "inputSchema": {
            "type": "object",
            "additionalProperties": False,
            "required": ["target", "pattern"],
            "properties": {
                "target": {"type": "string", "description": "OpenSSH target such as host, alias, or user@host."},
                "pattern": {"type": "string", "description": "Regular expression to search for."},
                "path": {"type": "string", "description": "Remote file or directory to search. Default: '.' (the SSH login directory)."},
                "glob": {"type": "string", "description": "Glob filter for which filenames to search, e.g. '*.py' or '*.{ts,tsx}'."},
                "case_insensitive": {"type": "boolean", "description": "Case-insensitive search. Default: false."},
                "output_mode": {
                    "type": "string",
                    "enum": ["content", "files_with_matches", "count"],
                    "description": (
                        "'content': matching lines with line numbers (supports context). "
                        "'files_with_matches': just the matching paths (default). "
                        "'count': per-file match counts (files with zero matches are omitted)."
                    ),
                },
                "context": {"type": "integer", "minimum": 0, "description": "Lines of context before and after each match. Only applies to output_mode='content'."},
                "context_before": {"type": "integer", "minimum": 0, "description": "Lines of context before each match. Overridden by 'context' if both are given."},
                "context_after": {"type": "integer", "minimum": 0, "description": "Lines of context after each match. Overridden by 'context' if both are given."},
                "head_limit": {"type": "integer", "minimum": 1, "description": "Cap the number of returned matches/files."},
                "timeout": {"type": "number", "description": "Local timeout in seconds."},
                "port": {"type": "integer", "minimum": 1, "maximum": 65535},
                "identity_file": {"type": "string"},
                "known_hosts_file": {"type": "string"},
                "strict_host_key_checking": _STRICT_HOST_KEY_CHECKING_SCHEMA,
                "extra_ssh_args": _EXTRA_SSH_ARGS_SCHEMA,
            },
        },
    },
    {
        "name": "ssh_glob",
        "description": (
            "Find remote files by name pattern over SSH — the remote counterpart of the local "
            "filename-pattern tool. Supports '*', '?', '[seq]'/'[!seq]', '{a,b}' alternation, and "
            "'**' for matching across multiple path segments (e.g. 'src/**/*.ts'). A path segment "
            "starting with '.' is only matched by a pattern segment that itself starts with '.'. "
            "Enumerates under 'path' via remote find, skipping .git/.hg/.svn; matching is done locally."
        ),
        "inputSchema": {
            "type": "object",
            "additionalProperties": False,
            "required": ["target", "pattern"],
            "properties": {
                "target": {"type": "string", "description": "OpenSSH target such as host, alias, or user@host."},
                "pattern": {"type": "string", "description": "Glob pattern to match, relative to 'path', e.g. '**/*.ts' or '*.{ts,tsx}'."},
                "path": {"type": "string", "description": "Remote base directory to search under. Default: '.' (the SSH login directory)."},
                "head_limit": {"type": "integer", "minimum": 1, "description": "Cap the number of returned matches."},
                "timeout": {"type": "number", "description": "Local timeout in seconds."},
                "port": {"type": "integer", "minimum": 1, "maximum": 65535},
                "identity_file": {"type": "string"},
                "known_hosts_file": {"type": "string"},
                "strict_host_key_checking": _STRICT_HOST_KEY_CHECKING_SCHEMA,
                "extra_ssh_args": _EXTRA_SSH_ARGS_SCHEMA,
            },
        },
    },
    {
        "name": "ssh_start_session",
        "description": (
            "Start an approval-gated interactive SSH session backed by a local PTY. "
            "Each session input call should be reviewed by the MCP client. "
            "Returns the session id, initial output, and observer metadata. "
            "If 'truncated' is true or 'pending_output_chars' > 0 in the response, "
            "call ssh_read_session to retrieve the remaining buffered output. "
            "For most agent workflows, prefer ssh_ensure_session instead — it reuses "
            "existing sessions and avoids accidental duplicates."
        ),
        "inputSchema": {
            "type": "object",
            "additionalProperties": False,
            "required": ["target"],
            "properties": {
                "target": {"type": "string", "description": "OpenSSH target such as host, alias, or user@host."},
                "session_name": _SESSION_NAME_SCHEMA,
                "cwd": {"type": "string", "description": "Remote directory to cd into at session start."},
                "env": {"type": "object", "additionalProperties": {"type": "string"}, "description": "Remote environment variables to export at session start."},
                "shell": {"type": "string", "description": "Remote shell executable to launch."},
                "observer_mode": {
                    "type": "string",
                    "enum": ["transcript", "tmux"],
                    "description": "Passive observer mode. Defaults to 'tmux' and falls back to transcript-only observation if tmux is unavailable. 'transcript' always records a transcript and returns a local follow command.",
                },
                "auto_close": {
                    "type": "boolean",
                    "description": (
                        "When true, the session is automatically cleaned up after the remote shell "
                        "or command exits. Use for one-shot long-running commands where you want "
                        "session-style output streaming but don't need the shell afterwards. "
                        "Default: false."
                    ),
                },
                "wait_seconds": {
                    "type": "number",
                    "minimum": 0,
                    "description": "Maximum seconds to wait for initial output. Returns early after output settles briefly. Default: 1.0.",
                },
                "max_output_chars": {"type": "integer", "minimum": 1},
                "port": {"type": "integer", "minimum": 1, "maximum": 65535},
                "identity_file": {"type": "string"},
                "known_hosts_file": {"type": "string"},
                "strict_host_key_checking": _STRICT_HOST_KEY_CHECKING_SCHEMA,
                "extra_ssh_args": _EXTRA_SSH_ARGS_SCHEMA,
            },
        },
    },
    {
        "name": "ssh_ensure_session",
        "description": (
            "Return an existing running SSH session or start a new one. "
            "This is the recommended tool for agent workflows — always provide a descriptive "
            "session_name so the session can be reliably found across tool calls and conversations. "
            "When a session is reused (reused=true in response), the cwd, env, and shell "
            "parameters are ignored — they only apply when creating a new session. "
            "Reused sessions return buffered output immediately without waiting for new output. "
            "Check 'created' vs 'reused' in the response to know which happened."
        ),
        "inputSchema": {
            "type": "object",
            "additionalProperties": False,
            "required": ["target"],
            "properties": {
                "target": {"type": "string", "description": "OpenSSH target such as host, alias, or user@host."},
                "session_name": _SESSION_NAME_SCHEMA,
                "cwd": {"type": "string", "description": "Remote directory to cd into (only when creating a new session)."},
                "env": {"type": "object", "additionalProperties": {"type": "string"}, "description": "Remote environment variables (only when creating a new session)."},
                "shell": {"type": "string", "description": "Remote shell executable (only when creating a new session)."},
                "observer_mode": {
                    "type": "string",
                    "enum": ["transcript", "tmux"],
                    "description": "Observer mode to ensure on the reused or newly created session. Defaults to 'tmux' and falls back to transcript-only observation if tmux is unavailable.",
                },
                "auto_close": {
                    "type": "boolean",
                    "description": (
                        "When true, the session is automatically cleaned up after the remote shell "
                        "or command exits. Only applies when creating a new session. Default: false."
                    ),
                },
                "wait_seconds": {
                    "type": "number",
                    "minimum": 0,
                    "description": "Maximum seconds to wait for initial output of a new session. Reused sessions do not wait. Default: 1.0.",
                },
                "max_output_chars": {"type": "integer", "minimum": 1},
                "port": {"type": "integer", "minimum": 1, "maximum": 65535},
                "identity_file": {"type": "string"},
                "known_hosts_file": {"type": "string"},
                "strict_host_key_checking": _STRICT_HOST_KEY_CHECKING_SCHEMA,
                "extra_ssh_args": _EXTRA_SSH_ARGS_SCHEMA,
            },
        },
    },
    {
        "name": "ssh_read_session",
        "description": (
            "Read unread output from a tracked SSH session. "
            "Set wait_seconds (e.g. 1-10) as an upper bound for new output; "
            "0 returns immediately with whatever is buffered right now. Default: 1.0. "
            "New output returns after a brief quiet interval, not necessarily command completion. "
            "If 'truncated' is true or 'pending_output_chars' > 0, call again to drain remaining output. "
            "Check 'running' to know whether the session is still alive."
        ),
        "inputSchema": {
            "type": "object",
            "additionalProperties": False,
            "required": ["session_id"],
            "properties": {
                "session_id": {"type": "string"},
                "wait_seconds": {
                    "type": "number",
                    "minimum": 0,
                    "description": "Maximum seconds to wait for new output. Returns early after output settles briefly. Zero returns buffered output immediately. Default: 1.0.",
                },
                "max_output_chars": {"type": "integer", "minimum": 1},
            },
        },
    },
    {
        "name": "ssh_write_session",
        "description": (
            "Write text or a control sequence to an approval-gated SSH session PTY. "
            "Review each call before submitting it to the remote shell. "
            "Always terminate commands with a trailing newline (\\n) to submit them. "
            "Control characters: \\u0003 for Ctrl-C, \\u0004 for Ctrl-D, \\u001a for Ctrl-Z. "
            "Use wait_seconds (e.g. 1-5) as an upper bound for new output. Early output does not mean the command finished. "
            "Check 'pending_output_chars' in the response; if non-zero, call ssh_read_session to drain."
        ),
        "inputSchema": {
            "type": "object",
            "additionalProperties": False,
            "required": ["session_id", "input"],
            "properties": {
                "session_id": {"type": "string"},
                "input": {
                    "type": "string",
                    "description": (
                        "Raw text to write to the session PTY. Include '\\n' to press Enter. "
                        "Control characters work: '\\u0003' for Ctrl-C, '\\u0004' for Ctrl-D. "
                        "Text is written exactly as provided."
                    ),
                },
                "wait_seconds": {
                    "type": "number",
                    "minimum": 0,
                    "description": "Maximum seconds to wait for output after writing. Returns early after output settles briefly, not necessarily command completion. Default: 1.0.",
                },
                "max_output_chars": {"type": "integer", "minimum": 1},
            },
        },
    },
    {
        "name": "ssh_stop_session",
        "description": (
            "Terminate a tracked SSH session, close any attached tmux observer, and return "
            "final unread output plus exit metadata. The transcript file is preserved on disk."
        ),
        "inputSchema": {
            "type": "object",
            "additionalProperties": False,
            "required": ["session_id"],
            "properties": {
                "session_id": {"type": "string"},
                "force": {"type": "boolean", "description": "Send SIGKILL instead of SIGTERM. Default: false."},
                "wait_seconds": {"type": "number", "minimum": 0, "description": "Seconds to wait for process to exit. Default: 2.0."},
                "max_output_chars": {"type": "integer", "minimum": 1},
            },
        },
    },
    {
        "name": "ssh_list_sessions",
        "description": (
            "List tracked SSH sessions with their session_id, session_name, target, state, "
            "uptime, and observer details (including tmux_session_name for cross-referencing "
            "with tmux ls). Use session_name filter to find a specific named session."
        ),
        "inputSchema": {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "include_exited": {"type": "boolean", "description": "Include sessions that have exited. Default: true."},
                "target": {"type": "string", "description": "Filter by SSH target."},
                "session_name": {"type": "string", "description": "Filter by session name."},
            },
        },
    },
    {
        "name": "ssh_forward",
        "description": (
            "Start a dedicated SSH port forward (local or remote). This is a separate "
            "tool from ssh_exec/ssh_start_session so MCP clients can permission-gate "
            "port forwarding independently. Use direction 'local' to make a remote "
            "service reachable on a local port, or 'remote' to expose a local service "
            "on the remote host."
        ),
        "inputSchema": {
            "type": "object",
            "additionalProperties": False,
            "required": ["target", "direction", "local_port", "remote_host", "remote_port"],
            "properties": {
                "target": {"type": "string", "description": "OpenSSH target such as host, alias, or user@host."},
                "direction": {
                    "type": "string",
                    "enum": ["local", "remote"],
                    "description": (
                        "Forward direction. 'local' binds a local port that tunnels to a remote "
                        "host:port. 'remote' binds a remote port that tunnels back to a local host:port."
                    ),
                },
                "local_port": {"type": "integer", "minimum": 1, "maximum": 65535, "description": "Port on the local side."},
                "remote_host": {"type": "string", "description": "Destination host from the SSH server's perspective."},
                "remote_port": {"type": "integer", "minimum": 1, "maximum": 65535, "description": "Destination port."},
                "bind_address": {
                    "type": "string",
                    "description": (
                        "Address to bind on. Default: 127.0.0.1. Set to 0.0.0.0 to expose on "
                        "all interfaces (use with caution)."
                    ),
                },
                "port": {"type": "integer", "minimum": 1, "maximum": 65535},
                "identity_file": {"type": "string"},
                "known_hosts_file": {"type": "string"},
                "strict_host_key_checking": _STRICT_HOST_KEY_CHECKING_SCHEMA,
                "extra_ssh_args": _EXTRA_SSH_ARGS_SCHEMA,
            },
        },
    },
    {
        "name": "ssh_list_forwards",
        "description": (
            "List tracked SSH port forwards with their forward_id, direction, ports, "
            "target, and running status."
        ),
        "inputSchema": {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "include_stopped": {"type": "boolean", "description": "Include forwards that have exited. Default: false."},
                "target": {"type": "string", "description": "Filter by SSH target."},
            },
        },
    },
    {
        "name": "ssh_stop_forward",
        "description": "Stop a tracked SSH port forward and return its final status.",
        "inputSchema": {
            "type": "object",
            "additionalProperties": False,
            "required": ["forward_id"],
            "properties": {
                "forward_id": {"type": "string", "description": "ID of the forward to stop."},
            },
        },
    },
]


def _clone_tool_definition(base_name: str, name: str, description: str) -> dict[str, Any]:
    base = next(tool for tool in TOOL_DEFINITIONS if tool["name"] == base_name)
    clone = deepcopy(base)
    clone["name"] = name
    clone["description"] = description
    return clone


_sudo_exec_tool = _clone_tool_definition(
    "ssh_exec",
    "ssh_sudo_exec",
    "Run one approval-gated sudo executable. Uses sudo -n and requires an absolute executable path. Review the complete command before approving it.",
)
_sudo_exec_properties = _sudo_exec_tool["inputSchema"]["properties"]
for _key in ("cwd", "env", "shell", "tty"):
    _sudo_exec_properties.pop(_key, None)
_sudo_exec_properties["command"]["description"] = (
    "Write the full program location followed by arguments, e.g. /usr/bin/apt-get update "
    "instead of apt-get update. Review the complete command before approving it."
)

_delete_tool: dict[str, Any] = {
    "name": "ssh_delete",
    "description": (
        "Delete literal remote paths. The MCP client should ask before this call. "
        "Defaults to dry-run; actual deletion requires both dry_run=false and confirm=true. "
        "Review every path and recursive setting before approval."
    ),
    "inputSchema": {
        "type": "object",
        "additionalProperties": False,
        "required": ["target", "paths"],
        "properties": {
            "target": {"type": "string", "description": "OpenSSH target such as host alias or user@host."},
            "paths": {
                "type": "array",
                "minItems": 1,
                "items": {"type": "string"},
                "description": "Absolute paths or paths under ~/. Review each path carefully before approving deletion.",
            },
            "recursive": {"type": "boolean", "description": "Recursively remove directories. Default: false."},
            "dry_run": {"type": "boolean", "description": "Preview only. Default: true."},
            "confirm": {"type": "boolean", "description": "Must be true together with dry_run=false to delete."},
            "timeout": {"type": "number", "description": "Local timeout in seconds."},
            "port": {"type": "integer", "minimum": 1, "maximum": 65535},
            "identity_file": {"type": "string"},
            "known_hosts_file": {"type": "string"},
            "strict_host_key_checking": _STRICT_HOST_KEY_CHECKING_SCHEMA,
            "extra_ssh_args": _EXTRA_SSH_ARGS_SCHEMA,
        },
    },
}

_admin_session_start_tool = _clone_tool_definition(
    "ssh_start_session",
    "ssh_admin_session_start",
    "Start an explicitly privileged, approval-gated interactive SSH session. Each input call should be reviewed. This is not a sandbox; enforce privilege limits with remote sudoers.",
)
_admin_session_ensure_tool = _clone_tool_definition(
    "ssh_ensure_session",
    "ssh_admin_session_ensure",
    "Reuse or start an explicitly privileged interactive session. Reused sessions return buffered output without waiting. Review each input call; approve this tool only when the admin session is needed.",
)
_admin_session_write_tool = _clone_tool_definition(
    "ssh_write_session",
    "ssh_admin_session_write",
    "Write input to an explicitly privileged SSH session. Each call should be reviewed; the session can run arbitrary commands.",
)
_admin_session_write_tool["description"] += (
    " Send one reviewed command or response per call."
)
_admin_sudo_write_tool: dict[str, Any] = {
    "name": "ssh_admin_sudo_session_write",
    "description": (
        "Run one approved sudo executable in an admin PTY session. It uses sudo -n and "
        "Review the complete command before approving it. This is a distinct tool "
        "so the MCP client can request a separate approval."
    ),
    "inputSchema": {
        "type": "object",
        "additionalProperties": False,
        "required": ["session_id", "command"],
        "properties": {
            "session_id": {"type": "string"},
            "command": {"type": "string", "description": "One absolute executable path and its arguments; review the complete command before approving it."},
            "wait_seconds": {"type": "number", "minimum": 0, "description": "Maximum output wait, default 1 second. Returns early after a brief quiet interval, not necessarily command completion."},
            "max_output_chars": {"type": "integer", "minimum": 1},
        },
    },
}
_admin_session_key_tool: dict[str, Any] = {
    "name": "ssh_admin_session_key",
    "description": (
        "Send one named terminal key to an admin PTY session. Supported keys are enter, tab, escape, "
        "arrows, ctrl-c/d/z, q, y, and n; arbitrary text is not accepted."
    ),
    "inputSchema": {
        "type": "object",
        "additionalProperties": False,
        "required": ["session_id", "key"],
        "properties": {
            "session_id": {"type": "string"},
            "key": {
                "type": "string",
                "enum": ["enter", "tab", "escape", "up", "down", "right", "left", "ctrl-c", "ctrl-d", "ctrl-z", "q", "y", "n"],
            },
            "wait_seconds": {"type": "number", "minimum": 0},
            "max_output_chars": {"type": "integer", "minimum": 1},
        },
    },
}
TOOL_DEFINITIONS.extend(
    [
        _sudo_exec_tool,
        _delete_tool,
        _admin_session_start_tool,
        _admin_session_ensure_tool,
        _admin_session_write_tool,
        _admin_sudo_write_tool,
        _admin_session_key_tool,
    ]
)


class McpServer:
    def __init__(
        self,
        *,
        stdin: Any | None = None,
        stdout: Any | None = None,
        tool_service: SshToolService | None = None,
    ) -> None:
        self._stdin = stdin or sys.stdin.buffer
        self._stdout = stdout or sys.stdout.buffer
        self._tool_service = tool_service or SshToolService()
        self._initialized = False
        self._output_lock = threading.Lock()
        self._tool_handlers: dict[str, Callable[[Mapping[str, Any]], dict[str, Any]]] = {
            "ssh_exec": self._tool_service.ssh_exec,
            "ssh_sudo_exec": self._tool_service.ssh_sudo_exec,
            "ssh_delete": self._tool_service.ssh_delete,
            "ssh_scp": self._tool_service.ssh_scp,
            "ssh_sync": self._tool_service.ssh_sync,
            "ssh_view": self._tool_service.ssh_view,
            "ssh_create": self._tool_service.ssh_create,
            "ssh_edit": self._tool_service.ssh_edit,
            "ssh_grep": self._tool_service.ssh_grep,
            "ssh_glob": self._tool_service.ssh_glob,
            "ssh_start_session": self._tool_service.ssh_start_session,
            "ssh_admin_session_start": self._tool_service.ssh_admin_session_start,
            "ssh_admin_session_ensure": self._tool_service.ssh_admin_session_ensure,
            "ssh_ensure_session": self._tool_service.ssh_ensure_session,
            "ssh_read_session": self._tool_service.ssh_read_session,
            "ssh_write_session": self._tool_service.ssh_write_session,
            "ssh_admin_session_write": self._tool_service.ssh_admin_session_write,
            "ssh_admin_sudo_session_write": self._tool_service.ssh_admin_sudo_session_write,
            "ssh_admin_session_key": self._tool_service.ssh_admin_session_key,
            "ssh_stop_session": self._tool_service.ssh_stop_session,
            "ssh_list_sessions": self._tool_service.ssh_list_sessions,
            "ssh_forward": self._tool_service.ssh_forward,
            "ssh_list_forwards": self._tool_service.ssh_list_forwards,
            "ssh_stop_forward": self._tool_service.ssh_stop_forward,
        }

    def serve(self) -> None:
        try:
            # Lifecycle and cheap metadata requests stay on the reader thread.
            # Tool calls can complete out of order, correlated by JSON-RPC id.
            # Drain accepted work before closing sessions/forwards on EOF.
            with ThreadPoolExecutor(max_workers=8, thread_name_prefix="mcp-tool") as workers:
                while True:
                    line = self._stdin.readline()
                    if not line:
                        break
                    if not line.strip():
                        continue
                    try:
                        message = json.loads(line)
                    except json.JSONDecodeError as exc:
                        self._write_message(
                            _jsonrpc_error(
                                JSONRPC_PARSE_ERROR,
                                f"Invalid JSON: {exc.msg}",
                                request_id=None,
                            )
                        )
                        continue
                    params = message.get("params") if isinstance(message, dict) else None
                    is_tool_call = (
                        isinstance(message, dict)
                        and message.get("method") == "tools/call"
                        and self._initialized
                    )
                    is_listing = isinstance(params, dict) and params.get("name") in {
                        "ssh_list_sessions", "ssh_list_forwards",
                    }
                    if is_tool_call and not is_listing:
                        workers.submit(self._respond, message)
                    else:
                        self._respond(message)
        finally:
            self._tool_service.close()

    def _respond(self, message: Any) -> None:
        response = self._handle_message(message)
        if response is not None:
            self._write_message(response)

    def _handle_message(self, message: Any) -> dict[str, Any] | None:
        if not isinstance(message, dict):
            return _jsonrpc_error(
                JSONRPC_INVALID_REQUEST,
                "JSON-RPC messages must be objects.",
                request_id=None,
            )
        request_id = message.get("id")
        if message.get("jsonrpc") != "2.0":
            return _jsonrpc_error(
                JSONRPC_INVALID_REQUEST,
                "Only JSON-RPC 2.0 is supported.",
                request_id=request_id,
            )
        method = message.get("method")
        if not isinstance(method, str) or not method:
            return _jsonrpc_error(
                JSONRPC_INVALID_REQUEST,
                "Request method must be a non-empty string.",
                request_id=request_id,
            )
        params = message.get("params", {})
        is_notification = "id" not in message
        try:
            result = self._dispatch(method, params)
        except JsonRpcRequestError as exc:
            if is_notification:
                return None
            return _jsonrpc_error(exc.code, exc.message, request_id=request_id, data=exc.data)
        except Exception as exc:  # pragma: no cover - defensive fallback
            print(traceback.format_exc(), file=sys.stderr, flush=True)
            if is_notification:
                return None
            return _jsonrpc_error(
                JSONRPC_INTERNAL_ERROR,
                f"Internal server error: {exc}",
                request_id=request_id,
            )
        if is_notification:
            return None
        return {"jsonrpc": "2.0", "id": request_id, "result": result}

    def _dispatch(self, method: str, params: Any) -> dict[str, Any]:
        if method == "initialize":
            if params is None:
                params = {}
            if not isinstance(params, dict):
                raise JsonRpcRequestError(
                    JSONRPC_INVALID_PARAMS,
                    "'initialize' params must be an object.",
                )
            protocol_version = params.get("protocolVersion") or DEFAULT_PROTOCOL_VERSION
            if not isinstance(protocol_version, str) or not protocol_version:
                raise JsonRpcRequestError(
                    JSONRPC_INVALID_PARAMS,
                    "'protocolVersion' must be a non-empty string when provided.",
                )
            negotiated_version = (
                protocol_version
                if protocol_version in SUPPORTED_PROTOCOL_VERSIONS
                else DEFAULT_PROTOCOL_VERSION
            )
            self._initialized = True
            return {
                "protocolVersion": negotiated_version,
                "capabilities": SERVER_CAPABILITIES,
                "serverInfo": {"name": SERVER_NAME, "version": __version__},
            }
        if method == "notifications/initialized":
            return {}
        if method == "ping":
            return {}
        if not self._initialized:
            raise JsonRpcRequestError(
                JSONRPC_SERVER_NOT_INITIALIZED,
                "Server has not been initialized yet. Send 'initialize' first.",
            )
        if method == "tools/list":
            if params is None:
                params = {}
            if not isinstance(params, dict):
                raise JsonRpcRequestError(
                    JSONRPC_INVALID_PARAMS,
                    "'tools/list' params must be an object when provided.",
                )
            cursor = params.get("cursor")
            if cursor is not None and not isinstance(cursor, str):
                raise JsonRpcRequestError(
                    JSONRPC_INVALID_PARAMS,
                    "'tools/list.cursor' must be a string when provided.",
                )
            return {"tools": TOOL_DEFINITIONS}
        if method == "tools/call":
            return self._handle_tool_call(params)
        raise JsonRpcRequestError(
            JSONRPC_METHOD_NOT_FOUND,
            f"Unknown method '{method}'.",
        )

    def _handle_tool_call(self, params: Any) -> dict[str, Any]:
        if not isinstance(params, dict):
            raise JsonRpcRequestError(
                JSONRPC_INVALID_PARAMS,
                "'tools/call' params must be an object.",
            )
        name = params.get("name")
        if not isinstance(name, str) or not name:
            raise JsonRpcRequestError(
                JSONRPC_INVALID_PARAMS,
                "'tools/call' requires a non-empty string 'name'.",
            )
        arguments = params.get("arguments", {})
        if arguments is None:
            arguments = {}
        if not isinstance(arguments, dict):
            raise JsonRpcRequestError(
                JSONRPC_INVALID_PARAMS,
                "'tools/call.arguments' must be an object when provided.",
            )
        handler = self._tool_handlers.get(name)
        if handler is None:
            return _tool_error(f"Unknown tool '{name}'.", error_type="unknown_tool")
        try:
            return _tool_success(handler(arguments))
        except PolicyViolation as exc:
            return _tool_error(str(exc), error_type="policy_denied")
        except ValidationError as exc:
            return _tool_error(str(exc), error_type="validation_error")
        except SessionNotFoundError as exc:
            return _tool_error(str(exc), error_type="session_not_found")
        except ForwardNotFoundError as exc:
            return _tool_error(str(exc), error_type="forward_not_found")
        except RemoteFileError as exc:
            return _tool_error(str(exc), error_type="remote_file_error")
        except Exception as exc:  # pragma: no cover - defensive fallback
            print(traceback.format_exc(), file=sys.stderr, flush=True)
            return _tool_error(f"Internal tool error: {exc}", error_type="internal_error")

    def _write_message(self, message: Mapping[str, Any]) -> None:
        encoded = json.dumps(message, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        with self._output_lock:
            self._stdout.write(encoded + b"\n")
            self._stdout.flush()


class JsonRpcRequestError(Exception):
    def __init__(self, code: int, message: str, data: Mapping[str, Any] | None = None) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.data = data
