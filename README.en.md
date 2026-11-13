# ssh-mcp-policy

[简体中文](README.md) | English

A policy-focused fork of [slepp/ssh-mcp](https://github.com/slepp/ssh-mcp). It keeps the upstream SSH, file, session, and forwarding tools, and adds separate approval points for sudo and deletion.

## Added features

- `ssh_exec`, interactive sessions, sudo, and sync no longer hard-block commands based on their content. The MCP client should ask before each call and show the complete command and paths.
- `ssh_sudo_exec` uses `sudo -n`; no sudo password is sent through MCP. Include the full executable path, such as `/usr/bin/systemctl`, not just `systemctl`.
- `ssh_delete` previews by default; actual deletion still requires both `dry_run=false` and `confirm=true`. `ssh_sync` executes rsync deletion when `delete=true`.
- Admin sessions, session sudo, and fixed terminal keys use separate tools.

These policies are guardrails, not a shell sandbox. SSH commands retain the remote account's permissions. Use a restricted account and matching server-side `sudoers` rules.

## Install and run

The server needs Python 3.10+, a POSIX shell, and local OpenSSH. Interactive sessions require a PTY. The MCP client may run elsewhere, but the server process must run in a POSIX environment that can access the SSH configuration, credentials, and network.

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -e .
```

Add a local stdio server to your MCP client: set the command to `.venv/bin/ssh-mcp-policy` and leave arguments empty. See the [upstream README](https://github.com/slepp/ssh-mcp) for the upstream tools' parameter reference.

Prefer `ssh_exec` for short commands. Session `wait_seconds` is an upper bound: new output returns after a brief quiet interval, which does not mean the command has finished; read again for later output. Reusing a session returns buffered output immediately. Independent tool calls run concurrently and replies match request IDs. Reads and writes on one session are serialized; session listings and ping are not queued behind long tool calls. `ssh_edit` can edit different files concurrently; edits to the same SSH target, port, and path are serialized to prevent lost updates.

## Security defaults

```json
{}
```

Configure your MCP client to ask (`ask`) before every `ssh-mcp` tool call. Approval allows that call only; it does not create a one-time remote root privilege. Remote `NOPASSWD: ALL` still lets the SSH account use passwordless sudo outside MCP. The policy validates argument structure but does not use a command blacklist in place of user approval.

## Tests

```bash
python3 -m pip install -e ".[test]" build
python3 -m unittest discover -s tests -v
python3 -m compileall -q src
python3 -m build
```

MIT licensed; see [LICENSE](LICENSE) and [NOTICE](NOTICE).
