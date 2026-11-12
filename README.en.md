# ssh-mcp-policy

[简体中文](README.md) | English

A policy-focused fork of [slepp/ssh-mcp](https://github.com/slepp/ssh-mcp). It keeps the upstream SSH, file, session, and forwarding tools, and adds separate approval points for sudo and deletion.

## Added features

- `ssh_exec` and normal sessions block common sudo and destructive commands.
- `ssh_sudo_exec` runs commands that pass the local policy, using `sudo -n`; no sudo password is sent through MCP. The command must include the full executable path, such as `/usr/bin/systemctl`, not just `systemctl`.
- `ssh_delete` previews by default. Actual deletion requires both `dry_run=false` and `confirm=true`, and the path must be under a configured delete root.
- Admin sessions, session sudo, and fixed terminal keys use separate tools. `ssh_sync` rejects rsync `--delete`.

These policies are guardrails, not a shell sandbox. SSH commands retain the remote account's permissions. Use a restricted account and matching server-side `sudoers` rules.

## Install and run

The server needs Python 3.10+, a POSIX shell, and local OpenSSH. Interactive sessions require a PTY. The MCP client may run elsewhere, but the server process must run in a POSIX environment that can access the SSH configuration, credentials, and network.

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -e .
```

Add a local stdio server to your MCP client: set the command to `.venv/bin/ssh-mcp-policy` and leave arguments empty. See the [upstream README](https://github.com/slepp/ssh-mcp) for the upstream tools' parameter reference.

## Security defaults

```json
{
  "delete_roots": ["~/projects/", "~/scratch/"],
  "sudo_commands": []
}
```

The default policy file is `~/.config/ssh-mcp-policy/policy.json`. The sudo allowlist is empty by default. To allow any single sudo command through `ssh_sudo_exec`, set `"sudo_commands": ["*"]`; the full executable path is still required, such as `/usr/bin/systemctl` instead of `systemctl`, and shell chaining and detected destructive commands remain blocked. This requires remote `NOPASSWD: ALL`, which grants the SSH account the same privilege outside MCP as well. Configure your MCP client to ask before every tool call; avoid broad auto-allow rules.

## Tests

```bash
python3 -m pip install -e ".[test]" build
python3 -m unittest discover -s tests -v
python3 -m compileall -q src
python3 -m build
```

MIT licensed; see [LICENSE](LICENSE) and [NOTICE](NOTICE).
