# ssh-mcp-policy

[简体中文](README.md) | English

A policy-focused fork of [slepp/ssh-mcp](https://github.com/slepp/ssh-mcp). It keeps the upstream SSH, file, session, and forwarding tools, while adding separate approval points for high-risk operations.

## What changed in this fork

- `ssh_exec` and normal sessions block common sudo and destructive-command patterns.
- `ssh_sudo_exec` accepts only explicitly allowlisted absolute command prefixes and uses `sudo -n`; it never sends a sudo password through MCP.
- `ssh_delete` is preview-only by default. Actual deletion requires both `dry_run=false` and `confirm=true`, and is limited by configured delete roots.
- Admin sessions, session sudo, and fixed terminal keys use separate tools so MCP clients can ask for approval individually.
- `ssh_sync` rejects rsync `--delete`; use the separately gated `ssh_delete` tool instead.

These policies are guardrails, not a shell sandbox. SSH commands still have the remote account's permissions. Use a restricted account and matching server-side `sudoers` rules.

## Requirements

- Python 3.10+ and a POSIX environment; interactive sessions require a local PTY.
- Local OpenSSH. `ssh_sync` also requires local and remote `rsync`; remote search needs `grep`/`find`, and delete validation needs `realpath`.

## Run from a WSL checkout

Install the launcher:

```bash
mkdir -p ~/.local/bin
install -m 700 /path/to/checkout/scripts/ssh-mcp-policy-openchamber ~/.local/bin/ssh-mcp-policy-openchamber
```

Set these values in your local MCP client configuration. Do not commit machine-specific values:

- `SSH_MCP_POLICY_HOME`: checkout path as seen from WSL.
- `SSH_MCP_WINDOWS_SSH_CONFIG`: Windows SSH config path as seen from WSL.
- `SSH_MCP_ALIAS_REWRITES`: optional comma-separated host mappings in `old=new` form.

OpenCode command example (replace the placeholders):

```json
{
  "mcp": {
    "servers": {
      "ssh-mcp": {
        "type": "local",
        "command": [
          "wsl.exe", "-d", "<distro>", "--exec", "env",
          "SSH_MCP_POLICY_HOME=/path/to/checkout",
          "SSH_MCP_WINDOWS_SSH_CONFIG=/mnt/c/Users/<user>/.ssh/config",
          "SSH_MCP_ALIAS_REWRITES=old-gpu=gpu-wsl",
          "/home/<user>/.local/bin/ssh-mcp-policy-openchamber"
        ]
      }
    }
  }
}
```

The launcher copies only safe SSH connection directives; it never copies private keys or `IdentityFile`. On first start, it creates `~/.config/ssh-mcp-policy/policy.json` from `config/policy.example.json`.

## Security defaults

```json
{
  "delete_roots": ["~/projects/", "~/scratch/"],
  "sudo_commands": []
}
```

The sudo allowlist is empty by default. Before enabling it, choose exact commands and apply the same scope in remote `sudoers`. Configure OpenCode to ask before using `ssh-mcp` tools; do not add broad auto-allow rules.

## Tests

```bash
uv run --extra test --with pytest python -m unittest discover -s tests -v
python3 -m compileall -q src
uv run --with build python -m build
```

For the upstream tools' full parameter reference, see the [upstream README](https://github.com/slepp/ssh-mcp). This project is MIT licensed; see [LICENSE](LICENSE) and [NOTICE](NOTICE).
