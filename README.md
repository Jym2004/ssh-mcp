# ssh-mcp-policy

简体中文 | [English](README.en.md)

[slepp/ssh-mcp](https://github.com/slepp/ssh-mcp) 的策略增强 fork。保留上游 SSH、文件、会话和端口转发能力，并为 sudo 与删除增加独立工具和审批边界。

## 新增功能

- `ssh_exec` 和普通会话拦截常见 sudo、删除命令。
- `ssh_sudo_exec` 只运行通过本地策略检查的命令，使用 `sudo -n`，不通过 MCP 传递密码；命令要写完整程序位置，例如 `/usr/bin/systemctl`，不能只写 `systemctl`。
- `ssh_delete` 默认只预览；实际删除必须同时设置 `dry_run=false` 和 `confirm=true`，且路径必须位于配置的删除根目录内。
- 管理会话、会话 sudo 和固定终端按键使用独立工具；`ssh_sync` 禁止 rsync `--delete`。

这些策略是防护栏，不是 shell 沙箱。SSH 账号仍拥有其远程权限；请使用受限账号，并在服务器端配置匹配的 `sudoers` 规则。

## 安装与运行

服务运行环境需要 Python 3.10+、POSIX shell 和本地 OpenSSH；交互会话需要 PTY。MCP 客户端可以运行在另一台机器上，但服务进程必须运行在能访问 SSH 配置、凭据和网络的 POSIX 环境中。

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -e .
```

在 MCP 客户端添加本地 stdio 服务：命令指向 `.venv/bin/ssh-mcp-policy`，参数留空。上游工具参数说明见[上游 README](https://github.com/slepp/ssh-mcp)。

## 安全默认值

```json
{
  "delete_roots": ["~/projects/", "~/scratch/"],
  "sudo_commands": []
}
```

配置文件默认位于 `~/.config/ssh-mcp-policy/policy.json`。sudo 白名单默认留空。若明确要允许 `ssh_sudo_exec` 执行任意单条 sudo 命令，可设置 `"sudo_commands": ["*"]`；仍要求写完整程序位置，例如 `/usr/bin/systemctl`，并拒绝 shell 拼接和识别到的破坏性命令。此选项需远端账号已配置 `NOPASSWD: ALL`，而且远端账号在 MCP 之外也会拥有该权限。MCP 客户端应在每次调用工具前询问批准，不要配置宽泛的自动允许规则。

## 测试

```bash
python3 -m pip install -e ".[test]" build
python3 -m unittest discover -s tests -v
python3 -m compileall -q src
python3 -m build
```

MIT 许可证，见 [LICENSE](LICENSE) 和 [NOTICE](NOTICE)。
