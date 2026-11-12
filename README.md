# ssh-mcp-policy

简体中文 | [English](README.en.md)

[slepp/ssh-mcp](https://github.com/slepp/ssh-mcp) 的策略增强 fork。保留上游 SSH、文件、会话和端口转发能力，并为 sudo 与删除增加独立工具和审批边界。

## 新增功能

- `ssh_exec`、交互会话、sudo 和同步操作不再按危险命令内容硬拒绝；MCP 客户端应在每次工具调用前询问，并展示完整命令和路径。
- `ssh_sudo_exec` 使用 `sudo -n`，不通过 MCP 传递密码。命令要写完整程序位置，例如 `/usr/bin/systemctl`，不能只写 `systemctl`。
- `ssh_delete` 默认只预览；实际删除仍必须同时设置 `dry_run=false` 和 `confirm=true`。`ssh_sync` 的 `delete=true` 会执行 rsync 删除。

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
{}
```

MCP 客户端必须把 `ssh-mcp` 工具权限设为每次询问（`ask`）。批准某次调用只代表允许本次请求，不会建立一次性远端 root 权限；远端 `NOPASSWD: ALL` 仍会让 SSH 账号在 MCP 之外也能免密 sudo。策略会检查参数格式，但不再用命令黑名单替代用户审批。

## 测试

```bash
python3 -m pip install -e ".[test]" build
python3 -m unittest discover -s tests -v
python3 -m compileall -q src
python3 -m build
```

MIT 许可证，见 [LICENSE](LICENSE) 和 [NOTICE](NOTICE)。
