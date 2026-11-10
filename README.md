# ssh-mcp-policy

简体中文 | [English](README.en.md)

这是 [slepp/ssh-mcp](https://github.com/slepp/ssh-mcp) 的策略增强 fork：保留原有 SSH、文件、会话和端口转发工具，另外将高风险操作拆成独立工具并要求单独审批。

## 本 fork 的调整

- `ssh_exec` 和普通会话会拦截常见 sudo、删除命令。
- `ssh_sudo_exec` 只运行显式白名单中的绝对路径命令，使用 `sudo -n`，不会通过 MCP 传 sudo 密码。
- `ssh_delete` 默认只预览；实际删除必须同时设置 `dry_run=false` 和 `confirm=true`，并受配置删除根目录约束。
- 管理会话、会话 sudo 和固定终端按键分别提供工具，便于 MCP 客户端逐项询问。
- `ssh_sync` 禁止 rsync 的 `--delete`，删除请走独立的 `ssh_delete` 工具。

这些策略是防护栏，不是 shell 沙箱。SSH 账号仍有它自身的远程权限；应使用受限账号，并在服务器端配置匹配的 `sudoers` 规则。

## 环境要求

- Python 3.10+ 和 POSIX 环境；交互会话需要本地 PTY。
- 本地 OpenSSH；`ssh_sync` 需要本地和远程 `rsync`；远程搜索需要 `grep`/`find`，删除路径校验需要 `realpath`。

## 从 WSL 源码启动

安装启动器：

```bash
mkdir -p ~/.local/bin
install -m 700 /path/to/checkout/scripts/ssh-mcp-policy-openchamber ~/.local/bin/ssh-mcp-policy-openchamber
```

在本地 MCP 客户端配置中设置以下环境变量，不要把机器专属值提交到仓库：

- `SSH_MCP_POLICY_HOME`：WSL 中的源码目录。
- `SSH_MCP_WINDOWS_SSH_CONFIG`：WSL 可访问的 Windows SSH 配置路径。
- `SSH_MCP_ALIAS_REWRITES`：可选的主机别名映射，格式为逗号分隔的 `旧名=新名`。

OpenCode 命令示例（请替换占位值）：

```json
{
  "mcp": {
    "servers": {
      "ssh-mcp": {
        "type": "local",
        "command": [
          "wsl.exe", "-d", "<发行版>", "--exec", "env",
          "SSH_MCP_POLICY_HOME=/源码目录",
          "SSH_MCP_WINDOWS_SSH_CONFIG=/mnt/c/Users/<用户>/.ssh/config",
          "SSH_MCP_ALIAS_REWRITES=old-gpu=gpu-wsl",
          "/home/<用户>/.local/bin/ssh-mcp-policy-openchamber"
        ]
      }
    }
  }
}
```

启动器只复制安全的 SSH 连接指令，不复制私钥或 `IdentityFile`。首次启动时会从 `config/policy.example.json` 创建 `~/.config/ssh-mcp-policy/policy.json`。

## 安全默认值

```json
{
  "delete_roots": ["~/projects/", "~/scratch/"],
  "sudo_commands": []
}
```

sudo 白名单默认留空。启用前，应明确指定命令，并在远程 `sudoers` 中设置同等范围。OpenCode 应将 `ssh-mcp` 工具设为 `ask`，不要添加宽泛的自动允许规则。

## 测试

```bash
uv run --extra test --with pytest python -m unittest discover -s tests -v
python3 -m compileall -q src
uv run --with build python -m build
```

上游工具的完整参数说明见 [上游 README](https://github.com/slepp/ssh-mcp)。本项目采用 MIT 许可证，见 [LICENSE](LICENSE) 和 [NOTICE](NOTICE)。
