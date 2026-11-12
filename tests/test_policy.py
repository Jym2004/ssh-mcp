from __future__ import annotations

import os
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from ssh_mcp.policy import Policy, PolicyViolation, build_delete_command, destructive_reason, has_sudo


class PolicyTests(unittest.TestCase):
    def setUp(self) -> None:
        # Keep tests independent of the developer's installed policy file and
        # of any policy environment overrides.
        self._policy_env = {
            name: os.environ.get(name)
            for name in ("SSH_MCP_POLICY_CONFIG", "SSH_MCP_DELETE_ROOTS", "SSH_MCP_SUDO_COMMANDS")
        }
        os.environ["SSH_MCP_POLICY_CONFIG"] = str(
            Path(__file__).with_name("missing-policy-for-tests.json")
        )
        os.environ.pop("SSH_MCP_DELETE_ROOTS", None)
        os.environ.pop("SSH_MCP_SUDO_COMMANDS", None)

    def tearDown(self) -> None:
        for name, value in self._policy_env.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value

    def test_detects_common_privilege_escalation_forms(self) -> None:
        for command in (
            "sudo apt-get update",
            "/usr/bin/sudo -n /usr/bin/id",
            "s\"\"udo systemctl restart ssh",
            "doas id",
            "pkexec id",
            "su - root",
        ):
            with self.subTest(command=command):
                self.assertTrue(has_sudo(command))

    def test_does_not_match_sudo_as_a_substring(self) -> None:
        self.assertFalse(has_sudo("pseudo-terminal"))
        self.assertFalse(has_sudo("sudoers.d"))

    def test_detects_destructive_commands(self) -> None:
        cases = {
            "rm -rf ~/cache": "remove files",
            "find /tmp/build -type f -delete": "find -delete",
            "rsync -a --delete source/ host:/data/": "rsync --delete",
            "git clean -fdx": "git clean",
            "dd if=image of=/dev/sda": "dd overwrite",
            "mkfs.ext4 /dev/sdb": "format filesystem",
            "docker system prune -af": "docker prune",
            "kubectl delete pod worker": "kubectl delete",
            "DROP TABLE users": "SQL destructive statement",
        }
        for command, expected in cases.items():
            with self.subTest(command=command):
                self.assertEqual(destructive_reason(command), expected)

    def test_exec_policy_leaves_command_approval_to_the_mcp_client(self) -> None:
        policy = Policy()
        policy.check_exec("sudo apt-get update")
        policy.check_exec("rm -rf ~/cache")
        policy.check_exec("/usr/bin/sed -e 's/a/b/;s/c/d/' file")
        policy.check_exec("python train.py")

    def test_sudo_exec_requires_an_explicit_command_prefix(self) -> None:
        policy = Policy(sudo_allowed_commands=["/usr/bin/apt-get update", "/usr/bin/apt-get install"])
        self.assertEqual(
            policy.authorize_sudo_exec("/usr/bin/apt-get update"),
            ["/usr/bin/apt-get", "update"],
        )
        self.assertEqual(
            policy.authorize_sudo_exec("/usr/bin/apt-get install -y python3-dev"),
            ["/usr/bin/apt-get", "install", "-y", "python3-dev"],
        )
        self.assertEqual(
            policy.authorize_sudo_exec("/usr/bin/apt-get autoremove -y"),
            ["/usr/bin/apt-get", "autoremove", "-y"],
        )
        self.assertEqual(
            policy.authorize_sudo_exec("/usr/bin/sed -e 's/a/b/;s/c/d/' file"),
            ["/usr/bin/sed", "-e", "s/a/b/;s/c/d/", "file"],
        )
        with self.assertRaisesRegex(PolicyViolation, "absolute path"):
            policy.authorize_sudo_exec("apt-get update")

    def test_sudo_exec_wildcard_allows_any_single_absolute_command(self) -> None:
        policy = Policy(sudo_allowed_commands=["*"])
        self.assertEqual(policy.authorize_sudo_exec("/usr/bin/systemctl restart example.service"), [
            "/usr/bin/systemctl", "restart", "example.service"
        ])
        with self.assertRaisesRegex(PolicyViolation, "absolute path"):
            policy.authorize_sudo_exec("systemctl restart example.service")
        self.assertEqual(
            policy.authorize_sudo_exec("/usr/bin/systemctl restart x && /usr/bin/id"),
            ["/usr/bin/systemctl", "restart", "x", "&&", "/usr/bin/id"],
        )
        self.assertEqual(
            policy.authorize_sudo_exec("/usr/bin/rm -rf /tmp/example"),
            ["/usr/bin/rm", "-rf", "/tmp/example"],
        )

    def test_normal_session_allows_commands_for_per_call_approval(self) -> None:
        policy = Policy()
        for command in (
            "sudo apt-get update\n",
            "rm -rf ~/cache\n",
            "find /tmp -delete\n",
            "sed -e 's/a/b/;s/c/d/' file\n",
        ):
            with self.subTest(command=command):
                policy.check_session_input(command, mode="safe")
        policy.check_session_input("python train.py\n", mode="safe")

    def test_admin_session_allows_commands_for_per_call_approval(self) -> None:
        policy = Policy()
        policy.check_session_input("sudo apt-get update\n", mode="admin")
        policy.check_session_input("sudo rm -rf ~/cache\n", mode="admin")
        policy.check_session_input("sed -e 's/a/b/;s/c/d/' file\n", mode="admin")
        policy.check_session_input("sudo apt-get update && sudo apt-get install -y x\n", mode="admin")

    def test_guarded_session_requires_complete_single_line_input(self) -> None:
        policy = Policy()
        with self.assertRaisesRegex(PolicyViolation, "newline-terminated"):
            policy.check_session_input("su", mode="safe")
        with self.assertRaisesRegex(PolicyViolation, "one command"):
            policy.check_session_input("pwd\nls\n", mode="safe")
        policy.check_session_input("y\n", mode="admin")

    def test_admin_session_sudo_tool_parses_multi_expression_sed(self) -> None:
        policy = Policy(sudo_allowed_commands=["/usr/bin/apt-get install"])
        policy.check_session_input("sudo /usr/bin/apt-get install -y python3-dev\n", mode="admin")
        self.assertEqual(
            policy.authorize_sudo_exec("/usr/bin/sed -e 's/a/b/;s/c/d/' file"),
            ["/usr/bin/sed", "-e", "s/a/b/;s/c/d/", "file"],
        )

    def test_delete_paths_require_absolute_or_home_paths(self) -> None:
        policy = Policy()
        for path in ("", "../etc/passwd", "relative/path", "bad\npath"):
            with self.subTest(path=path), self.assertRaises(PolicyViolation):
                policy.check_delete_paths([path])
        policy.check_delete_paths(["/etc/passwd", "~/projects/cache", "/data/old-run", "/"])

    def test_delete_command_quotes_paths_and_uses_option_terminator(self) -> None:
        command = build_delete_command(["~/project/my data", "/data/old-run"], recursive=True)
        self.assertEqual(command, "rm -r -- \"$HOME\"'/project/my data' /data/old-run")


if __name__ == "__main__":
    unittest.main()
