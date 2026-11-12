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

    def test_exec_policy_separates_sudo_and_delete_tools(self) -> None:
        policy = Policy()
        with self.assertRaisesRegex(PolicyViolation, "ssh_sudo_exec"):
            policy.check_exec("sudo apt-get update")
        with self.assertRaisesRegex(PolicyViolation, "ssh_delete"):
            policy.check_exec("rm -rf ~/cache")
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
        with self.assertRaisesRegex(PolicyViolation, "not allowed"):
            policy.authorize_sudo_exec("/usr/bin/apt-get autoremove -y")
        with self.assertRaisesRegex(PolicyViolation, "shell operators"):
            policy.authorize_sudo_exec("/usr/bin/apt-get update && /usr/bin/apt-get install x")
        with self.assertRaisesRegex(PolicyViolation, "absolute path"):
            policy.authorize_sudo_exec("apt-get update")

    def test_sudo_exec_wildcard_allows_any_single_absolute_command(self) -> None:
        policy = Policy(sudo_allowed_commands=["*"])
        self.assertEqual(policy.authorize_sudo_exec("/usr/bin/systemctl restart example.service"), [
            "/usr/bin/systemctl", "restart", "example.service"
        ])
        with self.assertRaisesRegex(PolicyViolation, "absolute path"):
            policy.authorize_sudo_exec("systemctl restart example.service")
        with self.assertRaisesRegex(PolicyViolation, "shell operators"):
            policy.authorize_sudo_exec("/usr/bin/systemctl restart x && /usr/bin/id")
        with self.assertRaisesRegex(PolicyViolation, "destructive command"):
            policy.authorize_sudo_exec("/usr/bin/rm -rf /tmp/example")

    def test_sudo_wildcard_must_be_the_only_allowlist_entry(self) -> None:
        with self.assertRaisesRegex(ValueError, "must be the only"):
            Policy(sudo_allowed_commands=["*", "/usr/bin/id"])

    def test_normal_session_blocks_privilege_and_delete_commands(self) -> None:
        policy = Policy()
        for command in ("sudo apt-get update\n", "rm -rf ~/cache\n", "find /tmp -delete\n"):
            with self.subTest(command=command), self.assertRaises(PolicyViolation):
                policy.check_session_input(command, mode="safe")
        policy.check_session_input("python train.py\n", mode="safe")

    def test_admin_session_routes_sudo_and_delete_to_separate_tools(self) -> None:
        policy = Policy()
        with self.assertRaisesRegex(PolicyViolation, "ssh_admin_sudo_session_write"):
            policy.check_session_input("sudo apt-get update\n", mode="admin")
        with self.assertRaisesRegex(PolicyViolation, "ssh_delete"):
            policy.check_session_input("sudo rm -rf ~/cache\n", mode="admin")
        with self.assertRaisesRegex(PolicyViolation, "shell chaining"):
            policy.check_session_input("sudo apt-get update && sudo apt-get install -y x\n", mode="admin")

    def test_guarded_session_requires_complete_single_line_input(self) -> None:
        policy = Policy()
        with self.assertRaisesRegex(PolicyViolation, "newline-terminated"):
            policy.check_session_input("su", mode="safe")
        with self.assertRaisesRegex(PolicyViolation, "one command"):
            policy.check_session_input("pwd\nls\n", mode="safe")
        policy.check_session_input("y\n", mode="admin")

    def test_admin_session_sudo_is_only_allowed_through_the_sudo_tool(self) -> None:
        policy = Policy(sudo_allowed_commands=["/usr/bin/apt-get install"])
        with self.assertRaisesRegex(PolicyViolation, "ssh_admin_sudo_session_write"):
            policy.check_session_input("sudo /usr/bin/apt-get install -y python3-dev\n", mode="admin")
        self.assertEqual(
            policy.authorize_sudo_exec("/usr/bin/apt-get install -y python3-dev"),
            ["/usr/bin/apt-get", "install", "-y", "python3-dev"],
        )

    def test_delete_roots_require_literal_non_root_paths(self) -> None:
        policy = Policy()
        for path in ("/", "/etc/passwd", "/home/example", "~/", "~/project/*", "../etc/passwd", "relative/path"):
            with self.subTest(path=path), self.assertRaises(PolicyViolation):
                policy.check_delete_paths([path])
        policy.check_delete_paths(["~/projects/cache", "/data/old-run"])

    def test_delete_command_quotes_paths_and_uses_option_terminator(self) -> None:
        command = build_delete_command(["~/project/my data", "/data/old-run"], recursive=True)
        self.assertEqual(command, "rm -r -- \"$HOME\"'/project/my data' /data/old-run")


if __name__ == "__main__":
    unittest.main()
