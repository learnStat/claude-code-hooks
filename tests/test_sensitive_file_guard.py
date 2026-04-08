import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import unittest
from sensitive_file_guard import is_sensitive_file, is_sensitive_bash_command, is_env_dump_command, references_secret_var, should_block


class TestIsSensitiveFile(unittest.TestCase):

    def test_blocks_dotenv(self):
        self.assertTrue(is_sensitive_file(".env"))

    def test_blocks_dotenv_with_suffix(self):
        self.assertTrue(is_sensitive_file(".env.production"))

    def test_blocks_dotenv_in_path(self):
        self.assertTrue(is_sensitive_file("/some/path/.env"))

    def test_blocks_pem(self):
        self.assertTrue(is_sensitive_file("server.pem"))

    def test_blocks_private_key(self):
        self.assertTrue(is_sensitive_file("id_rsa"))

    def test_blocks_credentials_json(self):
        self.assertTrue(is_sensitive_file("credentials.json"))

    def test_allows_dotenv_example(self):
        self.assertFalse(is_sensitive_file(".env.example"))

    def test_allows_normal_file(self):
        self.assertFalse(is_sensitive_file("main.py"))

    def test_allows_envrc(self):
        self.assertFalse(is_sensitive_file(".envrc"))


class TestIsSensitiveBashCommand(unittest.TestCase):

    def test_blocks_cat_dotenv(self):
        self.assertTrue(is_sensitive_bash_command("cat .env"))

    def test_blocks_cat_dotenv_in_path(self):
        self.assertTrue(is_sensitive_bash_command("cat /path/to/.env"))

    def test_blocks_cat_dotenv_with_suffix(self):
        self.assertTrue(is_sensitive_bash_command("cat .env.production"))

    def test_blocks_grep_dotenv(self):
        self.assertTrue(is_sensitive_bash_command("grep SECRET .env"))

    def test_allows_dotenv_example(self):
        self.assertFalse(is_sensitive_bash_command("cat .env.example"))

    def test_allows_envrc(self):
        self.assertFalse(is_sensitive_bash_command("cat .envrc"))

    def test_allows_non_read_command(self):
        self.assertFalse(is_sensitive_bash_command("echo .env"))

    def test_allows_empty_command(self):
        self.assertFalse(is_sensitive_bash_command(""))


class TestIsEnvDumpCommand(unittest.TestCase):

    def test_blocks_env_piped_to_grep(self):
        self.assertTrue(is_env_dump_command("env | grep ANTHROPIC"))

    def test_blocks_bare_env(self):
        self.assertTrue(is_env_dump_command("env"))

    def test_blocks_bare_printenv(self):
        self.assertTrue(is_env_dump_command("printenv"))

    def test_blocks_bare_export(self):
        self.assertTrue(is_env_dump_command("export"))

    def test_allows_env_with_var_assignment_and_command(self):
        self.assertFalse(is_env_dump_command("env VAR=value some_command"))

    def test_allows_export_with_assignment(self):
        self.assertFalse(is_env_dump_command("export MY_VAR=hello"))


class TestReferencesSecretVar(unittest.TestCase):

    def test_blocks_echo_secret_var(self):
        self.assertTrue(references_secret_var("echo $ANTHROPIC_API_KEY"))

    def test_blocks_printenv_secret_var(self):
        self.assertTrue(references_secret_var("printenv ANTHROPIC_API_KEY"))

    def test_allows_safe_command(self):
        self.assertFalse(references_secret_var("env VAR=value some_command"))

    def test_allows_export_assignment(self):
        self.assertFalse(references_secret_var("export MY_VAR=hello"))


class TestShouldBlock(unittest.TestCase):

    def test_blocks_read_sensitive_file(self):
        blocked, target = should_block({"tool_name": "Read", "tool_input": {"file_path": ".env"}})
        self.assertTrue(blocked)
        self.assertEqual(target, ".env")

    def test_blocks_edit_sensitive_file(self):
        blocked, _ = should_block({"tool_name": "Edit", "tool_input": {"file_path": "id_rsa"}})
        self.assertTrue(blocked)

    def test_blocks_write_sensitive_file(self):
        blocked, _ = should_block({"tool_name": "Write", "tool_input": {"file_path": "secrets.json"}})
        self.assertTrue(blocked)

    def test_blocks_bash_cat_dotenv(self):
        blocked, target = should_block({"tool_name": "Bash", "tool_input": {"command": "cat .env"}})
        self.assertTrue(blocked)
        self.assertEqual(target, "cat .env")

    def test_allows_read_normal_file(self):
        blocked, _ = should_block({"tool_name": "Read", "tool_input": {"file_path": "main.py"}})
        self.assertFalse(blocked)

    def test_allows_bash_safe_command(self):
        blocked, _ = should_block({"tool_name": "Bash", "tool_input": {"command": "cat .env.example"}})
        self.assertFalse(blocked)

    def test_allows_unknown_tool(self):
        blocked, _ = should_block({"tool_name": "MultiEdit", "tool_input": {}})
        self.assertFalse(blocked)

    def test_allows_missing_tool_input(self):
        blocked, _ = should_block({"tool_name": "Read"})
        self.assertFalse(blocked)


if __name__ == "__main__":
    unittest.main()
