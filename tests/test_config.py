"""Tests for key resolution (no files are written)."""

from __future__ import annotations

import unittest
from unittest import mock

from fwl import config


class ResolveKeyTests(unittest.TestCase):
    def test_explicit_key_wins(self) -> None:
        with mock.patch.dict("os.environ", {"VIRUSTOTAL_API_KEY": "env-key"}, clear=False):
            self.assertEqual(config.resolve_api_key("cli-key"), "cli-key")

    def test_environment_is_used(self) -> None:
        with mock.patch.dict("os.environ", {"VIRUSTOTAL_API_KEY": "env-key"}, clear=False):
            with mock.patch.object(config, "load_config", return_value={"api_key": "file-key"}):
                self.assertEqual(config.resolve_api_key(None), "env-key")

    def test_config_file_is_used_last(self) -> None:
        env = {name: "" for name in config.ENV_KEYS}
        with mock.patch.dict("os.environ", env, clear=False):
            with mock.patch.object(config, "load_config", return_value={"api_key": "file-key"}):
                self.assertEqual(config.resolve_api_key(None), "file-key")

    def test_missing_everywhere(self) -> None:
        env = {name: "" for name in config.ENV_KEYS}
        with mock.patch.dict("os.environ", env, clear=False):
            with mock.patch.object(config, "load_config", return_value={}):
                self.assertIsNone(config.resolve_api_key(None))

    def test_defaults_are_loaded(self) -> None:
        config_values = config.DEFAULTS
        self.assertEqual(config_values["rpm"], 4.0)
        self.assertEqual(config_values["upload_policy"], "ask")


if __name__ == "__main__":
    unittest.main()
