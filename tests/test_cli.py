"""CLI and package metadata regression tests."""

from __future__ import annotations

import argparse
import importlib
import importlib.util
import sys
import tomllib
from pathlib import Path

import pytest

from phonect import cli


def test_parser_rejects_removed_tui_command():
    with pytest.raises(SystemExit) as exc_info:
        cli.build_parser().parse_args(["tui"])

    assert exc_info.value.code == 2


def test_parser_accepts_retained_documented_commands():
    parser = cli.build_parser()

    gen_keys = parser.parse_args([
        "gen-keys", "--private-key", "private.pem", "--public-key", "public.pem",
    ])
    assert (gen_keys.private_key, gen_keys.public_key) == ("private.pem", "public.pem")
    assert gen_keys.func is cli.cmd_gen_keys

    server = parser.parse_args(["server", "trusted.pem", "--port", "9876", "--timeout", "5"])
    assert (server.public_key, server.port, server.timeout) == ("trusted.pem", 9876, 5.0)
    assert server.func is cli.cmd_server

    client = parser.parse_args([
        "client", "phone.pem", "192.0.2.1", "9876", "--device-name", "phone", "--timeout", "5",
    ])
    assert (client.private_key, client.pc_ip, client.pc_port, client.device_name, client.timeout) == (
        "phone.pem", "192.0.2.1", 9876, "phone", 5.0,
    )
    assert client.func is cli.cmd_client

    daemon = parser.parse_args(["daemon", "--config", "config.toml", "--foreground"])
    assert (daemon.config, daemon.foreground) == ("config.toml", True)
    assert daemon.func is cli.cmd_daemon

    init_config = parser.parse_args(["init-config", "--path", "config.toml"])
    assert init_config.path == "config.toml"
    assert init_config.func is cli.cmd_init_config

    pair = parser.parse_args(["pair", "--config", "config.toml"])
    assert pair.config == "config.toml"
    assert pair.func is cli.cmd_pair


def test_cmd_pair_preserves_deprecated_no_op_output(capsys):
    cli.cmd_pair(argparse.Namespace(config="config.toml"))

    assert capsys.readouterr().out.splitlines() == [
        "Manual pairing is disabled. Start 'phonect daemon' and connect from the phone on Wi-Fi/TCP.",
        "The first valid phone key will be pinned, but that first connection will not unlock.",
    ]


def test_cli_import_does_not_require_removed_tui_dependencies():
    sys.modules.pop("phonect.cli", None)
    try:
        imported = importlib.import_module("phonect.cli")
        assert imported.build_parser().prog == "phonect"
        assert importlib.util.find_spec("phonect.tui") is None
        with pytest.raises(ModuleNotFoundError):
            importlib.import_module("phonect.tui")
    finally:
        sys.modules.pop("phonect.cli", None)
        importlib.import_module("phonect.cli")


def test_production_metadata_excludes_removed_tui_dependencies():
    with (Path(__file__).parents[1] / "pyproject.toml").open("rb") as metadata_file:
        project = tomllib.load(metadata_file)["project"]

    assert project["dependencies"] == ["cryptography>=41.0.0", "dbus-next>=0.2.3"]
    assert project.get("optional-dependencies") == {
        "dev": ["pytest>=8.0", "pytest-asyncio>=0.24"],
    }
