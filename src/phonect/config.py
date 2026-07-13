"""
phonect.config — Configuration file management for the daemon.

Config location:  ``$XDG_CONFIG_HOME/phonect/config.toml``
Defaults:         ``~/.config/phonect/config.toml``

The daemon listens for TCP connections from the phone and advertises itself
with UDP discovery broadcasts.

Example config::

    [keys]
    private_key = "/home/user/.config/phonect/pc_private.pem"
    public_key = "/home/user/.config/phonect/trusted_device.pub"

    [logging]
    level = "INFO"
"""

from __future__ import annotations

import tomllib
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

CONFIG_DIR_NAME = "phonect"
CONFIG_FILE_NAME = "config.toml"
DEFAULT_PC_KEY_BASENAME = "pc_private"

UDP_DISCOVERY_PORT = 9875

# ---------------------------------------------------------------------------
# Config data class
# ---------------------------------------------------------------------------


@dataclass
class DaemonConfig:
    """Runtime configuration for the daemon."""

    # PC identity
    pc_name: str = field(default="")

    # Key paths
    private_key_path: Path = field(default_factory=lambda: Path("/nonexistent"))
    public_key_path: Path = field(default_factory=lambda: Path("/nonexistent"))

    # Behaviour
    unlock_on_start: bool = field(default=False)
    listen_host: str = field(default="0.0.0.0")
    listen_port: int = field(default=9876)
    poll_interval: float = field(default=0.3)
    poll_timeout: float = field(default=15.0)
    unlock_backend: str = field(default="loginctl")
    unlock_command: list[str] = field(default_factory=list)

    # Logging
    log_level: str = field(default="INFO")

    # Derived
    config_dir: Path = field(default_factory=lambda: _default_config_dir())

    @property
    def trusted_key_pem(self) -> bytes:
        """Read the trusted (mobile) public key PEM file."""
        return self.public_key_path.read_bytes()

    @property
    def pc_private_key_pem(self) -> bytes:
        """Read the PC private key PEM file."""
        return self.private_key_path.read_bytes()

    @property
    def has_pc_key(self) -> bool:
        """PC has its own private key (needed for signing challenges)."""
        return self.private_key_path.exists()

    @property
    def has_trusted_key(self) -> bool:
        """A phone public key has been paired (TOFU completed)."""
        return self.public_key_path.exists()

    @property
    def mutual_auth_ready(self) -> bool:
        """Both sides can authenticate each other."""
        return self.has_pc_key and self.has_trusted_key


# ---------------------------------------------------------------------------
# Path helpers
# ---------------------------------------------------------------------------


def _default_config_dir() -> Path:
    """Return ``$XDG_CONFIG_HOME/phonect`` or ``~/.config/phonect``."""
    xdg = os.environ.get("XDG_CONFIG_HOME")
    if xdg:
        return Path(xdg) / CONFIG_DIR_NAME
    return Path.home() / ".config" / CONFIG_DIR_NAME


def default_config_path() -> Path:
    """Return the default config file path."""
    return _default_config_dir() / CONFIG_FILE_NAME


def validate_unlock_config(config: DaemonConfig) -> None:
    """Validate the closed set of local unlock-backend settings."""
    if not isinstance(config.unlock_backend, str) or config.unlock_backend not in {"loginctl", "command"}:
        raise ValueError("daemon.unlock_backend must be 'loginctl' or 'command'")
    if not isinstance(config.unlock_command, list) or not all(isinstance(arg, str) for arg in config.unlock_command):
        raise ValueError("daemon.unlock_command must be a list of strings")
    if config.unlock_backend == "command":
        if not config.unlock_command or not config.unlock_command[0].strip():
            raise ValueError("daemon.unlock_command requires a nonblank executable for the command backend")
    elif config.unlock_command:
        raise ValueError("daemon.unlock_command must be empty for the loginctl backend")


# ---------------------------------------------------------------------------
# Config loader
# ---------------------------------------------------------------------------


def load_config(path: Optional[Path] = None) -> DaemonConfig:
    """
    Load and parse a ``phonect`` TOML config file.

    If *path* is ``None``, the default location is used
    (``~/.config/phonect/config.toml``).  Missing files return defaults.
    """

    cfg_path = path or default_config_path()

    if not cfg_path.exists():
        cfg_dir = cfg_path.parent
        return DaemonConfig(
            config_dir=cfg_dir,
            private_key_path=cfg_dir / f"{DEFAULT_PC_KEY_BASENAME}.pem",
            public_key_path=cfg_dir / "trusted_device.pub",
        )

    raw = cfg_path.read_bytes()
    data = tomllib.loads(raw.decode("utf-8"))

    base = DaemonConfig(config_dir=cfg_path.parent)

    # ── [keys] ────────────────────────────────────────────────────────
    keys = data.get("keys", {})

    pk = keys.get("public_key", "")
    if pk:
        base.public_key_path = Path(pk).expanduser()
    else:
        base.public_key_path = cfg_path.parent / "trusted_device.pub"

    privk = keys.get("private_key", "")
    if privk:
        base.private_key_path = Path(privk).expanduser()
    else:
        base.private_key_path = cfg_path.parent / f"{DEFAULT_PC_KEY_BASENAME}.pem"

    # ── [device] ──────────────────────────────────────────────────────
    device = data.get("device", {})
    base.pc_name = device.get("pc_name", base.pc_name)
    base.unlock_on_start = device.get("unlock_on_start", base.unlock_on_start)

    # ── [daemon] Wi-Fi/TCP settings ────────────────────────────────────
    daemon = data.get("daemon", {})
    base.listen_host = daemon.get("listen_host", base.listen_host)
    base.listen_port = int(daemon.get("listen_port", base.listen_port))
    base.poll_interval = float(daemon.get("poll_interval", base.poll_interval))
    base.poll_timeout = float(daemon.get("poll_timeout", base.poll_timeout))
    base.unlock_backend = daemon.get("unlock_backend", base.unlock_backend)
    base.unlock_command = daemon.get("unlock_command", base.unlock_command)
    base.pc_name = daemon.get("pc_name", base.pc_name)
    base.unlock_on_start = daemon.get("unlock_on_start", base.unlock_on_start)

    # ── [logging] ─────────────────────────────────────────────────────
    logging_ = data.get("logging", {})
    base.log_level = logging_.get("level", base.log_level)

    validate_unlock_config(base)
    return base


# ---------------------------------------------------------------------------
# Config file initialiser
# ---------------------------------------------------------------------------


def write_default_config(path: Optional[Path] = None) -> Path:
    """Write a template config file to *path* (or the default location)."""
    cfg_path = path or default_config_path()
    cfg_path.parent.mkdir(parents=True, exist_ok=True)

    template = """\
# ── phonect daemon configuration ──────────────────────────────────────────
# See https://github.com/zumuvik/phonect
#
# Wi-Fi/TCP transport: the daemon advertises over UDP and listens on TCP.

[daemon]
listen_host = "0.0.0.0"
listen_port = 9876
# Seconds between UDP discovery broadcasts during an auth window
poll_interval = 0.3
# Maximum seconds to advertise and accept one TCP auth after wake/manual/start
poll_timeout = 15.0
# Unlock active sessions with loginctl, or run one static local command argv.
unlock_backend = "loginctl"
unlock_command = []

[keys]
# Path to the PC's own private key (PEM) — generate with: phonect gen-keys
private_key = "%s/pc_private.pem"
# Path to the trusted mobile device public key (PEM) — auto-populated by
# Trust-On-First-Use on the first successful connection
public_key = "%s/trusted_device.pub"

[device]
# Human-friendly PC name shown during pairing
pc_name = "my-laptop"
# Run one auth cycle when the daemon starts
unlock_on_start = false

[logging]
level = "INFO"
""" % (cfg_path.parent, cfg_path.parent)

    cfg_path.write_text(template)
    return cfg_path
