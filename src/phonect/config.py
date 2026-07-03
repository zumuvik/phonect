"""
phonect.config — Configuration file management for the daemon.

Config location:  ``$XDG_CONFIG_HOME/phonect/config.toml``
Defaults:         ``~/.config/phonect/config.toml``

The daemon uses Bluetooth RFCOMM to connect to the phone directly,
bypassing Wi-Fi AP isolation issues.

Example config::

    [keys]
    private_key = "/home/user/.config/phonect/pc_private.pem"
    public_key = "/home/user/.config/phonect/trusted_device.pub"

    [device]
    bluetooth_mac = "AA:BB:CC:DD:EE:FF"

    [logging]
    level = "INFO"
"""

from __future__ import annotations

import re
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

# Bluetooth RFCOMM channel used for phonect
BLUETOOTH_RFCOMM_CHANNEL = 1

# UUID used by the Android BT server for phonect connections
SERVICE_UUID = "fa87c0d0-afac-11de-8a39-0800200c9a66"

# Regex for MAC address validation
_MAC_RE = re.compile(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$")


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

    # Bluetooth device address (phone)
    bluetooth_mac: str = field(default="")

    # Behaviour
    unlock_on_start: bool = field(default=False)

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


# ---------------------------------------------------------------------------
# Config loader
# ---------------------------------------------------------------------------


def validate_mac(mac: str) -> bool:
    """Check if *mac* is a valid ``XX:XX:XX:XX:XX:XX`` address."""
    return bool(_MAC_RE.match(mac))


def load_config(path: Optional[Path] = None) -> DaemonConfig:
    """
    Load and parse a ``phonect`` TOML config file.

    If *path* is ``None``, the default location is used
    (``~/.config/phonect/config.toml``).  Missing files return defaults.
    """

    cfg_path = path or default_config_path()

    if not cfg_path.exists():
        return DaemonConfig()

    raw = cfg_path.read_bytes()
    data = tomllib.loads(raw.decode("utf-8"))

    base = DaemonConfig(config_dir=cfg_path.parent)

    # ── [keys] ────────────────────────────────────────────────────────
    keys = data.get("keys", {})

    pk = keys.get("public_key", "")
    if pk:
        base.public_key_path = Path(pk).expanduser()
    else:
        fallback = cfg_path.parent / "trusted_device.pub"
        if fallback.exists():
            base.public_key_path = fallback

    privk = keys.get("private_key", "")
    if privk:
        base.private_key_path = Path(privk).expanduser()
    else:
        fallback_priv = cfg_path.parent / f"{DEFAULT_PC_KEY_BASENAME}.pem"
        if fallback_priv.exists():
            base.private_key_path = fallback_priv

    # ── [device] ──────────────────────────────────────────────────────
    device = data.get("device", {})
    bt_mac = device.get("bluetooth_mac", "")
    if bt_mac and validate_mac(bt_mac):
        base.bluetooth_mac = bt_mac

    base.pc_name = device.get("pc_name", base.pc_name)
    base.unlock_on_start = device.get("unlock_on_start", base.unlock_on_start)

    # ── [logging] ─────────────────────────────────────────────────────
    logging_ = data.get("logging", {})
    base.log_level = logging_.get("level", base.log_level)

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
# Bluetooth RFCOMM transport: the daemon connects to the phone directly
# via Bluetooth (no Wi-Fi needed).

[keys]
# Path to the PC's own private key (PEM) — generate with: phonect gen-keys
private_key = "%s/pc_private.pem"
# Path to the trusted mobile device public key (PEM) — auto-populated by
# Trust-On-First-Use on the first successful connection
public_key = "%s/trusted_device.pub"

[device]
# Bluetooth MAC address of the phone (format: XX:XX:XX:XX:XX:XX)
# The phone must be paired at the OS level before running the daemon.
bluetooth_mac = ""
# Human-friendly PC name shown during pairing
pc_name = "my-laptop"
# Run one auth cycle when the daemon starts
unlock_on_start = false

[logging]
level = "INFO"
""" % (cfg_path.parent, cfg_path.parent)

    cfg_path.write_text(template)
    return cfg_path
