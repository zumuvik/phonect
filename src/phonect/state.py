"""
phonect.state — Legacy mutable device state persistence (``state.json``).

The current Wi-Fi/TCP daemon does not use this file for pairing or transport
configuration. It is kept as a small compatibility helper for old state files.

Schema
======

.. code-block:: json

    {
      "device_name": "Pixel 7",
      "fingerprint": "a1b2c3d4e5..."
    }
"""

from __future__ import annotations

import json
import os
import logging
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Optional

LOG = logging.getLogger("phonect.state")

STATE_FILE_NAME = "state.json"


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass
class DeviceState:
    """Legacy persistent metadata for a paired mobile device."""

    device_name: str = ""
    fingerprint: str = ""


# ---------------------------------------------------------------------------
# Path helpers
# ---------------------------------------------------------------------------


def state_dir() -> Path:
    """Return the phonect config directory (``~/.config/phonect``)."""
    xdg = os.environ.get("XDG_CONFIG_HOME")
    if xdg:
        return Path(xdg) / "phonect"
    return Path.home() / ".config" / "phonect"


def state_path() -> Path:
    """Return the full path to the state JSON file."""
    return state_dir() / STATE_FILE_NAME


# ---------------------------------------------------------------------------
# Load / save
# ---------------------------------------------------------------------------


def load_state(path: Optional[Path] = None) -> DeviceState:
    """
    Load device state from *path* (default: ``state_path()``).

    Returns an empty ``DeviceState`` if the file is missing or unparseable.
    """
    p = path or state_path()
    if not p.exists():
        return DeviceState()

    try:
        raw = p.read_text()
        data = json.loads(raw)
        return DeviceState(
            device_name=data.get("device_name", ""),
            fingerprint=data.get("fingerprint", ""),
        )
    except (json.JSONDecodeError, OSError, ValueError) as exc:
        LOG.warning("Failed to load state from %s: %s — using defaults", p, exc)
        return DeviceState()


def save_state(state: DeviceState, path: Optional[Path] = None) -> Path:
    """
    Persist *state* as JSON to *path* (default: ``state_path()``).

    Returns the path written.
    """
    p = path or state_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    data = asdict(state)
    p.write_text(json.dumps(data, indent=2) + "\n")
    LOG.info("Device state saved to %s", p)
    return p
