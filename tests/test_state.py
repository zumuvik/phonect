"""
Tests for ``phonect.state`` — device state persistence.
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

from phonect.state import DeviceState, load_state, save_state


class TestDeviceState:
    def test_default_empty(self):
        """A fresh DeviceState has empty fields."""
        state = DeviceState()
        assert state.device_name == ""
        assert state.fingerprint == ""

    def test_populated(self):
        state = DeviceState(
            device_name="Pixel 7",
            fingerprint="a1b2c3d4e5",
        )
        assert state.device_name == "Pixel 7"
        assert state.fingerprint == "a1b2c3d4e5"


class TestLoadSave:
    def test_save_and_load_roundtrip(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "state.json"
            state_in = DeviceState(
                device_name="Pixel 7",
                fingerprint="a1b2c3d4e5...",
            )
            saved = save_state(state_in, path)
            assert saved == path
            assert path.exists()

            state_out = load_state(path)
            assert state_out.device_name == "Pixel 7"
            assert state_out.fingerprint == "a1b2c3d4e5..."

    def test_load_missing_file_returns_empty(self):
        path = Path("/nonexistent/state.json")
        state = load_state(path)
        assert state.device_name == ""
        assert state.fingerprint == ""

    def test_load_corrupt_file_returns_empty(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "state.json"
            path.write_text("{invalid json")
            state = load_state(path)
            assert state.device_name == ""
            assert state.fingerprint == ""

    def test_load_partial_json(self):
        """Missing fields in JSON should default to empty strings."""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "state.json"
            path.write_text(json.dumps({"device_name": "Pixel 7"}))
            state = load_state(path)
            assert state.device_name == "Pixel 7"
            assert state.fingerprint == ""

    def test_save_creates_parent_dir(self):
        with tempfile.TemporaryDirectory() as tmp:
            nested = Path(tmp) / "sub" / "dir" / "state.json"
            state = DeviceState(device_name="Pixel 7")
            saved = save_state(state, nested)
            assert saved.exists()
            assert saved.parent.exists()
