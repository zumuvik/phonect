"""
phonect.tui — Textual-based TUI for phonect pairing, status, and logs.

Requires ``textual`` and ``qrcode`` (Pillow optional, pure-Python fallback).

Screens
-------
- **Pairing Wizard**: Generate PC keys, show ASCII QR code for phone scanning
- **Status**: Daemon running status, paired device info
- **Logs**: Real-time feed from journalctl
"""

from __future__ import annotations

import asyncio
import json
import os
import socket
import subprocess
from pathlib import Path
from typing import Optional

from textual import on
from textual.app import App, ComposeResult
from textual.containers import Container, Horizontal, Vertical
from textual.screen import Screen
from textual.widgets import (
    Button,
    Footer,
    Header,
    Input,
    Label,
    ListItem,
    ListView,
    RichLog,
    Static,
    TabbedContent,
    TabPane,
)

from phonect.config import (
    DaemonConfig,
    load_config,
    default_config_path,
    write_default_config,
)
from phonect.crypto import (
    generate_key_pair,
    fingerprint_from_public_key,
    public_key_to_pem,
)
from phonect.daemon import PhonectDaemon


# ======================================================================
# Pairing token helpers
# ======================================================================

def make_pairing_token(
    pc_name: str,
    pc_ip: str,
    pc_port: int,
    pc_fingerprint: str,
    pc_public_key_pem: str,
) -> str:
    """Build a JSON token for QR-code pairing."""
    return json.dumps({
        "pc_name": pc_name,
        "pc_ip": pc_ip,
        "pc_port": pc_port,
        "pc_fingerprint": pc_fingerprint,
        "pc_public_key": pc_public_key_pem,
    }, separators=(",", ":"))


def render_ascii_qr(data: str) -> str:
    """Render a QR code as ASCII art (pure Python, no Pillow needed)."""
    import qrcode
    from qrcode.image.pil import PilImage

    qr = qrcode.QRCode(
        version=None,          # auto-detect
        error_correction=qrcode.constants.ERROR_CORRECT_M,
        box_size=2,
        border=2,
    )
    qr.add_data(data)
    qr.make(fit=True)

    # Try PIL render first (better looking), fallback to text
    try:
        img = qr.make_image(fill_color="black", back_color="white")
        # Convert matrix to ASCII
        matrix = qr.get_matrix()
        lines = []
        for row in matrix:
            line = "".join("  " if cell else "██" for cell in row)
            lines.append(line)
        return "\n".join(lines)
    except Exception:
        # Pure text fallback
        return qr.make_image().to_text(quiet_zone=2)


def discover_local_ip() -> str:
    """Heuristic: find the LAN IP by connecting to a non-routable address."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(0.5)
        s.connect(("192.168.1.1", 1))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


# ======================================================================
# Pairing Wizard Screen
# ======================================================================

class PairingScreen(Screen):
    """Pairing wizard: generate PC keys, display QR code."""

    def compose(self) -> ComposeResult:
        yield Label("Pairing Wizard", classes="title")
        yield Label("Generate a PC key pair and scan the QR code with phonect Android app.", id="pairing-hint")

        yield Label("PC Name:")
        yield Input(placeholder="my-laptop", id="pc-name")

        with Horizontal():
            yield Button("Generate PC Keys", id="btn-gen-keys", variant="primary")
            yield Button("Show QR Code", id="btn-show-qr", variant="default", disabled=True)

        yield Static("", id="key-status")
        yield Static("", id="pairing-qr", classes="qr-code")
        yield Button("Back", id="btn-back", variant="default")

    @on(Button.Pressed, "#btn-gen-keys")
    def on_gen_keys(self) -> None:
        key_status = self.query_one("#key-status", Static)

        config_dir = _default_config_dir()
        config_dir.mkdir(parents=True, exist_ok=True)

        priv_path = config_dir / "pc_private.pem"
        pub_path = config_dir / "pc_public.pem"

        # Generate fresh PC key pair
        kp = generate_key_pair()
        priv_path.write_bytes(kp.private_key_pem)
        pub_path.write_bytes(kp.public_key_pem)

        self._pc_kp = kp
        key_status.update(
            f"✓ Keys generated!\n"
            f"  Private: {priv_path} ({len(kp.private_key_pem)} bytes)\n"
            f"  Public:  {pub_path} ({len(kp.public_key_pem)} bytes)\n"
            f"  Fingerprint: {kp.public_key_fingerprint[:32]}…"
        )
        self.query_one("#btn-show-qr", Button).disabled = False

    @on(Button.Pressed, "#btn-show-qr")
    def on_show_qr(self) -> None:
        from phonect.config import _default_config_dir

        if not hasattr(self, "_pc_kp"):
            # Try loading from files
            config_dir = _default_config_dir()
            pub_path = config_dir / "pc_public.pem"
            if pub_path.exists():
                from phonect.crypto import load_public_key
                pub = load_public_key(pub_path.read_bytes())
                fp = fingerprint_from_public_key(pub)
                pub_pem = public_key_to_pem(pub)

                # Recreate KeyPair-like object
                from dataclasses import dataclass
                from phonect.crypto import KeyPair
                kp = KeyPair(
                    private_key_pem=b"",
                    public_key_pem=pub_pem.encode(),
                    public_key_fingerprint=fp,
                )
                self._pc_kp = kp
            else:
                self.query_one("#pairing-qr", Static).update(
                    "[red]No keys found. Click 'Generate PC Keys' first.[/red]"
                )
                return

        pc_name = self.query_one("#pc-name", Input).value or socket.gethostname()
        pc_ip = discover_local_ip()
        pc_port = 9876

        pairing_data = make_pairing_token(
            pc_name=pc_name,
            pc_ip=pc_ip,
            pc_port=pc_port,
            pc_fingerprint=self._pc_kp.public_key_fingerprint,
            pc_public_key_pem=self._pc_kp.public_key_pem.decode(),
        )

        qr_art = render_ascii_qr(pairing_data)

        info = (
            f"\n[b]PC Name:[/b] {pc_name}\n"
            f"[b]IP:[/b] {pc_ip}:{pc_port}\n"
            f"[b]Fingerprint:[/b] {self._pc_kp.public_key_fingerprint[:32]}…\n"
            f"\nScan this QR code with the phonect Android app:\n"
        )

        self.query_one("#pairing-qr", Static).update(info + qr_art)

    @on(Button.Pressed, "#btn-back")
    def on_back(self) -> None:
        self.app.pop_screen()


# ======================================================================
# Status Screen
# ======================================================================

class StatusScreen(Screen):
    """Display daemon status and paired devices."""

    def compose(self) -> ComposeResult:
        yield Label("Daemon Status", classes="title")
        yield Static("", id="status-config")
        yield Static("", id="status-keys")
        yield ListView(id="paired-list")
        yield Button("Refresh", id="btn-refresh", variant="default")
        yield Button("Back", id="btn-back")

    def on_mount(self) -> None:
        self.refresh_status()

    @on(Button.Pressed, "#btn-refresh")
    def refresh_status(self) -> None:
        config = load_config()

        config_status = (
            f"[b]Config:[/b] {default_config_path()}\n"
            f"[b]Mobile IP:[/b] {config.mobile_ip or '(not set)'}\n"
            f"[b]Mobile Port:[/b] {config.mobile_port}\n"
            f"[b]PC Name:[/b] {config.pc_name or socket.gethostname()}\n"
        )
        self.query_one("#status-config", Static).update(config_status)

        key_status = (
            f"[b]Mobile pubkey:[/b] {'✓' if config.public_key_path.exists() else '✗'} "
            f"{config.public_key_path}\n"
            f"[b]PC privkey:[/b]   {'✓' if config.private_key_path.exists() else '✗'} "
            f"{config.private_key_path}\n"
            f"[b]Mutual auth:[/b]  {'✓ READY' if config.mutual_auth_ready else '— not configured'}\n"
        )
        self.query_one("#status-keys", Static).update(key_status)

        # Show paired device from config
        paired_list = self.query_one("#paired-list", ListView)
        paired_list.clear()
        if config.public_key_path.exists():
            try:
                from phonect.crypto import load_public_key, fingerprint_from_public_key
                pub = load_public_key(config.public_key_path.read_bytes())
                fp = fingerprint_from_public_key(pub)
                paired_list.append(ListItem(Label(
                    f"IP: {config.mobile_ip}:{config.mobile_port}  "
                    f"FP: {fp[:16]}…"
                )))
            except Exception:
                paired_list.append(ListItem(Label("(error reading key)")))
        else:
            paired_list.append(ListItem(Label("No devices paired yet")))

    @on(Button.Pressed, "#btn-back")
    def on_back(self) -> None:
        self.app.pop_screen()


# ======================================================================
# Logs Screen
# ======================================================================

class LogsScreen(Screen):
    """Real-time journalctl log viewer for phonect daemon."""

    def compose(self) -> ComposeResult:
        yield Label("Daemon Logs", classes="title")
        yield RichLog(id="log-view", highlight=True, markup=True, max_lines=500)
        yield Horizontal(
            Button("Pause", id="btn-pause"),
            Button("Clear", id="btn-clear"),
            Button("Back", id="btn-back"),
        )

    def on_mount(self) -> None:
        self._log_view = self.query_one("#log-view", RichLog)
        self._paused = False
        self._tail_task = asyncio.create_task(self._tail_journalctl())

    async def _tail_journalctl(self) -> None:
        """Tail journalctl for phonect daemon logs."""
        try:
            proc = await asyncio.create_subprocess_exec(
                "journalctl",
                "--user" if _is_user_service() else "--system",
                "--unit=phonect",
                "--follow",
                "--no-pager",
                "--output=short-iso",
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
            )
        except FileNotFoundError:
            self._log_view.write("[yellow]journalctl not available (not Linux/systemd)[/yellow]")
            return

        while True:
            line = await proc.stdout.readline()
            if not line:
                break
            if not self._paused:
                self._log_view.write(line.decode("utf-8", errors="replace").rstrip())

    @on(Button.Pressed, "#btn-pause")
    def on_pause(self) -> None:
        self._paused = not self._paused
        btn = self.query_one("#btn-pause", Button)
        btn.label = "Resume" if self._paused else "Pause"

    @on(Button.Pressed, "#btn-clear")
    def on_clear(self) -> None:
        self._log_view.clear()

    @on(Button.Pressed, "#btn-back")
    def on_back(self) -> None:
        self._tail_task.cancel()
        self.app.pop_screen()


# ======================================================================
# Main TUI Application
# ======================================================================

class PhonectTui(App):
    """Textual TUI for phonect configuration and pairing."""

    CSS = """
    Screen {
        align: center top;
    }

    .title {
        text-style: bold;
        content-align: center top;
        padding: 1;
        background: $accent;
        color: $text;
    }

    .qr-code {
        margin: 1 2;
        padding: 1;
        border: solid $primary;
        min-height: 10;
    }

    #pairing-hint {
        padding: 0 2;
        color: $text-muted;
    }

    Button {
        margin: 0 1;
    }

    #btn-gen-keys, #btn-show-qr, #btn-refresh {
        min-width: 24;
    }

    #key-status {
        padding: 1 2;
    }

    RichLog {
        border: solid $primary;
        height: 80%;
        margin: 1 0;
    }
    """

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with TabbedContent(initial="pairing"):
            with TabPane("Pairing", id="pairing"):
                yield PairingScreen()
            with TabPane("Status", id="status"):
                yield StatusScreen()
            with TabPane("Logs", id="logs"):
                yield LogsScreen()
        yield Footer()


def _default_config_dir() -> Path:
    xdg = os.environ.get("XDG_CONFIG_HOME")
    if xdg:
        return Path(xdg) / "phonect"
    return Path.home() / ".config" / "phonect"


def _is_user_service() -> bool:
    """Check if the phonect service runs as a user service."""
    result = subprocess.run(
        ["systemctl", "--user", "is-active", "phonect"],
        capture_output=True, text=True, timeout=5,
    )
    return result.returncode == 0 or "active" in result.stdout


def run_tui() -> None:
    """Entry point for ``phonect tui``."""
    app = PhonectTui()
    app.run()


if __name__ == "__main__":
    run_tui()
