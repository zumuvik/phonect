# phonect — P2P Biometric Laptop Unlock

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![CI](https://github.com/zumuvik/phonect/actions/workflows/tests.yml/badge.svg)](https://github.com/zumuvik/phonect/actions/workflows/tests.yml)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue)](pyproject.toml)
[![Kotlin](https://img.shields.io/badge/kotlin-1.9%2B-purple)](android/)

**phonect** (phone + connect) — система бесшовной разблокировки Linux-ноутбука с помощью биометрии Android-смартфона. Связь между ПК и телефоном идёт напрямую по локальной сети Wi‑Fi/LAN: ПК объявляет себя через UDP discovery, телефон подключается обратно к TCP-демону ПК и подтверждает разблокировку подписью из Android Keystore.

Облака, внешние серверы и Bluetooth не используются.

## Текущий транспорт

- UDP discovery: порт `9875`, payload начинается с `PHONECT_DISCOVERY`.
- TCP daemon: порт по умолчанию `9876`.
- Android слушает UDP discovery и подключается к TCP listener на ПК.
- TCP-фреймы: `[4-byte big-endian uint32 length][UTF-8 JSON]`.
- Максимальный JSON payload: `65_536` байт.

## Как это работает

```text
┌─────────────────────┐        Wi‑Fi/LAN         ┌─────────────────────┐
│   Linux Laptop (PC) │                          │  Android Smartphone │
│                     │ ── UDP discovery ──────► │                     │
│  phonect daemon     │ ◄── TCP connect-back ─── │  Foreground service │
│                     │                          │                     │
│  1. pair_accept     │ ◄──── pair_hello ─────── │  0. phone key       │
│  2. challenge nonce │ ───── challenge ───────► │  3. BiometricPrompt │
│  5. verify + unlock │ ◄──── signature ──────── │  4. sign nonce      │
│                     │                          │                     │
│  loginctl           │                          │  Android Keystore   │
│  unlock-session     │                          │  BIOMETRIC_STRONG   │
└─────────────────────┘                          └─────────────────────┘
```

### Pairing / TOFU

Ручное pairing-командой больше не используется. `phonect pair` оставлен только как deprecated stub.

Текущая схема pairing:

1. Телефон подключается к TCP-демону во время открытого auth window.
2. Телефон отправляет `pair_hello` с публичным RSA-ключом и fingerprint.
3. ПК проверяет fingerprint PEM, отвечает `pair_accept` со своим публичным ключом.
4. Телефон доказывает владение приватным ключом, подписывая nonce.
5. При первом успешном TOFU ПК сохраняет публичный ключ телефона в `trusted_device.pub`.
6. **Первое TOFU-соединение не разблокирует сессию**. Разблокировка разрешена только на последующих соединениях с уже закреплённым ключом.

### Криптография

- RSA-4096.
- Nonce: 32 случайных байта, 64 hex-символа.
- Подпись: RSA-PSS/SHA-512.
- Python и Android должны использовать одинаковую PSS salt length: `64` байта.
- Android хранит приватный ключ в Android Keystore, с биометрическим подтверждением (`BIOMETRIC_STRONG`, StrongBox/TEE в зависимости от устройства).
- Доверие основано на публичных ключах, а не на IP-адресах.

## Структура проекта

```text
phonect/
├── src/phonect/
│   ├── __init__.py
│   ├── cli.py              # CLI: gen-keys, init-config, daemon, dev server/client
│   ├── config.py           # TOML config, defaults, UDP/TCP settings
│   ├── crypto.py           # RSA-4096, nonce, fingerprint, sign/verify
│   ├── daemon.py           # asyncio daemon: D-Bus resume, UDP discovery, TCP auth, unlock
│   ├── handshake.py        # Dev/test TCP challenge-response server/client
│   ├── protocol.py         # JSON length-prefixed frames, message builders/validators
│   └── state.py            # Legacy state.json compatibility helper
├── android/                # Android app, Kotlin/JDK 17
│   └── app/src/main/java/com/phonect/android/
│       ├── biometric/BiometricHandler.kt
│       ├── crypto/CryptoManager.kt
│       ├── logging/LogManager.kt
│       ├── model/HandshakeModels.kt
│       ├── network/PhonectNetworkService.kt
│       ├── network/ProtocolHandler.kt
│       └── ui/MainActivity.kt
├── phonect-service.nix     # NixOS module: package, config, firewall, user service
├── scripts/
│   └── e2e_cli_test.py     # Dev E2E test using CLI server/client
├── tests/
│   ├── test_cli.py
│   ├── test_daemon.py
│   ├── test_handshake.py
│   ├── test_protocol_security.py
│   └── test_state.py
├── SECURITY.md
├── CONTRIBUTING.md
└── LICENSE
```

## Установка и запуск на ПК

```bash
git clone https://github.com/zumuvik/phonect.git
cd phonect

python3 -m venv .venv
source .venv/bin/activate
pip install -e .

phonect gen-keys --private-key ~/.config/phonect/pc_private.pem \
                 --public-key ~/.config/phonect/pc_public.pem
phonect init-config
phonect daemon --foreground
```

По умолчанию config находится в:

- `$XDG_CONFIG_HOME/phonect/config.toml`, если задан `XDG_CONFIG_HOME`;
- иначе `~/.config/phonect/config.toml`.

Важные настройки:

```toml
[daemon]
listen_host = "0.0.0.0"
listen_port = 9876
poll_interval = 0.3
poll_timeout = 15.0

[keys]
private_key = "/home/user/.config/phonect/pc_private.pem"
public_key = "/home/user/.config/phonect/trusted_device.pub"

[device]
pc_name = "my-laptop"
unlock_on_start = false
```

## CLI-команды

| Команда | Описание |
|---------|----------|
| `phonect gen-keys` | Генерация RSA-4096 пары ключей |
| `phonect init-config [--path <path>]` | Создать шаблон `config.toml` |
| `phonect daemon [--config <path>] [--foreground]` | Запуск Wi‑Fi/TCP daemon |
| `phonect pair [--config <path>]` | Deprecated: ручной pairing отключён, используется daemon-side TOFU |
| `phonect server <public_key> [--port <port>]` | Dev PC challenge server |
| `phonect client <private_key> <pc_ip> <pc_port>` | Dev mobile emulator client |

Dev E2E:

```bash
python scripts/e2e_cli_test.py
```

## Демон

`phonect daemon`:

1. Загружает приватный ключ ПК и доверенный публичный ключ телефона, если он уже есть.
2. Запускает TCP listener на `listen_host:listen_port`.
3. Подписывается на `org.freedesktop.login1.Manager.PrepareForSleep` через system D-Bus.
4. При resume (`PrepareForSleep=false`) открывает ограниченное auth window.
5. Во время auth window отправляет UDP discovery и принимает одно TCP authentication-соединение.
6. При успешной проверке закреплённого ключа вызывает `loginctl unlock-session` для активных сессий пользователя.

Дополнительно:

- `unlock_on_start = true` запускает auth cycle при старте daemon.
- `SIGUSR1` используется как ручной trigger auth cycle.
- Подключения вне auth window закрываются без разблокировки.
- Если телефон подключился с новым ключом, первый успешный TOFU сохраняет ключ, но не разблокирует.

## Android-приложение

Android app находится в `android/` и собирается Gradle/JDK 17.

Основные компоненты:

- `PhonectNetworkService.kt` — foreground service: слушает UDP discovery, подключается к TCP daemon, выполняет TOFU/auth flow.
- `ProtocolHandler.kt` — чтение/запись length-prefixed JSON frames.
- `HandshakeModels.kt` — Kotlin-модели сообщений, порты и discovery constants.
- `CryptoManager.kt` — Android Keystore, RSA-4096, fingerprint PEM, biometric-bound signing.
- `BiometricHandler.kt` — wrapper над `BiometricPrompt`.
- `MainActivity.kt` — управление сервисом, статус, текущая Activity для `BiometricPrompt` через `WeakReference`.
- `LogManager.kt` — локальные логи приложения.

Разрешения Android: `INTERNET`, `ACCESS_NETWORK_STATE`, `ACCESS_WIFI_STATE`, foreground service и `USE_BIOMETRIC`. Bluetooth permissions не требуются.

## NixOS module

`phonect-service.nix` предоставляет NixOS-модуль:

```nix
{
  imports = [ ./phonect-service.nix ];

  services.phonect = {
    enable = true;
    settings = {
      keys.public_key = "/home/user/.config/phonect/trusted_device.pub";
      keys.private_key = "/home/user/.config/phonect/pc_private.pem";

      device.pc_name = "my-laptop";
      device.unlock_on_start = false;

      daemon.listen_host = "0.0.0.0";
      daemon.listen_port = 9876;
      daemon.poll_interval = 0.3;
      daemon.poll_timeout = 15.0;

      logging.level = "INFO";
    };
  };
}
```

Модуль:

- собирает Python package и добавляет CLI в `environment.systemPackages`;
- пишет config в `/etc/phonect/config.toml`;
- открывает UDP `9875` и настроенный TCP порт daemon;
- запускает `systemd.user.services.phonect` от пользователя, не root;
- включает lightweight hardening для user service.

## Тесты

Текущие тесты:

- `tests/test_cli.py` — CLI-команды, импорт без удалённых TUI-зависимостей и metadata-проверки.
- `tests/test_handshake.py` — challenge-response, wrong-key rejection, biometric decline.
- `tests/test_daemon.py` — config, session detection, daemon TCP pairing/auth, TOFU, auth window.
- `tests/test_protocol_security.py` — max frame size, malformed JSON, nonce/signature validation.
- `tests/test_state.py` — legacy `state.json` helpers.
- `scripts/e2e_cli_test.py` — dev E2E через `phonect server` + `phonect client`.

Локально обычная команда для CI/dev окружения:

```bash
pip install -e ".[dev]"
pytest tests/ -v --tb=short
```

Для AI-агентов это считается тяжёлой операцией, если занимает заметное время: см. следующий раздел.

## Требования

- Python >= 3.11.
- Python dependencies: `cryptography`, `dbus-next`.
- Android: Kotlin/JDK 17, Android Gradle project in `android/`.
- NixOS module users: NixOS with user systemd services and firewall configuration.

## Лицензия

MIT
