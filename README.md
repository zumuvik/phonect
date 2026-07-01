# phonect — P2P Biometric Laptop Unlock

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

**phonect** (phone + connect) — система бесшовной разблокировки Linux-ноутбука с помощью сканера отпечатков пальцев на Android-смартфоне. Связь между устройствами осуществляется напрямую (P2P) по локальной сети Wi-Fi, без сторонних облачных серверов.

## Как это работает

```
┌─────────────────────┐          Wi-Fi LAN           ┌─────────────────────┐
│   Linux Laptop (PC) │◄────────────────────────────►│  Android Smartphone │
│                     │    Challenge-Response TCP     │                     │
│  ┌───────────────┐  │                               │  ┌───────────────┐  │
│  │ 1. Генерирует  │──┼──── nonce (32 байта) ────────┼─►│ 2. Запрашивает │  │
│  │    Nonce       │  │                               │  │    отпечаток   │  │
│  └───────────────┘  │                               │  └───────┬───────┘  │
│                     │                               │          ▼          │
│  ┌───────────────┐  │                               │  ┌───────────────┐  │
│  │ 4. Проверяет   │◄─┼── signature (RSA-4096 PSS) ───┼─┤ 3. Подписывает │  │
│  │    подпись     │  │                               │  │    Nonce       │  │
│  └───────┬───────┘  │                               │  └───────────────┘  │
│          ▼          │                               │                     │
│  ┌───────────────┐  │                               │  Android Keystore   │
│  │ loginctl       │  │                               │  BIOMETRIC_STRONG   │
│  │ unlock-session │  │                               │                     │
│  └───────────────┘  │                               └─────────────────────┘
└─────────────────────┘
```

### Криптографическая схема (Challenge-Response)

1. **На телефоне** генерируется пара ключей **RSA-4096**. Приватный ключ изолирован в Android Keystore с флагом `BIOMETRIC_STRONG`. Публичный ключ передается на ПК при сопряжении.
2. **При открытии крышки** ноутбука ПК генерирует случайный 32-байтный Nonce и отправляет его на телефон по TCP.
3. **Телефон** запрашивает отпечаток пальца через `BiometricPrompt`. После успешной аутентификации подписывает Nonce и отправляет подпись обратно.
4. **ПК** проверяет подпись публичным ключом. При успехе вызывает `loginctl unlock-session`.

## Структура проекта

```
phonect/
├── src/phonect/
│   ├── __init__.py         # Пакет
│   ├── crypto.py           # RSA-4096: генерация ключей, Nonce, подпись, верификация
│   ├── protocol.py         # Сетевой протокол (JSON length-prefixed frames)
│   ├── handshake.py        # Оркестрация handshake (PC server + mobile client)
│   ├── daemon.py           # 🆕 Фоновый asyncio-демон (D-Bus, poll, unlock)
│   ├── config.py           # 🆕 Конфигурация (TOML, ~/.config/phonect/)
│   └── cli.py              # CLI: gen-keys, server, client, daemon, init-config
├── phonect-service.nix     # 🆕 NixOS модуль: systemd service + опции
├── scripts/
│   └── e2e_cli_test.py     # End-to-end интеграционный тест
├── tests/
│   ├── test_handshake.py   # Unit-тесты handshake
│   └── test_daemon.py      # 🆕 Тесты демона (config, session, async handshake)
└── pyproject.toml
```

## Быстрый старт (Шаг 1 — прототип)

```bash
# Клонировать
git clone https://github.com/zumuvik/phonect.git
cd phonect

# Установить
python3 -m venv .venv
source .venv/bin/activate
pip install -e .

# Сгенерировать ключи
phonect gen-keys

# Запустить ПК-сервер (в терминале 1)
phonect server phonect_public.pem --port 9999

# Запустить эмулятор мобилки (в терминале 2)
phonect client phonect_private.pem 127.0.0.1 9999

# Или запустить полный E2E тест
python scripts/e2e_cli_test.py
```

## CLI-команды

| Команда | Описание |
|---------|----------|
| `phonect gen-keys` | Генерация RSA-4096 ключей |
| `phonect server <pubkey>` | Запуск ПК-сервера (ожидает мобилку) |
| `phonect client <privkey> <ip> <port>` | Эмуляция Android-клиента |
| `phonect daemon` | 🆕 Запуск фонового демона (D-Bus + poll + unlock) |
| `phonect init-config` | 🆕 Создать шаблон config.toml |

## План реализации

- [x] **Шаг 1**: Прототип криптографического handshake (RSA-4096, Nonce, подпись, верификация) — **готов**
- [x] **Шаг 2**: Фоновый демон для Linux с интеграцией `systemd-logind` и `suspend.target` — **готов**
- [ ] **Шаг 3**: Android-приложение (Keystore, BiometricPrompt, сетевой сокет)
- [ ] **Шаг 4**: TUI-конфигуратор с QR-кодом и менеджером устройств

## Демон (Шаг 2)

Фоновый демон (`phonect daemon`) интегрируется с `systemd-logind` через D-Bus:

1. **D-Bus listener**: подписывается на сигнал `PrepareForSleep` от `org.freedesktop.login1.Manager`.
2. **При wakeup** (PrepareForSleep=false): запускает агрессивный цикл опроса — пытается соединиться с телефоном каждые 200 мс в течение 10 секунд.
3. **При успешном соединении**: выполняется Challenge-Response handshake.
4. **При успешной верификации**: `loginctl unlock-session <id>` для всех активных сессий пользователя.
5. **SIGUSR1**: ручной триггер цикла аутентификации (без сна).

### NixOS модуль

Файл `phonect-service.nix` — готовый NixOS-модуль для включения в конфигурацию:

```nix
{
  imports = [ ./phonect-service.nix ];

  services.phonect = {
    enable = true;
    user = "zumuvik";
    mobileIp = "192.168.1.100";
    mobilePort = 9876;
    publicKey = "/var/lib/phonect/trusted_device.pub";
  };
}
```

Модуль автоматизирует:
- Сборку Python-пакета с зависимостями (`cryptography`, `dbus-next`)
- Генерацию config.toml из опций
- Systemd-сервис с security hardening
- Запуск сервиса после `network.target` и `suspend.target`

## Требования

- Python ≥ 3.11
- Библиотека `cryptography` (устанавливается автоматически)

## Лицензия

MIT
