# Phonect

Phonect — система локальной разблокировки Linux-сеанса с Android-устройства. Телефон подтверждает действие биометрией, подписывает одноразовый challenge ключом из Android Keystore, а daemon на ПК проверяет подпись и выполняет выбранное локальное действие разблокировки.

Проект рассчитан на Linux-десктоп и Android. Он не использует облачные сервисы: обнаружение происходит в локальной сети, а доверие строится на закреплённых публичных ключах.

> Phonect — экспериментальный проект. Перед использованием на рабочей машине проверьте настройки daemon и выбранного backend разблокировки.

## Возможности

- биометрическое подтверждение на Android через `BiometricPrompt`;
- RSA-4096 challenge-response с RSA-PSS/SHA-512;
- взаимная проверка ПК и телефона;
- TOFU-паринг: первый корректный ключ телефона закрепляется, но не разблокирует сессию;
- UDP discovery и TCP-соединение в локальной сети;
- Android foreground service для приёма discovery и выполнения handshake;
- Python daemon с ограниченным окном аутентификации после resume, по `SIGUSR1` или при старте;
- backend разблокировки `loginctl` и статически заданная локальная argv-команда;
- Nix flake, NixOS module и проверки Nix;
- CI для Python, Nix и Android debug APK.

## Архитектура

| Компонент | Назначение |
| --- | --- |
| Android-приложение | Хранит ключ в Android Keystore, слушает UDP discovery, подключается к ПК и запрашивает биометрию. |
| Python daemon | Открывает окно аутентификации, рассылает discovery, проверяет handshake и запускает локальный backend разблокировки. |
| `config.toml` | Содержит пути ключей, сетевые параметры, настройки окна аутентификации и backend разблокировки. |
| Протокол | Передаёт length-prefixed JSON frames по TCP: `pair_hello`, `pair_accept`, `challenge`, `response`. |

Daemon слушает TCP, а телефон после UDP discovery сам подключается к объявленному адресу и порту. TCP-кадры не являются TLS-транспортом: целостность и аутентификация обеспечиваются закреплёнными RSA-ключами, взаимной подписью challenge и подписью nonce телефоном.

## Поток аутентификации

1. После resume, `SIGUSR1` или при `unlock_on_start = true` daemon открывает ограниченное окно аутентификации.
2. Пока окно открыто, daemon рассылает UDP-пакеты `PHONECT_DISCOVERY` на порту `9875`.
3. Android service получает discovery и открывает TCP-соединение с daemon (по умолчанию порт `9876`).
4. Телефон отправляет `pair_hello` с публичным ключом, fingerprint и идентификатором сессии. ПК отвечает `pair_accept` со своим публичным ключом.
5. При первом контакте daemon применяет TOFU: проверяет ключ телефона и сохраняет его только после полного доказательства владения ключом. Первый успешный контакт не разблокирует сессию.
6. ПК отправляет 32-байтный nonce в `challenge` и подписывает его своим ключом. Android проверяет ключ ПК, fingerprint и подпись.
7. Android показывает биометрический запрос. После подтверждения ключ Keystore подписывает nonce.
8. Daemon проверяет `response`. Только для уже закреплённого ключа после успешной проверки запускается backend разблокировки.

Кадр TCP имеет формат:

```text
[4-byte uint32 длина, big-endian][UTF-8 JSON]
```

Максимальный payload — 65 536 байт. Версия протокола — `1`.

## Безопасность

- Приватный ключ телефона создаётся в Android Keystore; биометрия требуется для подписи nonce.
- Daemon закрепляет публичный ключ телефона и не заменяет уже доверенный ключ неизвестным ключом.
- Первый TOFU-handshake не разблокирует сеанс.
- ПК также подписывает challenge, поэтому Android проверяет ключ ПК до биометрического запроса.
- Nonce состоит из 32 случайных байт и используется для одного challenge; ответ нельзя повторно использовать как доказательство для другого nonce.
- Соединения вне окна аутентификации и параллельные попытки закрываются.
- Команда backend не получает данные из Android, discovery или TCP JSON. Она берётся только из локального `config.toml`.

Phonect не гарантирует безопасность всей рабочей станции: корректность backend разблокировки, настройки desktop environment и защита локальных конфигурационных файлов остаются ответственностью администратора.

## Установка

### Nix

Flake предоставляет пакет для `x86_64-linux`:

```bash
nix build github:zumuvik/phonect#packages.x86_64-linux.default
./result/bin/phonect --help
```

Для проверки исходного дерева:

```bash
nix flake check path:. --no-write-lock-file --print-build-logs
```

### NixOS module

Подключите flake как input:

```nix
{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    phonect = {
      url = "github:zumuvik/phonect";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { nixpkgs, phonect, ... }: {
    nixosConfigurations.host = nixpkgs.lib.nixosSystem {
      system = "x86_64-linux";
      modules = [
        phonect.nixosModules.default
        {
          services.phonect = {
            enable = true;
            user = "user";
          };
        }
      ];
    };
  };
}
```

Минимальная настройка модуля:

```nix
services.phonect = {
  enable = true;
  user = "user";
  settings = {
    keys = {
      private_key = "/home/user/.config/phonect/pc_private.pem";
      public_key = "/home/user/.config/phonect/trusted_device.pub";
    };

    device = {
      pc_name = "my-laptop";
      unlock_on_start = false;
    };

    daemon = {
      listen_host = "0.0.0.0";
      listen_port = 9876;
      poll_interval = 0.3;
      poll_timeout = 15.0;
      unlock_backend = "loginctl";
      unlock_command = [];
    };

    logging.level = "INFO";
  };
};
```

Модуль создаёт `/etc/phonect/config.toml`, добавляет пакет в `environment.systemPackages`, открывает TCP-порт daemon и UDP `9875`, затем запускает user service только в systemd user manager указанного нормального пользователя (`user`):

```text
phonect daemon --config /etc/phonect/config.toml
```

### Другие Linux-дистрибутивы

Требуется Python 3.11+ и зависимости пакета `cryptography`, `dbus-next`.

```bash
python -m pip install .
phonect init-config
phonect gen-keys \
  --private-key ~/.config/phonect/pc_private.pem \
  --public-key ~/.config/phonect/pc_public.pem
phonect daemon --foreground
```

Для разработки:

```bash
python -m pip install -e ".[dev]"
pytest tests/ -v --tb=short
```

## Конфигурация daemon

По умолчанию конфигурация ищется в `$XDG_CONFIG_HOME/phonect/config.toml`, а при отсутствии `XDG_CONFIG_HOME` — в `~/.config/phonect/config.toml`.

```toml
[daemon]
listen_host = "0.0.0.0"
listen_port = 9876
poll_interval = 0.3
poll_timeout = 15.0
unlock_backend = "loginctl"
unlock_command = []

[keys]
private_key = "/home/user/.config/phonect/pc_private.pem"
public_key = "/home/user/.config/phonect/trusted_device.pub"

[device]
pc_name = "my-laptop"
unlock_on_start = false

[logging]
level = "INFO"
```

| Опция | Значение |
| --- | --- |
| `daemon.listen_host` | Адрес TCP listener. |
| `daemon.listen_port` | TCP-порт daemon; по умолчанию `9876`. |
| `daemon.poll_interval` | Интервал UDP discovery во время окна аутентификации. |
| `daemon.poll_timeout` | Длительность окна аутентификации в секундах. |
| `daemon.unlock_backend` | `loginctl` или `command`; по умолчанию `loginctl`. |
| `daemon.unlock_command` | Статический список argv для backend `command`. |
| `keys.private_key` | Приватный ключ ПК для подписи challenge. |
| `keys.public_key` | Закреплённый публичный ключ телефона; заполняется после TOFU. |
| `device.unlock_on_start` | Открыть окно аутентификации при старте daemon. |
| `logging.level` | `DEBUG`, `INFO`, `WARNING` или `ERROR`. |

### Backends разблокировки

`loginctl` — backend по умолчанию. Daemon находит сессии текущего пользователя на `seat0` и для каждой выполняет:

```text
loginctl unlock-session <session-id>
```

`command` предназначен для сред, где после успешной аутентификации требуется локальное действие, отличное от `loginctl`. Команда задаётся только списком argv:

```toml
[daemon]
unlock_backend = "command"
unlock_command = ["/usr/local/bin/phonect-unlock", "--quiet"]
```

Она выполняется один раз после успешной аутентификации уже закреплённого телефона. Строка shell-формата вроде `"program --arg"` не принимается. Не выполняются shell, подстановка переменных, пайпы, перенаправления и fallback на `loginctl`.

Не помещайте секреты в `unlock_command`. В частности, NixOS module записывает сгенерированный `config.toml` в `/etc`, поэтому argv должен содержать только безопасные для чтения значения. Phonect не устанавливает и не выбирает программу автоматически.

## CLI

Глобальный параметр для всех команд:

```text
--log-level {DEBUG,INFO,WARNING,ERROR}
```

| Команда | Назначение |
| --- | --- |
| `phonect gen-keys [--private-key PATH] [--public-key PATH]` | Создать RSA-4096 пару ключей. |
| `phonect daemon [--config PATH] [--foreground]` | Запустить TCP daemon и обработку resume. |
| `phonect init-config [--path PATH]` | Создать шаблон `config.toml`. |
| `phonect server PUBLIC_KEY [--port PORT] [--timeout SEC]` | Development challenge server. |
| `phonect client PRIVATE_KEY PC_IP PC_PORT [--device-name NAME] [--timeout SEC]` | Development mobile emulator. |

Примеры:

```bash
# Создать ключи с путями, соответствующими config.toml
phonect gen-keys --private-key ~/.config/phonect/pc_private.pem \
  --public-key ~/.config/phonect/pc_public.pem

# Запустить daemon с явной конфигурацией
phonect daemon --config ~/.config/phonect/config.toml --foreground

# Создать шаблон в другом месте
phonect init-config --path ./config.toml

# Development handshake
phonect server trusted_phone.pub --port 9876
phonect client phone_private.pem 127.0.0.1 9876 --device-name android-emulator
```

## Android

### Release signing

Create the owner keystore (password prompts are intentional) and store offline backups outside the repository:

```bash
keytool -genkeypair -keystore phonect-release.jks -alias phonect -keyalg RSA -keysize 4096 -validity 10000
base64 -w 0 phonect-release.jks                 # Linux
base64 < phonect-release.jks | tr -d '\n'       # macOS
keytool -list -v -keystore phonect-release.jks -alias phonect | grep 'SHA256:'
```

Normalize the exact alias SHA-256 digest to 64 uppercase hexadecimal characters. Configure GitHub Secrets: `ANDROID_KEYSTORE_BASE64`, `ANDROID_KEYSTORE_PASSWORD`, `ANDROID_KEY_ALIAS`, and `ANDROID_KEY_PASSWORD`; configure the required `ANDROID_SIGNING_CERT_SHA256` GitHub Variable. For a local release build:

```bash
cd android
ANDROID_KEYSTORE_PATH=/secure/phonect-release.jks ANDROID_KEYSTORE_PASSWORD=... ANDROID_KEY_ALIAS=phonect ANDROID_KEY_PASSWORD=... ./gradlew :app:assembleRelease
```

`versionCode` must increase for every published APK. APKs signed by an unavailable prior/debug key cannot be transparently migrated or installed as updates; users must uninstall first, which may lose application data. Use the dispatch-only **Release — Android** workflow with an existing `vX.Y.Z` tag and GitHub Release; debug CI artifacts are diagnostic only.

Android-приложение использует foreground service. Он слушает UDP discovery, соединяется с daemon по TCP, выполняет TOFU и проверку ключа ПК, а затем использует `BiometricPrompt` для подписи nonce.

Поддерживаемые параметры сборки: minSdk 28, compileSdk/targetSdk 34, JDK 17. Application ID: `com.phonect.android`.

Приложению требуются `INTERNET`, `ACCESS_NETWORK_STATE`, `ACCESS_WIFI_STATE`, `FOREGROUND_SERVICE`, `FOREGROUND_SERVICE_SPECIAL_USE` и `USE_BIOMETRIC`. Биометрическое оборудование помечено как необязательное в manifest.

Паринг не требует ручного ввода адреса: телефон ждёт UDP discovery. При первом корректном соединении ключи закрепляются по TOFU, но разблокировка выполняется только при последующем успешном handshake.

## Разработка

Структура репозитория:

```text
src/phonect/                 Python daemon, config, crypto и protocol
android/                     Android application и Gradle wrapper
tests/                       Python unit и integration tests
scripts/e2e_cli_test.py      Development TCP challenge-response test
package.nix                  Общая Nix derivation Python-пакета
flake.nix / flake.lock       Flake, package и semantic checks
phonect-service.nix          NixOS module
.github/workflows/           Python, Nix и Android CI
```

Основные команды:

```bash
# Python
python -m pip install -e ".[dev]"
pytest tests/ -v --tb=short
python scripts/e2e_cli_test.py

# Nix
nix flake check path:. --no-write-lock-file --print-build-logs
nix build path:.#packages.x86_64-linux.default --no-write-lock-file --print-build-logs

# Android: JDK 17 и Android SDK должны быть доступны
cd android
./gradlew --no-daemon testDebugUnitTest assembleDebug
```

На NixOS Android build может требовать FHS-окружение из `shell.nix` или совместимый runtime для Android build tools.

### CI и APK

- Python workflow проверяет тесты на Python 3.11, 3.12 и 3.13 и запускает CLI E2E.
- Nix workflow выполняет flake checks, сборку пакета и проверку CLI.
- Android workflow запускает `testDebugUnitTest assembleDebug` с JDK 17 и публикует debug APK как artifact на 7 дней.

Для релиза создайте commit и существующий `vX.Y.Z` tag/GitHub Release, затем запустите dispatch workflow **Release — Android** с этим tag. Debug APK должен быть явно помечен как diagnostic/debug build, а не production release.

## Сборка

### Python package

```bash
python -m build
```

### Android debug APK

```bash
cd android
./gradlew --no-daemon testDebugUnitTest assembleDebug
```

Готовый файл: `android/app/build/outputs/apk/debug/app-debug.apk`.

### Nix package

```bash
nix build path:.#packages.x86_64-linux.default --no-write-lock-file --print-build-logs
./result/bin/phonect --help
```

## Roadmap

Публично зафиксированного roadmap нет.

## Лицензия

MIT. См. [LICENSE](LICENSE).
