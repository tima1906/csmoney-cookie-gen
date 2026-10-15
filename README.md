# csmoney-cookie-gen

Асинхронный вход в CS.MONEY через Steam и Camoufox. Для каждого аккаунта сохраняется связка **cookies + прокси + User-Agent**. Новые аккаунты регистрируются в том же браузере; после входа открывается рынок и выполняется прокрутка. Перед сохранением сессия проходит серию HTTP-проверок.

## Установка

Python 3.12+. Команды ниже — для PowerShell из папки проекта.

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python -m camoufox fetch
Copy-Item config.example.json config.json
```

Используется закреплённая версия `aiosteampy==1.0.0b16`. HTTP-клиент — `aiohttp`, альтернативный backend — `httpx`.

## Конфиг

```json
{
  "settings": {
    "browser_concurrency": 2,
    "login_attempts": 3,
    "headless": true,
    "window": [1100, 650],
    "verify_interval": 600
  },
  "accounts": [
    {
      "account_id": "my_login",
      "proxy": "http://user:password@host:8080",
      "email": "my-address@example.com",
      "steam": {
        "username": "my_login",
        "password": "steam_password"
      }
    }
  ]
}
```

- `proxy`: HTTP(S), SOCKS4/5, в том числе `socks5h://`; форматы `scheme://user:password@host:port`, `host:port` или `host:port:user:password`. Без прокси используется прямое соединение. SOCKS с авторизацией для браузера подключается через локальный мост.
- `email`: почта для регистрации нового аккаунта. Если поле отсутствует, берётся из `emails.txt` рядом с конфигом: `my_login,my-address@example.com`. Имя файла задаётся в `settings.emails_file`. Поле в конфиге имеет приоритет.
- **maFile**: автоматически подхватывается `maFiles/<account_id>.mafile` рядом с конфигом, без учёта регистра имени и расширения. Явный `steam.mafile` имеет приоритет; относительный путь считается от конфига. Из файла берутся недостающие Steam-данные: `shared_secret`, имя аккаунта, токены и Steam ID.
- Вместо maFile можно задать `steam.shared_secret`, `refresh_token`, `access_token` или `cookies`. Логин и пароль служат запасным способом входа, когда пригодного токена нет.

Основные `settings`:

| Параметр | По умолчанию | Назначение |
|---|---|---|
| `browser_concurrency` | `2` | Одновременные входы, включая Steam |
| `login_attempts` | `3` | Ограничение попыток входа |
| `headless` | `true` | Работа без видимого окна |
| `window` | `null` | Размер окна `[ширина, высота]`; видимое окно без настройки — 1280×720 |
| `market_url` | `https://cs.money/ru/market/buy/?order=asc&sort=price` | Рынок после входа |
| `scroll_steps` / `scroll_pause` | `3` / `0.5` | Число прокруток и пауза в секундах |
| `check_paths` | Три запроса `sell-orders?limit=1` с разной сортировкой | Последовательные HTTP-проверки каждой сессии |
| `http_backend` / `http_timeout` / `http_retries` | `aiohttp` / `30` / `3` | HTTP-клиент, тайм-аут и повторы |
| `verify_interval` | `600` | Сколько секунд переиспользовать недавно проверенную сессию без запроса |
| `reauth_cooldown` / `reauth_cooldown_max` | `120` / `3600` | Пауза после неудачного входа, удваивается до предела |

Полный список — `Settings` в `csmoney_auth/core.py`. Значения из существующего конфига имеют приоритет над настройками по умолчанию.

## Команды

После активации окружения:

```powershell
# Импорт: login,password[,email или shared_secret] или login:password:email[:пароль_почты]
python -m csmoney_auth import accounts.txt --proxies proxies.txt --dry-run
python -m csmoney_auth import accounts.txt --proxies proxies.txt

# Вход и при необходимости регистрация; существующие рабочие сессии переиспользуются
python -m csmoney_auth login
python -m csmoney_auth login -a my_login
python -m csmoney_auth login -a my_login --force --headful --step-delay 3
python -m csmoney_auth login -a my_login --force --keep-open --window 1100x650
python -m csmoney_auth login -a my_login --manual --step-delay 3

# Только HTTP: до 8 аккаунтов одновременно; внутри каждого check_paths идут подряд
python -m csmoney_auth verify
python -m csmoney_auth verify -a my_login --jobs 4
python -m csmoney_auth status

# Просмотр и экспорт
python -m csmoney_auth cookies -a my_login
python -m csmoney_auth cookies -a my_login --reveal
python -m csmoney_auth cookies -a my_login --format config
python -m csmoney_auth export --format config
python -m csmoney_auth export -a my_login --format full -d exports
python -m csmoney_auth -c old-config.json export --format config

# Запрос, диагностика и удаление сохранённой сессии
python -m csmoney_auth request -a my_login "https://cs.money/api/public/v3/user-info" --limit 300
python -m csmoney_auth analyze-cookies -a my_login
python -m csmoney_auth forget -a my_login

# Другой конфиг и подробные логи: глобальные параметры перед подкомандой
python -m csmoney_auth -c other.json -v login -a my_login
```

Строки импорта: `login,password[,email или shared_secret]` или то же через `:` (`login:password:email[:пароль_почты]`). Поле с `@` считается почтой, иначе третья колонка — `shared_secret`; поля после почты и хвост ` # комментарий` игнорируются, строки с `#` в начале пропускаются. Повторные аккаунты пропускаются, но недостающая почта дописывается. Прокси назначаются только новым аккаунтам по порядку; если их не хватает, выводится предупреждение. `--dry-run` ничего не записывает, `--logins-only` игнорирует пароли и shared secret. Импорт не запускает вход и не открывает базу.

`--headful` показывает окно браузера, `--step-delay` делает паузу после каждого этапа, `--force` запускает новый вход, даже если сессия рабочая или действует пауза после неудач. `export` без `-a` берёт аккаунты из текущего конфига; сессии аккаунтов, удалённых из конфига, остаются в базе и выгружаются через `-a` или со старым конфигом (`-c`).

Замена аккаунтов: удалите их записи из `accounts` в `config.json` (прокси можно сохранить для новых), очистите сохранённые данные `forget -a ...`, затем импортируйте новые аккаунты с этими прокси и запустите `login`. Новые аккаунты не берите из той же партии, что заблокированные: Steam обычно ограничивает такие аккаунты все сразу.

Отдельные `setup` и `import_accounts.py` заменены командами `login` и `import`. При регистрации трейд-ссылка читается из Steam, принимаются обязательные условия; рассылка остаётся выключенной. На странице рынка принимается баннер cookies. `--keep-open` оставляет браузер для ручной работы до Enter или закрытия окна; до возврата из браузера новая сессия ещё не сохранена.

## Хранение и структура

- `data/sessions.db` — SQLite: сессии CS.MONEY, состояние Steam, история неудачных входов. Cookies, токены и прокси зашифрованы Fernet. Метаданные, в том числе статус, Steam ID и User-Agent, доступны без расшифровки.
- `data/store.key` — ключ, создаётся при первом запуске. Вместо него можно задать `CSMONEY_STORE_KEY`. Без правильного ключа база не расшифруется.
- `data/failures/<account_id>-<время>-<причина>.html/.png` — HTML и скриншот страницы, на которой застрял вход в Steam OpenID; путь указан в тексте ошибки.
- `exports/<account_id>.json` — явный экспорт **открытым текстом**. `full` сохраняет атрибуты cookies и метаданные; `config` — плоский словарь cookies, строку `cookie`, `user_agent` и `proxy`. Экспорт обновляется отдельной командой.
- `config.json`, `maFiles/`, списки аккаунтов, почт, прокси и `exports/` исключены из Git. Исходные конфиги и maFile не шифруются модулем.

Пакет: `core.py` — общие типы и настройки; `store.py` — хранилище; `client.py` — HTTP и диагностика; `steam.py` — Steam-сессия; `browser.py` — браузерный сценарий; `manager.py` — управление сессиями; `__main__.py` — CLI; `__init__.py` — публичные импорты. Camoufox, Playwright и aiosteampy загружаются при необходимости входа, а не для просмотра или HTTP-проверки сессий.

## Типичные ошибки

| Ошибка / статус | Что означает |
|---|---|
| `ProxyError`, `NetworkError` | Прокси, сеть или тайм-аут; проверьте доступность и учётные данные |
| `SteamAuthError` | Steam не принял пароль или токены |
| `SteamGuardRequired` | Нужен shared secret из maFile либо штатное ручное подтверждение с `--manual` |
| `SteamOpenIdRejected` | Steam ответил на подтверждение OpenID своей страницей «Error»: аккаунту (или его IP) запрещён вход на сторонние сайты. Повтор не выполняется; вручную в окне ошибка та же. Обычно это ограничение аккаунта, лучше заменить аккаунт |
| `BrowserTimeoutError: no redirect back to cs.money` | После подтверждения Steam не вернул на cs.money без явной ошибки. В тексте указано, был ли отправлен запрос подтверждения (POST) и с каким кодом пришёл ответ, и куда сохранена страница. Повторяется в пределах `login_attempts` |
| `RegistrationRequired` | Новому аккаунту не задан email |
| `CaptchaRequiredError`, код `4030` | Сервер требует CAPTCHA; это не доказательство истёкшей авторизации |
| `challenged` | HTTP-проверка встретила CAPTCHA или Cloudflare challenge |
| `expired` | Сохранённая сессия отклонена; нужен новый вход |
| `ReauthNotAllowed` | Ещё действует пауза после неудачного входа |
| `StorageError` | Ошибка базы или неверный ключ Fernet |

Запросы выполняются с сохранённым прокси и User-Agent. `cf_clearance` сохраняется, если браузер его получил; наличие cookie само по себе не гарантирует доступ. Коды 429 и серверные ошибки имеют ограниченные повторы. CAPTCHA и Steam Guard не обходятся; для ручных проверок предусмотрен `--manual`.

## Тесты

```powershell
python -m pytest -q
python -m pip install ruff
python -m ruff check csmoney_auth tests
```

Тесты используют временные конфиги, зашифрованную SQLite и локальные HTTP/SOCKS-серверы; реальные аккаунты не нужны. Проверяются также импорт, автоподхват maFile, ограничение параллельного `verify` и отсутствие браузерных зависимостей в командах просмотра. Сам сценарий сайта требует отдельной проверки в браузере.
