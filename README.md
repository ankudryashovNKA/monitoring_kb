# Monitoring KB MVP

MVP системы мониторинга состоит из:

- **FastAPI-сервера**, который принимает метрики CPU/RAM от удалённых узлов;
- **агента** на `psutil`, который раз в минуту собирает данные и отправляет их на сервер;
- **агента**, который раз в минуту отправляет метрики и последние системные логи;
- **веб-дашборда** с левым скрываемым меню и вкладками `Latest data` / `Nodes` / `Logs`;
- **интеграции с Knowledge Base API** (Hippocrates) и вкладкой `Knowledge Base`;
- **SQLAlchemy-подключения к Supabase PostgreSQL** и CRUD-примеров для `User`.

## Что реализовано

- Приём метрик через `POST /api/metrics`.
- Приём подписанных HMAC-запросов от агентов через `POST /api/agent/metrics` и `POST /api/agent/logs`.
- Реестр агентов (`agents`) c включением/выключением, отметкой `last_seen` и ротацией секрета.
- Хранение метрик и узлов в базе данных (Supabase PostgreSQL через SQLAlchemy).
- Политика retention: метрики старше 1 часа удаляются при запросах/записи.
- Получение последних значений через `GET /api/metrics`.
- Получение списка узлов и их параметров через `GET /api/nodes`.
- Приём логов узла через `POST /api/logs` (до 100 записей за отправку).
- Получение последних логов узла через `GET /api/logs?node_id=...`.
- Переименование узла через `PATCH /api/nodes/{node_id}`.
- Фоновая синхронизация Knowledge Base (`POST /solve/{KB_ID}` каждые 10 минут).
- Выдача результатов Knowledge Base для UI через `GET /api/knowledge-base`.
- CRUD для пользователей:
  - `POST /api/users`
  - `GET /api/users`
  - `GET /api/users/{user_id}`

## Конфигурация БД (Supabase)

1. Скопируйте `.env.example` в `.env` и заполните значения.
2. Используются переменные:
   - `SUPABASE_DB_HOST`
   - `SUPABASE_DB_PORT`
   - `SUPABASE_DB_NAME`
   - `SUPABASE_DB_USER`
   - `SUPABASE_DB_PASSWORD`
   - `KB_ID`
   - `KB_JWT_TOKEN`
   - (опционально) `KB_API_BASE_URL` и `KB_PRESET_NAME`
3. `DATABASE_URL` собирается автоматически из этих переменных в `app/config.py`.

> Примечание: если переменные не заданы, для локального запуска используется `sqlite:///./monitoring.db`.

## Запуск сервера

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```

При старте вызывается `Base.metadata.create_all(...)` для создания таблиц.
Для production рекомендуется использовать миграции (например, Alembic).

### Миграции/обновление схемы

В проекте сейчас нет Alembic, поэтому для создания таблицы `agents` достаточно перезапустить приложение (сработает `create_all`).  
Если нужна ручная SQL-миграция, используйте:

```sql
CREATE TABLE IF NOT EXISTS agents (
    agent_id VARCHAR(64) PRIMARY KEY,
    secret VARCHAR(128) NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    last_seen TIMESTAMPTZ NULL
);
```

## Запуск агента

1) В UI на вкладке **Nodes** нажмите **Register new node** и скопируйте `AGENT_ID` и `AGENT_SECRET` (показываются один раз).  
2) Запустите агента:

```bash
python agent.py --server-url http://127.0.0.1:8000 --node-id node-1 --agent-id <AGENT_ID> --agent-secret <AGENT_SECRET>
```

или через `.env`:

```env
SERVER_URL=http://127.0.0.1:8000
AGENT_ID=<AGENT_ID>
AGENT_SECRET=<AGENT_SECRET>
NODE_ID=node-1
```

По умолчанию агент отправляет данные каждые **60 секунд**.

### Формат подписи

Агент отправляет заголовки:
- `X-Agent-ID`
- `X-Timestamp`
- `X-Signature`

Подпись считается так:

`HMAC_SHA256(secret, METHOD + "\n" + PATH + "\n" + TIMESTAMP + "\n" + RAW_BODY)`

`RAW_BODY` — исходные байты JSON без повторной сериализации на сервере.

Пример подписанного запроса:

```bash
BODY='{"node_id":"node-1","cpu_percent":10,"ram_percent":20,"os_name":"Ubuntu","cpu_cores":4,"ram_total_mb":8192,"ip_address":"10.0.0.1","timestamp":"2026-03-30T12:00:00+00:00"}'
TS=$(date +%s)
SIG=$(python - <<'PY'
import hashlib, hmac, os
secret = os.environ["AGENT_SECRET"].encode()
ts = os.environ["TS"]
body = os.environ["BODY"].encode()
msg = f"POST\n/api/agent/metrics\n{ts}\n".encode() + body
print(hmac.new(secret, msg, hashlib.sha256).hexdigest())
PY
)
curl -X POST http://127.0.0.1:8000/api/agent/metrics \
  -H "Content-Type: application/json" \
  -H "X-Agent-ID: $AGENT_ID" \
  -H "X-Timestamp: $TS" \
  -H "X-Signature: $SIG" \
  -d "$BODY"
```

> Примечание по хранению секрета: для HMAC-проверки серверу нужен исходный `secret`, поэтому он хранится в БД. Для production дополнительно ограничьте доступ к БД, включите шифрование на уровне диска/СУБД и мониторинг доступа.

## Быстрая проверка User CRUD

### Создать пользователя

```bash
curl -X POST http://127.0.0.1:8000/api/users \
  -H 'Content-Type: application/json' \
  -d '{"email": "admin@example.com"}'
```

### Получить всех пользователей

```bash
curl http://127.0.0.1:8000/api/users
```

### Получить пользователя по ID

```bash
curl http://127.0.0.1:8000/api/users/1
```
