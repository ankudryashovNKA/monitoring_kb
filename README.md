# Monitoring KB MVP

`Monitoring KB MVP` — это сервер мониторинга узлов (node monitoring) с локальным агентом и встроенным веб-дашбордом в одном FastAPI-приложении.

Проект решает сразу несколько задач:

- собирает с удалённых узлов метрики CPU/RAM;
- принимает и отображает системные логи;
- хранит данные в PostgreSQL (Supabase) через SQLAlchemy;
- позволяет управлять агентами (регистрация, отключение, ротация секрета);
- поддерживает триггеры и список активных проблем;
- интегрируется с внешним API Knowledge Base (`kb.ai-hippocrates.ru`);
- даёт UI-вкладку LLM, которая проксирует запросы в локально установленный Ollama (`gemma3:4b`).

---

## 1) Архитектура проекта в целом

### Компоненты

1. **FastAPI-сервер (`main.py`)**
   - REST API для метрик, логов, агентов, триггеров, проблем, KB, LLM;
   - встроенный HTML/JS-дашборд на `GET /`;
   - on-demand интеграция с Knowledge Base для выбранного узла (по кнопке в UI).

2. **Агент (`agent.py`)**
   - собирает метрики с `psutil`;
   - читает системные логи (`/var/log/syslog`, `/var/log/messages` или `journalctl` на Linux; `wevtutil` на Windows);
   - отправляет на сервер подписанные HMAC-запросы.

3. **База данных (Supabase PostgreSQL / локально SQLite fallback)**
   - таблицы: узлы, метрики, логи, агенты, триггеры, пользователи;
   - SQLAlchemy ORM;
   - автоматическое создание схемы при старте (`create_all`).

4. **Интеграция с Knowledge Base API (Hippocrates)**
   - backend запускает solve по запросу для выбранного узла (`GET /api/knowledge-base?node_id=...`);
   - перед solve сопоставляет активные триггеры узла с KB-объектами, обновляет preset `agent_preset`;
   - возвращает в UI результаты solve + диагностические поля (`active_triggers`, `matched_node_ids`, `last_updated`).

5. **LLM-интеграция через Ollama**
   - endpoint `POST /api/llm/analyze-node` собирает контекст узла (метрики, триггеры, логи, KB) и стримит ответ;
   - endpoint `POST /api/llm/generate` принимает произвольный prompt и возвращает полный ответ;
   - модель жёстко задана как `gemma4:e4b` (локальный Ollama API на `http://localhost:11434`).

---

## 2) Структура репозитория

```text
.
├── main.py                  # FastAPI приложение + встроенный dashboard HTML/JS
├── agent.py                 # Агент, сбор метрик/логов и отправка подписанных запросов
├── app/
│   ├── api/users.py         # Пример CRUD endpoints пользователей
│   ├── config.py            # Загрузка env и сборка DATABASE_URL
│   ├── db/                  # SQLAlchemy engine/session/base
│   ├── models/              # ORM модели (Node, Metric, LogEntry, Agent, Trigger, User)
│   ├── schemas/             # Pydantic-схемы для users
│   └── security/agent_auth.py # HMAC-аутентификация агентов
├── requirements.txt
├── .env.example
└── tests/
```

---

## 3) Подготовка окружения

## Требования

- Python **3.10+**
- Linux/macOS/Windows
- Доступ к PostgreSQL (Supabase) для production-сценария
- (для раздела LLM) установленный Ollama на сервере

### Установка зависимостей

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

---

## 4) Конфигурация `.env`

Скопируйте пример и заполните переменные:

```bash
cp .env.example .env
```

Ключевые переменные:

- `SUPABASE_DB_HOST`
- `SUPABASE_DB_PORT`
- `SUPABASE_DB_NAME`
- `SUPABASE_DB_USER`
- `SUPABASE_DB_PASSWORD`
- `KB_ID`
- `KB_JWT_TOKEN`
- `KB_API_BASE_URL` (опционально, по умолчанию `https://kb.ai-hippocrates.ru/kbapi`)
- `KB_PRESET_NAME` (опционально, по умолчанию `Monitoring server`)
- `SERVER_URL` (для агента)
- `AGENT_ID`, `AGENT_SECRET` (для агента)
- `DISPLAY_NAME`/`NODE_ID` (опционально для агента)

Если Supabase-переменные не заданы полностью, сервер автоматически уходит в локальный fallback:

- `sqlite:///./monitoring.db`

---

## 5) Запуск сервера

```bash
source .venv/bin/activate
uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```

После запуска:

- Dashboard: `http://127.0.0.1:8000/`
- OpenAPI docs: `http://127.0.0.1:8000/docs`

При старте вызывается `Base.metadata.create_all(...)` — таблицы создаются автоматически.

> Для production лучше добавить Alembic-миграции.

---

## 6) Как запустить агента

### Шаг 1. Зарегистрировать агента

Есть два способа:

1. Через UI: вкладка **Nodes** → **Register new node**
2. Через API:

```bash
curl -X POST http://127.0.0.1:8000/api/agents/register
```

Вы получите:

- `agent_id`
- `secret`

Сохраните их: `secret` показывается как рабочий ключ подписи.

### Шаг 2. Запустить `agent.py`

Вариант через аргументы:

```bash
python agent.py \
  --server-url http://127.0.0.1:8000 \
  --display-name node-1 \
  --agent-id <AGENT_ID> \
  --agent-secret <AGENT_SECRET> \
  --interval 60
```

Вариант через `.env`:

```env
SERVER_URL=http://127.0.0.1:8000
AGENT_ID=<AGENT_ID>
AGENT_SECRET=<AGENT_SECRET>
DISPLAY_NAME=node-1
```

И далее:

```bash
python agent.py
```

Что делает агент в цикле:

1. собирает метрики CPU/RAM;
2. собирает последние системные логи (до 100 записей);
3. отправляет метрики в `POST /api/agent/metrics`;
4. отправляет логи в `POST /api/agent/logs`;
5. спит `interval` секунд (по умолчанию 60).

---

## 7) Авторизация сервера и агента (HMAC)

### Какие заголовки обязательны

Агент отправляет:

- `X-Agent-ID`
- `X-Timestamp`
- `X-Signature`

### Как вычисляется подпись

Каноническая строка:

```text
METHOD + "\n" + PATH + "\n" + TIMESTAMP + "\n" + RAW_BODY
```

Далее:

- `HMAC_SHA256(agent_secret, canonical_payload)`
- hex-строка становится `X-Signature`.

### Что проверяет сервер

1. Все заголовки присутствуют;
2. `X-Timestamp` — это валидный `int`;
3. Временное окно: не старше/не младше 600 секунд относительно сервера;
4. Агент существует в таблице `agents`;
5. Агент не отключён (`enabled=true`);
6. Подпись совпадает (`hmac.compare_digest`);
7. При успехе обновляется `last_seen`.

Если проверка не проходит — сервер отвечает `401`/`403`/`400` в зависимости от причины.

### Важно про секрет

- Секрет хранится в БД в исходном виде, потому что нужен для HMAC-проверки входящего запроса.
- В production обязательно ограничивайте доступ к БД, используйте защищённые секреты и аудит доступа.

---

## 8) Supabase PostgreSQL: как подключено

Проект не использует Supabase SDK, а подключается к Supabase **как к обычному PostgreSQL** через `psycopg2` и SQLAlchemy.

`DATABASE_URL` собирается динамически:

```text
postgresql+psycopg2://USER:PASSWORD@HOST:PORT/DB
```

Если один из обязательных `SUPABASE_DB_*` параметров отсутствует — будет fallback на SQLite.

### Практические рекомендации

- Для production лучше использовать отдельного DB-пользователя с минимальными правами;
- включить TLS-подключение к Supabase (если требуется вашей конфигурацией);
- добавить регулярные бэкапы/снапшоты;
- для изменений схемы перейти с `create_all` на Alembic-миграции.

---

## 9) Dashboard: подробно про каждый раздел

В левом меню 8 разделов:

## 9.1 Latest data

Назначение: быстрый просмотр последних 10 точек метрик по выбранному узлу.

- выбираете node;
- кнопка `Refresh now` тянет данные;
- показываются CPU %, RAM %, timestamp (UTC), имя узла;
- API: `GET /api/metrics?node_id=...`.

## 9.2 Nodes

Назначение: инвентаризация узлов и управление агентами.

- список узлов с OS, CPU cores, RAM, IP, last_seen;
- отображается статус привязанного агента (enabled/disabled);
- кнопка `Register new node` создаёт новый `agent_id/secret`;
- доступны действия (через UI-меню): rename node, enable/disable agent, rotate secret, delete node.

Основные API:

- `GET /api/nodes`
- `PATCH /api/nodes/{node_id}`
- `DELETE /api/nodes/{node_id}`
- `GET /api/agents`
- `POST /api/agents/register`
- `POST /api/agents/{agent_id}/enable`
- `POST /api/agents/{agent_id}/disable`
- `POST /api/agents/{agent_id}/rotate-secret`

## 9.3 Graphs

Назначение: график динамики выбранной метрики за интервал.

- выбор node;
- выбор метрики: CPU или RAM;
- выбор интервала (5/15/30/60 минут);
- рендер SVG-графика на фронте.

API:

- `GET /api/metrics/history?node_id=...&metric_name=cpu_percent|ram_percent&interval_minutes=...`

## 9.4 Triggers

Назначение: правила срабатывания по метрикам и автоматизация типовых инцидентов.

- создаёте правило: node + метрика + оператор (`>`/`<`) + threshold;
- при создании триггера можно привязать исполняемый скрипт: он запускается при срабатывании правила и помогает автоматически устранять типовые проблемы на удалённых узлах;
- в веб-дашборде в поле выбора скрипта показываются все доступные файлы из директории `./scripts`;
- поддерживаемые типы скриптов: **Linux** — `.sh`, `.py`; **Windows** — `.ps1`, `.bat`, `.cmd`, `.py`;
- видите список правил с текущим статусом активности;
- можно редактировать имя и порог, удалять.

Как это использовать на практике:

1. Сложите рабочие автоматизации в `./scripts` на сервере мониторинга.
2. При создании триггера в UI выберите нужный скрипт из выпадающего списка.
3. Когда условие триггера выполнится, система запустит выбранный скрипт на соответствующем удалённом узле.

Примеры use-case:

- **Высокая загрузка RAM**: триггер `ram_percent > 90` запускает скрипт очистки временных файлов/кэша и перезапуска проблемного сервиса.
- **Высокая загрузка CPU**: триггер `cpu_percent > 95` запускает диагностический скрипт (снятие `top`/`ps`/логов) и отправку отчёта в централизованный лог.
- **Потеря критичного процесса на Windows**: триггер запускает `.ps1`/`.bat` для проверки статуса службы и её автоматического рестарта.

API:

- `POST /api/triggers`
- `GET /api/triggers`
- `PATCH /api/triggers/{trigger_id}`
- `DELETE /api/triggers/{trigger_id}`

## 9.5 Problems

Назначение: список только активных проблем (где trigger сейчас выполняется).

- агрегирует активные триггеры по всем узлам;
- показывает condition, latest value, время создания триггера.

API:

- `GET /api/problems`

## 9.6 Logs

Назначение: централизованный просмотр системных логов по узлу.

- агент отправляет до 100 записей за одну отправку;
- сервер хранит до 2000 логов на узел (старые обрезаются);
- UI показывает последние 100 записей.

API:

- `POST /api/agent/logs` (для агента, с подписью)
- `POST /api/logs` (прямой вариант без HMAC, полезно для тестов)
- `GET /api/logs?node_id=...`

## 9.7 Knowledge Base

Назначение: получить диагностические рекомендации из Hippocrates KB для **конкретного выбранного узла**.

Как это работает сейчас:

- UI отправляет `GET /api/knowledge-base?node_id=<display_name>` только по кнопке **Run KB solve**;
- backend находит активные триггеры этого узла (по последней метрике);
- backend получает список KB-объектов, сопоставляет их по имени с активными триггерами и собирает `matched_node_ids`;
- backend проверяет/создаёт preset `agent_preset`, обновляет его `nodesId` и запускает `solve`;
- UI показывает `status`, `last_updated`, `active_triggers`, `matched_node_ids`, таблицу результатов и `explanatorySet`.

Важно:

- при отсутствии `KB_ID` или `KB_JWT_TOKEN` endpoint возвращает `status=disabled`;
- при сетевой/HTTP ошибке к внешнему KB API endpoint возвращает `status=error` и текст ошибки;
- браузер не ходит напрямую во внешний KB API — только в локальный backend.

API:

- `GET /api/knowledge-base?node_id=...`

## 9.8 LLM

Назначение: запуск LLM-диагностики узла и получение структурированного ответа на русском языке.

- в UI выбирается узел и нажимается кнопка **Analyze node**;
- backend вызывает `POST /api/llm/analyze-node`, формирует payload из узла, последней метрики, активных триггеров, логов и KB-результатов;
- ответ от Ollama стримится в UI по мере генерации;
- для ручных/внешних интеграций остаётся endpoint `POST /api/llm/generate` (один prompt → один склеенный ответ);
- модель по умолчанию: **`gemma4:e4b`**.

---

## 10) Про API `kb.ai-hippocrates.ru`

В проекте используется базовый URL:

- `https://kb.ai-hippocrates.ru/kbapi`

Текущий поток вызовов для `GET /api/knowledge-base?node_id=...`:

1. `GET /api/Objects/GetAllObjects/{KB_ID}` — получить объекты KB;
2. `GET /api/Test/getPresets/{KB_ID}` — найти preset `agent_preset`;
3. при необходимости `POST /api/Test/savePresets` — создать preset;
4. `PUT /api/Test/update/{preset_id}` — обновить `nodesId` для preset;
5. `POST /solve/{KB_ID}` с `{"presetName":"agent_preset"}` — получить solve-результат.

Типовые заголовки:

- `Authorization: <KB_JWT_TOKEN>`
- `accept: */*` (или `text/plain` для некоторых endpoints KB)
- `Content-Type: application/json-patch+json` для `POST/PUT` с JSON-телом

Если `KB_ID` или `KB_JWT_TOKEN` не заданы, интеграция помечается как disabled, и `/api/knowledge-base` возвращает соответствующий статус.

---

## 11) Важно: для раздела LLM нужна модель Ollama `gemma4:e4b`

На сервере, где работает FastAPI, должен быть доступен локальный Ollama API на `localhost:11434`.

Минимальные шаги:

1. Установить Ollama;
2. запустить сервис Ollama;
3. скачать модель:

```bash
ollama pull gemma4:e4b
```

4. Проверить, что модель доступна:

```bash
ollama list
```

5. Проверить генерацию напрямую:

```bash
curl -X POST http://localhost:11434/api/generate \
  -H 'Content-Type: application/json' \
  -d '{"model":"gemma4:e4b","prompt":"Hello","stream":false}'
```

Если Ollama не запущен или модель не установлена, LLM endpoints (`/api/llm/analyze-node`, `/api/llm/generate`) вернут `502 LLM service error`.

---

## 12) Основные API эндпоинты проекта

### Метрики

- `POST /api/metrics` (без HMAC)
- `POST /api/agent/metrics` (с HMAC)
- `GET /api/metrics`
- `GET /api/metrics/history`

### Логи

- `POST /api/logs`
- `POST /api/agent/logs`
- `GET /api/logs`

### Узлы и агенты

- `GET /api/nodes`
- `PATCH /api/nodes/{node_id}`
- `DELETE /api/nodes/{node_id}`
- `GET /api/agents`
- `POST /api/agents/register`
- `POST /api/agents/{agent_id}/enable`
- `POST /api/agents/{agent_id}/disable`
- `POST /api/agents/{agent_id}/rotate-secret`

### Триггеры и проблемы

- `POST /api/triggers`
- `PATCH /api/triggers/{trigger_id}`
- `DELETE /api/triggers/{trigger_id}`
- `GET /api/triggers`
- `GET /api/problems`

### Интеграции

- `GET /api/knowledge-base`
- `POST /api/llm/generate`

### Служебные

- `GET /` — dashboard
- `GET /docs` — Swagger UI

---

## 13) Быстрая диагностика

### Агент не отправляет данные

Проверьте:

- корректный `SERVER_URL`;
- правильные `AGENT_ID`/`AGENT_SECRET`;
- не отключён ли агент (`enabled=false`);
- синхронность времени на сервере и узле (важно для `X-Timestamp`);
- доступность сервера по сети.

### Нет данных в Knowledge Base

Проверьте:

- задан ли `node_id` в запросе `/api/knowledge-base`;
- заданы ли `KB_ID` и `KB_JWT_TOKEN`;
- доступны ли KB endpoints (`GetAllObjects`, `getPresets`, `update`, `solve`) из сети сервера;
- совпадают ли имена активных trigger'ов с именами объектов в KB (иначе `matched_node_ids` будет пустым).

### Не работает LLM

Проверьте:

- запущен ли Ollama на том же сервере;
- что `ollama list` содержит `gemma4:e4b`;
- что `http://localhost:11434/api/generate` отвечает.

---

## 14) Примечания для production

- Вынести UI из строки в `main.py` в отдельные шаблоны/статические файлы;
- добавить полноценную аутентификацию пользователей dashboard (сейчас сервер открыт, а HMAC применяется к agent-endpoints);
- внедрить Alembic миграции;
- добавить retry/backoff и метрики для внешних интеграций (KB, Ollama);
- централизованно логировать ошибки и аудит действий с агентами.

