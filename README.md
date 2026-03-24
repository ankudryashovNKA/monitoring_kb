# Monitoring KB MVP

MVP системы мониторинга состоит из:

- **FastAPI-сервера**, который принимает метрики CPU/RAM от удалённых узлов;
- **агента** на `psutil`, который раз в минуту собирает данные и отправляет их на сервер;
- **веб-дашборда** с левым скрываемым меню и вкладками `Latest data` / `Nodes`;
- **SQLAlchemy-подключения к Supabase PostgreSQL** и CRUD-примеров для `User`.

## Что реализовано

- Приём метрик через `POST /api/metrics`.
- Хранение метрик в памяти сервера в течение **1 часа**.
- Получение последних значений через `GET /api/metrics`.
- Получение списка узлов и их параметров через `GET /api/nodes`.
- Переименование узла через `PATCH /api/nodes/{node_id}`.
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

## Запуск агента

```bash
python agent.py --server-url http://127.0.0.1:8000 --node-id node-1
```

По умолчанию агент отправляет данные каждые **60 секунд**.

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
