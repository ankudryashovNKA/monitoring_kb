# Monitoring KB MVP

MVP системы мониторинга состоит из:

- **FastAPI-сервера**, который принимает метрики CPU/RAM от удалённых узлов;
- **агента** на `psutil`, который раз в минуту собирает данные и отправляет их на сервер;
- **веб-дашборда** с левым скрываемым меню и вкладками `Latest data` / `Nodes`.

## Что реализовано

- Приём метрик через `POST /api/metrics`.
- Хранение метрик в SQLite-базе в течение **1 часа** с сохранением между перезапусками сервера.
- Получение последних значений через `GET /api/metrics`.
- Получение списка узлов и их параметров через `GET /api/nodes`.
- Переименование узла через `PATCH /api/nodes/{node_id}`.
- Дашборд с выбором узла для просмотра **10 последних записей** и отдельной вкладкой со всеми узлами.

## Запуск сервера

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
MONITORING_DB_PATH=./data/monitoring.db uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```

## Запуск агента

```bash
python agent.py --server-url http://127.0.0.1:8000 --node-id node-1
```

По умолчанию агент отправляет данные каждые **60 секунд**.

## API

### Отправка метрик

```bash
curl -X POST http://127.0.0.1:8000/api/metrics \
  -H 'Content-Type: application/json' \
  -d '{
    "node_id": "node-1",
    "cpu_percent": 17.2,
    "ram_percent": 46.8,
    "os_name": "Ubuntu 24.04",
    "cpu_cores": 8,
    "ram_total_mb": 16384,
    "ip_address": "10.0.0.15"
  }'
```

### Получение последних метрик

```bash
curl http://127.0.0.1:8000/api/metrics
curl http://127.0.0.1:8000/api/metrics?node_id=node-1
```

### Получение списка узлов

```bash
curl http://127.0.0.1:8000/api/nodes
```

### Переименование узла

```bash
curl -X PATCH http://127.0.0.1:8000/api/nodes/node-1 \
  -H 'Content-Type: application/json' \
  -d '{"display_name": "Primary node"}'
```

## Хранение данных

- По умолчанию сервер создаёт SQLite-файл `monitoring.db` в рабочей директории.
- Можно указать свой путь через переменную окружения `MONITORING_DB_PATH`, например `MONITORING_DB_PATH=./data/monitoring.db`.
- Метрики автоматически очищаются из БД спустя **1 час**, а карточки узлов и их имена сохраняются между перезапусками.

## Ограничения MVP

- Нет аутентификации агентов.
- Используется SQLite, без репликации и горизонтального масштабирования.
