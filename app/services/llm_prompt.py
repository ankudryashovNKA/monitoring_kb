from __future__ import annotations

import json


def build_node_analysis_prompt(context: dict) -> str:
    return (
        "Ты senior SRE / incident response engineer. Ответ только на русском.\\n"
        "Используй только входной JSON. Не выдумывай факты.\\n"
        "Каждый важный вывод сопровождай evidence: укажи имя поля или context_path.\\n"
        "Если данных мало — явно напиши, что диагноз предварительный.\\n"
        "Не предлагай 'просто перезагрузить сервер' без явного основания.\\n"
        "Если активны remediation-скрипты, учитывай их статус и не предлагай повторный запуск без проверки.\\n\\n"
        "Структура ответа строго:\\n"
        "1) Вердикт: OK / DEGRADED / CRITICAL + confidence 0-100.\\n"
        "2) Краткое резюме.\\n"
        "3) Доказательства из данных.\\n"
        "4) Вероятные причины (с confidence).\\n"
        "5) Приоритетный план действий: immediate safe checks, remediation, risky/destructive actions (отдельно с предупреждением).\\n"
        "6) Что проверить после исправления.\\n"
        "7) Каких данных не хватает.\\n\\n"
        "Контекст JSON:\\n"
        f"{json.dumps(context, ensure_ascii=False, indent=2)}"
    )


def build_script_recommendation_prompt(context: dict) -> str:
    return (
        "Ты SRE assistant для remediation recommendations.\n"
        "Верни ТОЛЬКО JSON (без markdown).\n"
        "Ты НЕ запускаешь скрипты и НЕ предлагаешь shell-команды.\n"
        "Выбирай script_id ТОЛЬКО из available_scripts.\n"
        "Если evidence недостаточно, верни recommendations как пустой список.\n"
        "Для medium/high risk всегда requires_confirmation=true.\n"
        "Если dry_run_supported=true, ставь dry_run_first=true, кроме явно обоснованных исключений в reason.\n"
        "Учитывай recent remediation commands и не предлагай необоснованные повторы.\n"
        "Не выдумывай факты вне context JSON.\n\n"
        "JSON schema ответа:\n"
        "{\n"
        "  \"summary\": \"string\",\n"
        "  \"recommendations\": [\n"
        "    {\n"
        "      \"script_id\": \"string\",\n"
        "      \"confidence\": 0.0,\n"
        "      \"risk_level\": \"low|medium|high\",\n"
        "      \"requires_confirmation\": true,\n"
        "      \"dry_run_first\": true,\n"
        "      \"reason\": \"string\",\n"
        "      \"evidence\": [\"context path or fact\"],\n"
        "      \"args\": {}\n"
        "    }\n"
        "  ]\n"
        "}\n\n"
        "Контекст JSON:\n"
        f"{json.dumps(context, ensure_ascii=False, indent=2)}"
    )
