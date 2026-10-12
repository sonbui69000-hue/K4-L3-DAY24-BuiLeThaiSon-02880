# Baseline

1. No. `_naive_loop()` receives only a message and an LLM. It has no run ID, agent ID, or user permission check. See `agent/loop.py:27-39`.

2. No policy checks purpose, permission, or data type before the POST. The injection result controls the flow, while `tools.http_post()` only checks the localhost URL. See `agent/loop.py:34-44` and `agent/tools.py:68-84`.

3. The POST body is created at `agent/loop.py:44` as `{"records": collected}`. `sink/sink.py:42-47` writes each received body to `reports/sink.log`.
