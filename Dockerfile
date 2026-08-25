FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
# Единственный контейнер, до которого достаёт интернет, работает не под root.
# /app только читается (миграции — файлы образа), в БД пишем по сети, порт 8020 > 1024 —
# прав root ничему из этого не нужно.
RUN useradd --system --uid 10001 --no-create-home app
USER app
EXPOSE 8020
# --no-access-log: verify token Meta присылает в query-строке handshake, а access-лог
# uvicorn пишет request line целиком — секрет осел бы в docker logs на общем хосте.
# --limit-concurrency: висящие тела держат память по соединению, а потолок памяти
# у контейнера жёсткий — 64 одновременных запроса делают его арифметическим,
# лишнее получает 503 (Meta ретраит) вместо OOM-петли и потока 502 от Caddy.
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8020", \
     "--no-access-log", "--limit-concurrency", "64"]
