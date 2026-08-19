# Server API

Standalone FastAPI service for Netease music listen records.

中文文档：[`README_CN.md`](README_CN.md)

## Start

From the project root:

```powershell
$env:SERVER_API_ADMIN_TOKEN="replace-with-a-long-random-secret"
.\.venv\Scripts\python.exe -m uvicorn server_api.main:app --host 0.0.0.0 --port 9000
```

From inside `server_api`:

```powershell
..\.venv\Scripts\python.exe -m uvicorn main:app --host 0.0.0.0 --port 9000
```

Database: `server_api/data/server_api.db`

Open `http://localhost:9000/admin/tokens` to create independent client tokens. Clients use `X-Client-Token` and `X-Account-MD5`; `/api/next` returns a one-time task token that `/api/play/finish` must consume exactly once.
