# Server API 中文说明

## 启动

先设置管理员 Token，再启动服务：

```powershell
$env:SERVER_API_ADMIN_TOKEN="请改成足够长的随机值"
.\.venv\Scripts\python.exe -m uvicorn server_api.main:app --host 0.0.0.0 --port 9000
```

打开 `http://服务器地址:9000/admin/tokens`，输入管理员 Token，为客户端生成独立 Token。原始客户端 Token 只显示一次。

数据库默认保存在 `server_api/data/server_api.db`。

## 客户端接入

客户端请求统一携带：

```http
X-Client-Token: 服务端分发的客户端Token
X-Account-MD5: 当前本地账号MD5
```

首次调用 `POST /api/join` 时，服务端会把该 Token 与 `account_md5` 绑定；之后 Token 不能操作未绑定账号。

`GET /api/next` 返回：

```json
{
  "task_id": "一次性任务ID",
  "play_token": "一次性播放凭证",
  "netease_item_id": "歌曲或专辑ID",
  "expires_in": 1800
}
```

完成播放后提交：

```http
POST /api/play/finish
```

```json
{
  "account_md5": "当前客户端账号MD5",
  "netease_item_id": "api/next返回的ID",
  "task_id": "api/next返回的task_id",
  "play_token": "api/next返回的play_token"
}
```

任务凭证只能使用一次，且绑定客户端、账号、目标歌曲并在 30 分钟后过期。重复、伪造或错配提交会被拒绝并计入风险分。

## 风控

- 每个客户端和 IP 均有分钟级频率限制。
- 同一账号最多保留两个未完成任务。
- 重放、伪造任务、操作未绑定账号和频率超限会产生风险事件。
- 风险分达到 5 时标记为可疑，达到 10 时自动隔离客户端。
- 管理员可通过 `/api/admin/client-tokens`、`/api/admin/risk-events` 查看状态，通过 `release` 或 `revoke` 处理客户端。

公共互助可能触发平台风控。服务提供者和客户端用户都应控制频率，只向可信客户端分发 Token，并自行承担账号风险。
