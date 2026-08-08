# Server API 中文说明

## 启动

在项目根目录执行：

```powershell
.\.venv\Scripts\python.exe -m uvicorn server_api.main:app --host 0.0.0.0 --port 9000
```

数据库默认位置：

```text
server_api/data/server_api.db
```

## 主要接口

### 注册或重新启用

```http
POST /api/join
```

请求体：

```json
{
  "account_md5": "账号MD5",
  "apikey": "服务端规则生成的apikey",
  "daily_listen_limit": 100,
  "monthly_listen_limit": 3000
}
```

新账号默认启用。已关闭账号再次调用 `join` 后重新启用。

### 更新歌曲和限制

```http
POST /api/update
X-API-Key: 当前账号apikey
```

可更新：

```text
netease_item_id
daily_listen_limit
monthly_listen_limit
```

该接口不能修改计数和 `enabled`。

### 获取下一首音乐

```http
GET /api/next
X-API-Key: 数据库中任意apikey
```

服务端会跳过：

- 当天没有听过歌的账号
- 达到当天被听上限的音乐
- 达到当月被听上限的音乐
- `enabled=0` 的账号

### 播放完成

```http
POST /api/play/finish
X-API-Key: 数据库中任意apikey
```

请求体：

```json
{
  "account_md5": "账号MD5",
  "netease_item_id": "歌曲或专辑ID"
}
```

播放完成后，服务端自动更新当天、当月和累计计数。

### 查询账号

```http
GET /api/listen-records/{account_md5}
X-API-Key: 当前账号apikey
```

账号关闭或不存在时返回：

```http
404 record not found
```

### 关闭账号

```http
DELETE /api/listen-records/{account_md5}
X-API-Key: 当前账号apikey
```
