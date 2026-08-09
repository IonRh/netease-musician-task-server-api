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
X-API-Key: 当前客户端账号apikey
```

服务端会跳过：

- 当前客户端账号自己的歌曲或专辑
- 当天没有听过歌的账号
- 达到当天被听上限的音乐
- 达到当月被听上限的音乐
- `enabled=0` 的账号

如果严格筛选后没有可播放记录，接口会进入初始化兜底，允许选择当天
尚未听过歌的账号，避免新的一天所有计数为 0 时无法开始播放。

### 播放完成

```http
POST /api/play/finish
X-API-Key: 当前客户端账号apikey
```

请求体：

```json
{
  "account_md5": "当前客户端账号MD5",
  "netease_item_id": "api/next 返回的歌曲或专辑ID"
}
```

播放完成后，服务端增加当前客户端账号的听歌计数，并增加对应歌曲的
被听计数。

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
