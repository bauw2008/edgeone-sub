# 环境变量说明

## KV 存储绑定

| 变量名 | 说明 |
|--------|------|
| NODES_KV | KV 存储命名空间，用于存储数据 |

### KV 存储的 Key

| Key | 说明 |
|-----|------|
| nodes_data | 存储聚合数据 |
| subscribelinks_data | 存储订阅链接数据 |

## 环境变量

| 变量名 | 说明 |
|--------|------|
| ADMIN_PASSWORD | 管理员登录密码 |
| CLASH_CONVERT_API | Clash 转换 API（可选，默认使用 v2ray2clash.netlify.app） |