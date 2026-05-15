# ddns-manager v1.6.0 证书部署测试方法

> 无需等待证书过期，随时验证部署链路正确性。

## 测试环境

| 节点 | IP | 角色 |
|------|-----|------|
| Win2022 | 10.0.0.3 | Windows IIS 多站点 |
| sp.example.com | 10.0.0.5 | Windows IIS 单站点 |

## 测试 1：强制推送证书（验证全链路）

### 目的
验证证书从 Manager → Agent 解密 → 导入 → IIS 绑定 全链路。

### 步骤

```bash
# 1. 清空目标节点的 cert_hashes，强制下次心跳推送
TOKEN="xxx"
curl -sk -X POST \
  "https://manager.example.com:30443/api/admin/certs/acme-sp.example.com/push/sp.example.com" \
  -H "Authorization: Bearer $TOKEN"
# 预期: {"status":"force_pushed","next":"等待节点下次心跳自动拉取证书"}

# 2. 等待 5 分钟（节点心跳周期）

# 3. 查看 Manager 日志
ssh lsj@10.0.0.1 "sudo grep 'sp.example.com' /opt/ddns-manager/data/events.log | tail -20"
```

### 预期事件

```
✅ cert={name} 解密 cert.pfx (xxx bytes) → 成功
✅ cert={name} 写入 N 个文件 → C:\ddns-agent\certs\{name}\
✅ cert={name} certutil 导入 cert.pfx → 成功 (指纹=xxx...)
✅ cert={name} IIS绑定: hostname:443 CN=xxx → 匹配更新
✅ cert={name} 部署完成 → hash=sha256:xxx...
```

### 失败场景检验

```
❌ cert={name} certutil导入失败: 0x80070056 (密码错误) → ddns兜底→成功
⚠️ cert={name} CN=*.xxx 未匹配IIS绑定 → 需管理员手动绑定
❌ cert={name} 解密 cert.pfx 失败: bad decrypt
```

## 测试 2：IIS 快照上报

### 目的
验证 Agent 正确扫描 IIS 现有 SSL 绑定并上报。

### 步骤

```bash
# 查看节点 IIS 绑定快照
curl -sk "https://manager.example.com:30443/api/admin/nodes/sp.example.com" \
  -H "Authorization: Bearer $TOKEN" | python3 -m json.tool | grep -A10 iis_bound_sites
```

### 预期

```json
"iis_bound_sites": [
  {"hostname": "sp.example.com", "port": 443, "thumbprint": "2f0823ab..."},
  {"hostname": "0.0.0.0", "port": 443, "thumbprint": "54317eb0..."}
]
```

## 测试 3：Fits() 匹配验证

### 目的
验证三级 hostname 匹配规则。

### 测试用例

| IIS 绑定 | 证书 CN | 预期匹配 | 预期分数 |
|----------|---------|---------|---------|
| sp.example.com | sp.example.com | 精确匹配 | 100 |
| *.example.com | a.example.com | IIS泛域名→证书 | 50 |
| a.example.com | *.example.com | 证书泛域名→IIS | 90 |
| sp.example.com | xxx.other.com | 不匹配 | 0 |
| (空) 0.0.0.0:443 | 任意 | 默认(无SNI) | 10 |

### 步骤

日志中查找匹配度报告：
```
证书部署: IIS绑定 sp.example.com:443 CN=sp.example.com 匹配度=100(精确匹配)
```

## 测试 4：多站点证书隔离

### 目的
验证不同证书部署到不同子目录，不会互相覆盖。

### 步骤

```bash
# 检查 Agent 证书目录结构
dir C:\ddns-agent\certs\
# 预期:
#   acme-sp.example.com\    ← cert.pfx, cert.pem, fullchain.pem, ...
#   acme-*.example.com\     ← cert.pfx, cert.pem, fullchain.pem, ...
```

## 测试 5：Manager 终止重复推送

### 目的
验证证书 hash 匹配后 Manager 不再推送。

### 步骤

```bash
# 1. 强制推送并等待部署完成
# 2. 再次查看证书事件
ssh lsj@10.0.0.1 "sudo grep 'sp.example.com.*证书已下发' /opt/ddns-manager/data/events.log | tail -5"
# 预期: 只有1条新的"证书已下发"（hash匹配后不再推送）
```

## 测试 6：密码错误兜底

### 目的
验证 PFX 密码不匹配时 ddns 兜底重试。

### 步骤

日志中查找：
```
certutil 密码错误(0x80070056), 尝试 ddns 兜底
certutil ddns兜底导入成功
```

## 结果判定

| 结果 | 含义 |
|------|------|
| `[ok]` 证书部署完成 + hash=... | 全链路成功 |
| `[warn]` 未匹配IIS绑定 | 管理员需手动绑定(正常) |
| `[error]` certutil/ddns均失败 | 需排查 certutil/PFX/权限 |
