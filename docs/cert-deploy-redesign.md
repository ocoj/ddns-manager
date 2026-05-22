# 客户端证书更新逻辑 — 完整重构方案

> v1.6.0 | 2026-05-15 | 设计参考：win-acme | 对齐原则：每步可观测、每错可追溯

## 1. 设计原则

| 原则 | 说明 |
|------|------|
| **全链路日志** | 每个步骤的成功/失败/跳过都通过 `agentLog` 上报 Manager |
| **分阶段执行** | 发现 → 接收 → 导入 → 绑定 → 重载 → 清理，每阶段独立上报 |
| **不新建绑定** | Agent **只更新**已有 IIS 绑定，**不创建**新绑定（管理员手动做初始绑定） |
| **原子切换** | 证书文件先写 `.new` 后缀，`os.Rename` 原子切到正式名 |
| **回退安全** | 任何步骤失败不影响已成功的步骤，下次心跳自动重试 |

## 2. 整体流程

```
┌─ Heartbeat ────────────────────────────────────────────────────────┐
│                                                                     │
│  Phase 0: 发现 (Discovery)                                          │
│  ├─ scanCertDir()     → 扫描 CertPath 下各 bundle 子目录            │
│  ├─ scanIISBindings() → netsh http show sslcert 读取已有绑定        │
│  └─ 上报 cert_hashes map, cert_bound_sites list                     │
│                                                                     │
│  Phase 1: 接收 (Receive)  ←── Manager 下发 CertUpdate[]            │
│  ├─ 解密文件 → os.WriteFile(.new) → os.Rename → 正式文件            │
│  └─ 每文件日志: 写入成功/解密失败/磁盘满                              │
│                                                                     │
│  Phase 2: 导入 (Import)  ←── Windows only                          │
│  ├─ certutil -importpfx → Windows 证书存储                          │
│  ├─ certutil -dump -p → 提取指纹                                    │
│  └─ 日志: 导入成功/密码错误(0x80070056)/certutil不可用                │
│                                                                     │
│  Phase 3: 绑定 (Bind)    ←── Windows only                          │
│  ├─ netsh http show sslcert → 扫描现有 IIS 绑定                     │
│  ├─ 按 CN/SAN 匹配 → 只更新匹配的绑定                                │
│  └─ 日志: 绑定更新成功(N个)/未找到匹配绑定/无IIS绑定存在               │
│                                                                     │
│  Phase 4: 重载 (Reload)                                             │
│  ├─ systemctl reload / sc stop/start                               │
│  ├─ IIS appcmd recycle apppool                                     │
│  └─ 日志: 重载成功/失败(服务名)                                       │
│                                                                     │
│  Phase 5: 清理 (Cleanup)                                            │
│  ├─ certutil -delstore → 删除旧证书                                  │
│  ├─ os.RemoveAll → 清理不再推送的 bundle 子目录                       │
│  └─ 日志: 清理N个旧证书/清理N个旧目录                                 │
│                                                                     │
│  Phase 6: 标记 (Mark)                                               │
│  ├─ 写入 .cert_hash 文件                                            │
│  └─ 日志: 部署完成 + hash + 路径                                      │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

## 3. 数据结构

### 3.1 心跳上报新增字段

```go
type NodeStatus struct {
    // ... 现有字段 ...
    
    // v1.6.0: IIS 绑定状态 (Windows only)
    IISBoundSites []IISBoundSite `json:"iis_bound_sites,omitempty"`
}

type IISBoundSite struct {
    Hostname string `json:"hostname"`    // SNI hostname or IP
    Port     int    `json:"port"`
    CertHash string `json:"cert_hash"`   // SHA1 thumbprint of current IIS cert
    BundleName string `json:"bundle_name,omitempty"` // 匹配到的 bundle (如 acme-sp.example.com)
    Status   string `json:"status"`      // "matched" | "unknown" | "outdated"
}
```

### 3.2 AgentLog 日志分类

```
category=cert-deploy  证书部署全链路日志
  action: receive / import / bind / reload / cleanup / complete / error
  detail: 具体操作描述 + 成功/失败原因
```

> **实现差异**: 设计方案中 `HeartbeatReq.IISSnapshot` 在代码实现时并入 `NodeStatus.IISBoundSites`（json:"iis_bound_sites"），字段名和嵌套位置均不同。IIS 绑定快照由 Agent 心跳时通过 `NodeStatus.IISBoundSites` 上报。

## 4. 各阶段详细日志规范

### Phase 0: 发现

```
[ok]    发现 2 个证书集 (CertPath), 1 个 IIS 绑定
[info]  cert=acme-sp.example.com hash=sha256:1706e17... (disk)
[info]  cert=acme-*.example.com hash=sha256:e74f631... (disk)
[info]  IIS: hostname=sp.example.com:443 thumb=2f0823ab... bundle=acme-sp.example.com matched
```

### Phase 1: 接收

```
[ok]    收到 1 个证书更新
[info]  cert=acme-sp.example.com 解密 cert.pfx (2576 bytes) → 成功
[info]  cert=acme-sp.example.com 解密 fullchain.pem (2848 bytes) → 成功
[info]  cert=acme-sp.example.com 写入 5 个文件 → C:\ddns-agent\certs\acme-sp.example.com\
[error] cert=acme-sp.example.com 解密 cert.pfx 失败: bad decrypt → 跳过此文件
```

### Phase 2: 导入

```
[info]  cert=acme-sp.example.com certutil 导入 cert.pfx → 成功 (指纹=2f0823ab...)
[error] cert=acme-sp.example.com certutil 导入失败: 0x80070056 (ERROR_INVALID_PASSWORD)
[info]  cert=acme-sp.example.com 密码错误, 尝试 ddns 兜底 → 成功
[error] cert=acme-sp.example.com certutil 不可用: exec: "certutil": not found
```

### Phase 3: 绑定

```
[info]  cert=acme-sp.example.com IIS现有绑定: sp.example.com:443 → 匹配 CN=sp.example.com → 更新
[ok]    cert=acme-sp.example.com IIS绑定更新: 1 个绑定已更新, 0 个失败
[warn]  cert=acme-*.example.com CN=*.example.com 未匹配到任何IIS绑定 → 跳过(需管理员手动绑定)
[info]  cert=xxx IIS无SSL绑定存在 → 无操作
```

### Phase 4: 重载

```
[info]  nginx 服务重载成功
[error] iis-apppool 服务重载失败: 服务不存在
[ok]    服务重载完成: 1 成功, 1 失败
```

### Phase 5: 清理

```
[info]  certutil 删除旧证书: CN=sp.example.com (旧指纹=abcd1234...)
[info]  清理旧证书目录: acme-sp.example.com.bak
[ok]    清理完成: 1 个旧证书, 1 个旧目录
```

### Phase 6: 标记

```
[ok]    cert=acme-sp.example.com 部署完成 → hash=sha256:1706e17... path=C:\ddns-agent\certs\acme-sp.example.com\
```

## 5. 代码重构清单

### 5.1 函数拆分 (cmd/agent/main.go)

| 函数 | 职责 | 日志 |
|------|------|------|
| `certPhaseReceive(cu) []error` | 解密+写入文件 | 每文件解密/写入结果 |
| `certPhaseImport(pfxFile, pfxPwd, cn) (thumb, bool)` | certutil 导入 | 导入成功/密码错误/certutil不可用 |
| `certPhaseBind(thumb, cn, bindings) int` | IIS 绑定更新 | 匹配到N个绑定/更新成功N个/无匹配 |
| `certPhaseReload(services) []error` | 服务重载 | 每服务重载结果 |
| `certPhaseCleanup(oldCerts, oldDirs) int` | 清理旧证书和目录 | 清理数量 |
| `certPhaseMark(path, hash)` | 写入 .cert_hash | 写入成功/失败 |

### 5.2 新增函数

| 函数 | 职责 |
|------|------|
| `scanIISBindings() []IISBoundSite` | netsh http show sslcert 解析 |
| `matchIISBinding(thumb, cn string, bindings []IISBoundSite) []IISBoundSite` | CN 匹配 |

### 5.3 主流程 (applyCertUpdates)

```go
func applyCertUpdates(cfg, updates) (certErrors, certHashes, boundSites) {
    for _, cu := range updates {
        // Phase 1: 接收
        written := certPhaseReceive(cu)
        
        // Phase 2: 导入 (Windows only)
        if runtime.GOOS == "windows" {
            thumb, ok := certPhaseImport(pfxFile, pfxPwd, bundleName)
            if !ok { continue }
            
            // Phase 3: 绑定
            count := certPhaseBind(thumb, certCN, iisBindings)
            boundSites = append(boundSites, ...)
        }
        
        // Phase 4: 重载
        certPhaseReload(cu.ReloadServices)
        
        // Phase 5: 清理
        certPhaseCleanup(...)
        
        // Phase 6: 标记
        certPhaseMark(path, cu.CertHash)
        certHashes[cu.BundleName] = cu.CertHash
    }
}
```

## 6. HeartbeatReq 扩展

```go
type HeartbeatReq struct {
    // ... 现有字段 ...
    
    // v1.6.0: IIS 绑定快照
    IISSnapshot []IISBindingSnapshot `json:"iis_snapshot,omitempty"`
}

type IISBindingSnapshot struct {
    Hostname string `json:"hostname"`
    Port     int    `json:"port"`
    Thumb    string `json:"thumb"`        // SHA1 in IIS
    Status   string `json:"status"`       // "matched"/"unknown"
    BundleName string `json:"bundle,omitempty"`
}
```

## 7. 日志级别定义

| 前缀 | 含义 | 示例 |
|------|------|------|
| `[ok]` | 阶段成功 | `[ok] 证书部署完成` |
| `[info]` | 中间步骤 | `[info] 解密文件 cert.pfx` |
| `[warn]` | 非致命问题 | `[warn] 未匹配到IIS绑定` |
| `[error]` | 阶段失败 | `[error] certutil导入失败: 密码错误` |
| `[skip]` | 跳过 | `[skip] Linux跳过IIS绑定` |

## 8. Manager 端同步日志

Manager 收到心跳后，除了现有的 `cert` category 日志，新增：

```
category=cert-deploy  客户端证书部署摘要
  detail: "bundle=acme-sp.example.com phase=ok iis=1 bound=sp.example.com:443"
           "bundle=acme-*.example.com phase=bind iis=0 warn=未匹配到IIS绑定"
```

## 9. 实施计划

| 步骤 | 内容 | 预估行数 |
|------|------|---------|
| 1 | `applyCertUpdates` 拆分为 6 个 Phase 函数 | +60 |
| 2 | 新增 `scanIISBindings` `matchIISBinding` | +50 |
| 3 | 每 Phase 增加 agentLog 上报 | +30 |
| 4 | HeartbeatReq 增加 `IISSnapshot` 字段 | +20 |
| 5 | `collectCertHashes` 对齐子目录结构 | +15 |
| 6 | Manager 端 heartbeat 处理新增日志 | +20 |
| 7 | 单元测试 (每 Phase) | +80 |
| **合计** | | **~275 行** |
