# ddns-manager 多 DNS 配置重构方案

> 创建: 2026-05-23 | 状态: 待审核

---

## 一、现状分析

### 1.1 当前节点配置模型

```
NodeRecord (管理端存储)
├─ ConfigYAML: string   ← 一段 YAML，推到 Agent
│
│  YAML 内容 (对应 ddns-go Config):
│  ├─ dns_key_name: "阿里云-生产"
│  ├─ ipv4: {enable, gettype, url, netInterface, domains[...]}
│  ├─ ipv6: {enable, gettype, url, netInterface, domains[...]}
│  └─ cert_bindings: [{bundle_name, deploy_path, reload_services}]
│
│  问题: ipv4/ipv6 只能配一套，所有域名共享同一个 DNS Key 和获取方式
```

### 1.2 当前前端 UI

节点配置弹窗是一个**单页表单**：
- 1 个 DNS Key 下拉
- 1 组 IPv4 设置（启用/方式/参数/域名）
- 1 组 IPv6 设置（启用/方式/参数/域名）
- N 个证书绑定

**问题**：无法实现「阿里云 A 记录 + Cloudflare AAAA 记录」这种容错组合。

### 1.3 ddns-go 原生能力

ddns-go 的 `Config.DnsConf` 本身就是 `[]DnsConfig` 数组，每段独立：

```go
type DnsConfig struct {
    Name          string    // 配置段名称
    DNS           DNS       // {Name, ID, Secret} — DNS 提供商
    Ipv4          {Enable, GetType, URL, NetInterface, Cmd, Domains}
    Ipv6          {Enable, GetType, URL, NetInterface, Ipv6Reg, Domains}
    TTL           string
    HttpInterface string
}
```

ddns-go 原生就是**多段、每段独立**的——我们的管理端把它压扁成单段了。

---

## 二、改造目标

**管理端 UI → 多卡片，每卡片映射一段 DnsConfig。证书部署 → 节点统一配置。**

---

## 三、数据模型变更

### 3.1 新 NodeRecord 配置结构

```yaml
# 节点配置 YAML (新格式)
ipv4_enabled: true          # 全局: Agent 是否上报 IPv4 公网地址
ipv6_enabled: true          # 全局: Agent 是否上报 IPv6 公网地址
dns_confs:                  # DNS 配置卡片列表 (对应 ddns-go DnsConf[])
  - name: "阿里云-主"
    dns_key: "aliyun-prod"  # 引用的 DNS Key 名称
    ipv4:
      enable: true
      gettype: netInterface  # url | netInterface | cmd
      url: ""
      netInterface: eth0
      cmd: ""
      domains:
        - manager.example.com
        - oof.example.org
    ipv6:
      enable: true
      gettype: url
      url: "https://api6.ipify.org"
      ipv6reg: ""
      domains:
        - manager.example.com
        - oof.example.org
    ttl: "600"
  
  - name: "Cloudflare-备"
    dns_key: "cf-backup"
    ipv4:
      enable: false
    ipv6:
      enable: true
      gettype: netInterface
      netInterface: eth0
      domains:
        - backup.example.com
    ttl: "300"

cert_bindings:              # 证书部署 (节点统一, 不跟 DNS 卡片)
  - bundle_name: "manager.example.com"
    deploy_path: "C:\\ddns-agent\\certs"
    reload_services: ["nginx"]
```

### 3.2 NodeRecord 存储字段

```
NodeRecord 不变，ConfigYAML 字段内容从旧格式变为新格式。
新格式含 dns_confs 数组，向后兼容：无 dns_confs 时回退旧字段。
```

### 3.3 Agent 侧 (生成的 ddns-go Config)

```yaml
# 推送到 Agent 的 agent.yaml (由管理端根据 dns_confs 渲染)
dnsconf:
  - name: 阿里云-主
    dns:
      name: alidns
      id: "LTAI5t..."
      secret: "..."
    ipv4:
      enable: true
      gettype: netInterface
      netinterface: eth0
      domains: [manager.example.com, oof.example.org]
    ipv6:
      enable: true
      gettype: url
      url: "https://api6.ipify.org"
      domains: [manager.example.com, oof.example.org]
    ttl: "600"
  
  - name: Cloudflare-备
    dns:
      name: cloudflare
      id: "..."
      secret: "..."
    ipv4:
      enable: false
    ipv6:
      enable: true
      gettype: netInterface
      netinterface: eth0
      domains: [backup.example.com]
    ttl: "300"

ipv4_enabled: true
ipv6_enabled: true
cert_bindings:
  - bundle_name: "manager.example.com"
    deploy_path: "C:\\ddns-agent\\certs"
    reload_services: ["nginx"]
```

---

## 四、前端 UI 设计

### 4.1 节点配置弹窗 — 多卡片布局

```
┌─────────────────────────────────────────────────────┐
│  节点配置: Win2022                          [×]      │
├─────────────────────────────────────────────────────┤
│                                                      │
│  ┌─ DNS 配置卡片 ──────────────────────────────┐    │
│  │ [卡片 1] 阿里云-主                    [删除] │    │
│  │                                             │    │
│  │ DNS Key:  [aliyun-prod (alidns)  ▼]        │    │
│  │ TTL:      [600] 秒                          │    │
│  │                                             │    │
│  │ IPv4  ─────────────────────────────────     │    │
│  │ ☑ 启用   获取方式: [网卡 ▼]   eth0          │    │
│  │ 域名: manager.example.com, oof.example.org        │    │
│  │               [添加域名]                     │    │
│  │                                             │    │
│  │ IPv6  ─────────────────────────────────     │    │
│  │ ☑ 启用   获取方式: [URL ▼]                 │    │
│  │ URL: https://api6.ipify.org                │    │
│  │ 域名: manager.example.com, oof.example.org        │    │
│  │               [添加域名]                     │    │
│  └─────────────────────────────────────────────┘    │
│                                                      │
│  ┌─ DNS 配置卡片 ──────────────────────────────┐    │
│  │ [卡片 2] Cloudflare-备               [删除] │    │
│  │ ...                                         │    │
│  └─────────────────────────────────────────────┘    │
│                                                      │
│  [+ 新增 DNS 配置]                                   │
│                                                      │
│  ─── 证书部署 (节点统一) ───                         │
│  证书: [manager.example.com ▼]  路径: [/opt/certs]       │
│  重载服务: [nginx]                                   │
│  [+ 添加证书绑定]                                    │
│                                                      │
├─────────────────────────────────────────────────────┤
│                        [取消]  [保存配置]             │
└─────────────────────────────────────────────────────┘
```

### 4.2 交互规则

| 操作 | 行为 |
|------|------|
| **新增卡片** | 克隆一份空模板，卡片名称自动生成（"DNS配置 N"） |
| **删除卡片** | 至少保留 1 张，最后一张不可删 |
| **DNS Key 选择** | 下拉列出管理端所有已配置的 DNS Key |
| **IPv4/IPv6 启用** | 勾选后展开对应配置区 |
| **域名管理** | 输入框 + 添加按钮，已添加的以标签展示可删除 |
| **证书部署** | 与卡片分离，在底部独立区域配置 |
| **保存** | 收集所有卡片 + 证书配置 → JSON → POST API |

### 4.3 移动端适配

卡片在小屏幕上垂直堆叠，每张卡片内部字段换行排列。

---

## 五、后端 API 变更

### 5.1 配置 API

```
POST /api/node/{nodeID}/config
  Body: JSON (新格式, 含 dns_confs 数组)
  
  处理:
    1. 验证 dns_confs 每段的 dns_key 指向存在的 DNS Key
    2. 渲染 agent.yaml (展开 DNS Key → ddns-go DNS{Name,ID,Secret})
    3. 存入 NodeRecord.ConfigYAML
    4. 更新 ConfigHash → 下次心跳时 Agent 拉取新配置
```

### 5.2 兼容处理

```
读取旧格式 (ipv4/ipv6/dns_key_name 顶层字段):
  → 自动迁移为 dns_confs[0], 保持向后兼容
  
迁移触发: 下次保存节点配置时自动转新格式
```

### 5.3 YAML 渲染器

```go
// 新增: internal/config/render.go
func RenderAgentConfig(node *model.NodeRecord, keys map[string]*model.DNSKeyRecord) ([]byte, error) {
    // 1. 解析 node.ConfigYAML → config
    // 2. 遍历 config.DnsConfs
    // 3. 每段: 根据 dns_key → 查找 DNSKeyRecord → 展开 DNS{Name,ID,Secret}
    // 4. 输出 ddns-go 兼容的 Config YAML
}
```

---

## 六、Agent 端 (无需改动)

Agent 已经支持 `DnsConf []DnsConfig` 数组，当前代码遍历 `cfg.DnsConf` 逐段执行：

```go
for _, dc := range u.cfg.DnsConf {
    // 每段独立更新
}
```

**无需改 Agent 代码**。只改管理端生成的 YAML 结构即可。

---

## 七、实施步骤

| 步骤 | 内容 | 影响 |
|------|------|------|
| 1 | 新建 `internal/config/render.go` — 多段 YAML 渲染器 | 新增文件 |
| 2 | 修改 NodeRecord 配置 API — 支持 dns_confs 数组读写 | `handlers_admin.go` |
| 3 | 修改前端 — 多卡片 UI + JS 逻辑 | `index.html` |
| 4 | 向后兼容 — 旧格式自动迁移 | `handlers_admin.go` |
| 5 | 编译 + 测试 + 部署 | — |

---

## 八、风险

| 风险 | 缓解 |
|------|------|
| Agent 旧版本不兼容新 YAML | 新 YAML 仍包含 ipv4/ipv6 顶层备用字段 |
| DNS Key 重命名后卡片引用断裂 | 保存时校验 key 名存在；Agent 侧兜底跳过无效段 |
| 旧节点配置丢失 | 首次打开配置弹窗时自动迁移旧格式 |
