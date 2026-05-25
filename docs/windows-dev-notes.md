# Windows 静默执行开发规范

> v1.6.18 起生效 | 基于 v1.5.37→v1.6.18 数十次失败的教训

## 核心原则

**Windows 服务进程 (SYSTEM 账户, 无桌面会话) 下，脚本和交互式工具极易失败。**

| 工具 | 问题 | 结论 |
|------|------|------|
| **批处理 (.bat)** | `chcp`/`timeout /t`/`setlocal` 在无控制台环境卡死；`reg add` 可能 Access Denied；孤儿进程累积 | ❌ 禁止 |
| **PowerShell 脚本** | 版本兼容性极差 (5.1 vs 7.x)；模块 (`WebAdministration`) 非服务器版不存在；执行策略限制；`Out-File`/`Add-Content` 破坏系统文件 ANSI 编码（hosts/cert 等）→ 文件格式损坏不可逆 | ⚠️ 仅限单行查询命令 + 优雅降级；**禁止写系统文件** |
| **netsh 文本解析** | SYSTEM locale 输出中文标签 (`IP:端口`/`证书哈希`)，英文正则失效 | ❌ 禁止 |
| **Go 原生 API** | 无兼容性问题 | ✅ 首选 |

## 升级机制 (v1.6.13 C6)

```
方案:  Go → sc config disabled → 极简cmd助手(ping+move+sc) → SCM标准退出
原理:  助手仅3个内置命令，无控制台依赖，全Windows版本兼容
```

**禁止使用的模式**（已证实失败）:
- `reg add` Defender排除 — Win10拒绝写入HKLM
- `chcp 65001` — 无控制台进程卡死
- `timeout /t /nobreak` — 无控制台卡死
- `setlocal enabledelayedexpansion` — 孤儿cmd.exe累积
- 文件重定向 `>>log 2>&1` — 并发时文件锁死锁

## IIS SSL 绑定扫描 (v1.6.15 C7)

```
方案:  WebAdministration PowerShell API → 结构化JSON
原因:  netsh文本解析因SYSTEM locale中文输出彻底失效 (v1.6.1-1.6.5验证)
       WebAdministration 是唯一跨locale方案
降级:  模块不存在 → "NO_MODULE" → 返回nil，不报错
```

**netsh 在 SYSTEM 下的实际输出**（中文系统）:
```
IP:端口                      : 0.0.0.0:443    ← 不是 "IP:port"！
证书哈希                     : abc123...       ← 不是 "Certificate Hash"！
```

**chcp 437 前缀不可靠**: `chcp 437 >nul && netsh ...` 在某些版本/补丁级别失效。

## 可用工具清单

| 工具 | 调用方式 | 可靠性 |
|------|---------|--------|
| `sc` | `exec.Command("sc", ...)` | ✅ 全版本 |
| `netsh http add/delete sslcert` | `exec.Command("netsh", ...)` | ✅ 仅增删操作，不解析输出 |
| `certutil` | `exec.Command("certutil", ...)` | ✅ 全版本 |
| `C:\Windows\System32\*.exe` | 全路径调用 | ✅ 避免PATH问题 |
| `ping -n N 127.0.0.1` | 仅作延时 | ✅ |
| `powershell -Command "单行"` | 仅WebAdministration API | ⚠️ 需优雅降级 |

## 测试矩阵

功能需在以下环境验证：

| 环境 | OS | 关键差异 |
|------|-----|---------|
| Windows Server 2022 | IIS可用 | WebAdministration模块完整 |
| Windows Server 2016 | IIS可用 | PS 5.1 |
| Windows 10 Pro | 无IIS | WebAdministration模块缺失 |
| SYSTEM 账户 | 所有版本 | 无桌面会话，locale影响netsh |

## 历史教训时间线

| 版本 | 尝试 | 结果 |
|------|------|------|
| v1.5.23-1.5.25 | 批处理升级 | SCM死锁 |
| v1.5.26-1.6.12 | 批处理改进 | Win10上reg add/timeout卡死, 孤儿进程 |
| v1.6.1-1.6.2 | netsh文本解析 | 0个SSL绑定 |
| v1.6.5 | netsh + chcp 437 | SYSTEM locale中文输出 |
| v1.6.7 | WebAdministration API | ✅ 成功 |
| v1.6.13 C6 | 废弃批处理升级 | ✅ 成功 |
| v1.6.14 C7 | 误回退netsh文本 | ❌ 0个SSL绑定(重蹈v1.6.1) |
| v1.6.27 | certutil GBK乱码 | certutil在中文Windows输出GBK, 直接log产生乱码, 仅取hex错误码 |
