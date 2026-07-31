## Changelog
* 5e501126e2fd103a9ededc92ee4396250c4b3426 README: 去v2 + 版本badge + Docker部署说明 + 版本号更新
* ed3cc976cec1139a77fea92e75d616d448ab0536 Revert "docs: add PowerShell hosts encoding corruption to Windows dev notes"
* 47d3c538c376d986974710bf3767da4abf1b75be fix: ACME账户启动后显示未注册 — LoadACMEAccounts缺失解密逻辑
* 8892267740aa5dafc3b9580560e5d531587bd1a2 fix: Windows agent构建隔离到cmd/agent-win, 根治ARM syso交叉污染
* b4156010c8a52b33160701f73e24cc4d8e81db4b fix: gitignore排除.deepcode/, 移除已追踪的IDE文件
* 85bd2f2cf8f9fe09832bdcd0a4bbef075d9945e5 fix: goreleaser template remove unsupported default() function
* 0aab73795232726c1487c823ee00cb7da7a0af7b fix: mobile dashboard event badge also pushed below — order:2→0
* 06302ffa603d2d8a67a109dab7cc451edf3b77fe fix: mobile log page category badge pushed below content — order:2→0
* 85c1985d0e83e29ae7839ce5d3f0a05b22c54ef4 fix: remove goversioninfo hooks to prevent ARM syso cross-contamination
* 7eca7f6e62cfd62ec9c5aeca13e388b77abcfd7d fix: 从git追踪中移除memory/文件(含内部IP), 由.gitignore控制
* e6ea9d3b6117ea958db3ee0c4f835012f7a9a80a refactor: Docker镜像由GitHub Actions构建, 本地goreleaser不再依赖docker
* efb88d8cc526ae66608ed908ddf1c8d6217a943d v1.6.45: 审计修复 — context泄漏/data race/日志覆盖/时区统一/设计文档澄清
* d9b7972695d0a6f952c46281298265d70ee0357e v1.6.46: DDNS健康判定机制重构 — 全链路6项修复
* 4e004759a770a825b06b7985d0fcad34031ba4a4 v1.6.46: DNS健康状态防抖 — 连续失败计数消除ERR抖动
* 16235f561ee223e93d2f738d7d8494af3de00a87 v1.6.47: DNS日志去重 + 审计修复 + DDNS健康判定重构 + 文档对齐
* 02c3e0fb9cb7ba6fcd00785c1cf7c8fe71db56d2 v1.6.50: 全量审计修复 (6项) + 单元测试
* 132774ab1816ec3fa655e71537a3994f728cceb2 v1.6.52: TLS VerifySSL default true — agent verify certs by default
* a002e2250fc7d2349a52c4815ff56bdacca8a6a8 v1.6.57: 补充安全审计 — 15项发现全部修复
* b42604b85afc4d7b228b41c7fc868a6285415c76 v1.6.59: ddns-go v6.17.4 + 发布基础设施
