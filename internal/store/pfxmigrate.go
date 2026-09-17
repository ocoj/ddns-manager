package store

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
)

// MigratePlaintextPFXPasswords 急切迁移：把历史遗留的**明文** pfx_password 就地转为
// purpose 派生密钥加密的 pfx_password_enc，清空明文，并把 meta.json 收敛为 0600。
//
// 背景：v1.6.73 起新写入已脱敏，但**旧 bundle 只在"下次被写入"时才转换** ⇒ 长期不续期的
// bundle 会无限期保留明文（生产实测 3 个）。本函数把惰性转换变为**启动即完成**，并且
// 对未来"从旧备份恢复"同样自愈（每次启动都会扫一遍）。
//
// 安全契约（顺序不可颠倒）：
//  1. 先加密，**回读解密验证与原文逐字节相等**；验证失败 ⇒ 不动该文件（宁留明文，不毁口令）；
//  2. 通过后**原子替换**：同目录临时文件（0600）→ rename —— meta.json 是 bundle 的真相源，不可半写；
//  3. **幂等**：无明文的文件一律跳过（既不加密、也不改内容与权限）；
//  4. 范围仅限 certs/ 下的**在用** bundle；备份目录（部署前备份 / certs.bak-migrate-*）不在范围内。
//
// 返回成功转换数与逐条失败原因。调用方建议**不阻断启动**，仅告警。
func (s *ManagerStore) MigratePlaintextPFXPasswords() (int, []string, error) {
	root := filepath.Join(s.dir, "certs")
	entries, err := os.ReadDir(root)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil, nil
		}
		return 0, nil, fmt.Errorf("readdir certs: %w", err)
	}
	converted := 0
	var failures []string
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		name := e.Name()
		metaPath := filepath.Join(root, name, "meta.json")
		raw, err := os.ReadFile(metaPath)
		if err != nil {
			if os.IsNotExist(err) {
				continue // 无 meta 的目录：不视为失败
			}
			failures = append(failures, fmt.Sprintf("%s: 读取失败: %v", name, err))
			continue
		}
		meta := map[string]interface{}{}
		if err := json.Unmarshal(raw, &meta); err != nil {
			failures = append(failures, fmt.Sprintf("%s: meta 解析失败: %v", name, err))
			continue
		}
		pw, _ := meta["pfx_password"].(string)
		if pw == "" {
			continue // 幂等跳过（已迁移 / 从未设口令）
		}
		ct, err := s.encryptWithPurpose(purposePFXPassword, []byte(pw))
		if err != nil {
			failures = append(failures, fmt.Sprintf("%s: 加密失败: %v", name, err))
			continue
		}
		back, err := s.decryptWithPurpose(purposePFXPassword, ct)
		if err != nil || string(back) != pw {
			failures = append(failures, fmt.Sprintf("%s: 密文回读验证失败 ⇒ 保留明文", name))
			continue
		}
		meta["pfx_password"] = ""
		meta[PFXPasswordEncKey] = ct
		out, err := json.MarshalIndent(meta, "", "  ")
		if err != nil {
			failures = append(failures, fmt.Sprintf("%s: marshal 失败: %v", name, err))
			continue
		}
		if err := atomicWriteFile(metaPath, out, 0o600); err != nil {
			failures = append(failures, fmt.Sprintf("%s: 原子写失败: %v", name, err))
			continue
		}
		converted++
	}
	sort.Strings(failures)
	return converted, failures, nil
}
