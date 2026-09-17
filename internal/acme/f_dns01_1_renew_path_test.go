package acme

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	mycrypto "github.com/ocoj/ddns-manager/internal/crypto"
)

// TestT77a_BundleDirForCertDirNormalization —— F-1（v1.6.74 第三方审计第一轮）回归守卫。
//
// 缺陷：续期路径曾用 `"acme-" + filepath.Base(certDir)` 推导「口令权威来源」的 bundle 目录。
// 当目录名**已带** `acme-` 前缀时，该式会二次加前缀 ⇒ 推导出 `certs/acme-acme-<域名>`（不存在）。
// 修正：**仅在缺失时补一次前缀**（幂等），与 server.issueBundleName 规则一致。
//
// 判别力局限（本方自曝，第二轮审计独立复现）：本测试直接测**助手**；若把**调用点**改回旧式，
// 本测试**仍会 PASS**（两实现在全部可达状态下行为等价，见 TestT77b）。
func TestT77a_BundleDirForCertDirNormalization(t *testing.T) {
	cases := []struct{ in, want string }{
		{"/data/certs/acme-sp.lanxun.pro", "/data/certs/acme-sp.lanxun.pro"},
		{"/data/certs/acme-oof.noxen.pro", "/data/certs/acme-oof.noxen.pro"},
		{"/data/certs/acme-t73dns-x.lanxun.pro", "/data/certs/acme-t73dns-x.lanxun.pro"},
		{"/data/certs/sp.lanxun.pro", "/data/certs/acme-sp.lanxun.pro"},
		{"/data/certs/*.lanxun.pro", "/data/certs/acme-*.lanxun.pro"},
	}
	for _, c := range cases {
		if got := bundleDirForCertDir(c.in); got != c.want {
			t.Errorf("bundleDirForCertDir(%q) = %q；期望 %q", c.in, got, c.want)
		}
	}
	oldStyle := filepath.Join(filepath.Dir("/data/certs/acme-sp.lanxun.pro"),
		"acme-"+filepath.Base("/data/certs/acme-sp.lanxun.pro"))
	if oldStyle == bundleDirForCertDir("/data/certs/acme-sp.lanxun.pro") {
		t.Errorf("旧式与修正后结果相同（%q）⇒ 本测试不具备判别力", oldStyle)
	} else {
		t.Logf("判别力确认：旧式=%q ≠ 修正后=%q", oldStyle, bundleDirForCertDir("/data/certs/acme-sp.lanxun.pro"))
	}
}

// TestT77b_CustomPFXPasswordPreservedOnUpdateCertMeta —— O-1 行为级回归测试（第二轮审计建议本批闭合）。
//
// 不测助手字符串，而测**产物**：在 `UpdateCertMeta`（续期/重建路径，含 F-1 分支）之后，
// `cert.pfx` 必须**以用户自定义口令可解**，且**不可用默认口令解开**（本批不变量：绝不用默认口令顶替）。
//
// 覆盖两形态（与第二轮审计 §4.2 的分类一致）：
//   - 普通域名：签发目录 ≠ bundle 目录 ⇒ F-1 分支**会**执行，须从 bundle meta 取回自定义口令；
//   - `acme-` 域名：签发目录 **即** bundle 目录 ⇒ 首次解析即得自定义口令 ⇒ 分支不执行。
//
// 说明（诚实条目）：本测试**无法**判别「调用点被改回旧式」——按第二轮审计 §4.3，旧式在普通域名下
// 恰好得出正确目录、在 `acme-` 域名下分支不可达 ⇒ 两实现在**全部可达状态**下行为等价。
// 因此 T-2 所指的「调用点信号缺口」在此**不是覆盖不足，而是行为等价**；本测试的作用是把
// 「自定义口令不得被默认口令顶替」这一**行为**钉死，防止将来规则变更造成真实回归。
func TestT77b_CustomPFXPasswordPreservedOnUpdateCertMeta(t *testing.T) {
	const customPW = "USER-CUSTOM-PW-73"
	cases := []struct {
		label             string
		domain            string
		separateBundleDir bool
	}{
		{"普通域名（签发目录 ≠ bundle 目录）", "sp.lanxun.pro", true},
		{"acme- 域名（签发目录 == bundle 目录）", "acme-x.lanxun.pro", false},
	}
	for _, c := range cases {
		t.Run(c.label, func(t *testing.T) {
			root := t.TempDir()
			certsDir := filepath.Join(root, "certs")
			certDir := filepath.Join(certsDir, c.domain)
			if err := os.MkdirAll(certDir, 0o700); err != nil {
				t.Fatalf("mkdir: %v", err)
			}
			certPEM, keyPEM := selfSigned(t, c.domain)
			for f, b := range map[string][]byte{
				"fullchain.pem": certPEM, "privkey.pem": keyPEM, "cert.pem": certPEM,
			} {
				if err := os.WriteFile(filepath.Join(certDir, f), b, 0o600); err != nil {
					t.Fatalf("write %s: %v", f, err)
				}
			}
			// 签发侧 meta：**不含**口令键（生产事实：acme 侧写 domains/issued/acme/ca…）
			writeJSONT(t, filepath.Join(certDir, "meta.json"), map[string]interface{}{
				"domains": []string{c.domain},
			})
			// bundle meta：携带用户自定义口令（口令的权威来源）
			bundleDir := certDir
			if c.separateBundleDir {
				bundleDir = filepath.Join(certsDir, "acme-"+c.domain)
			}
			if err := os.MkdirAll(bundleDir, 0o700); err != nil {
				t.Fatalf("mkdir bundle: %v", err)
			}
			writeJSONT(t, filepath.Join(bundleDir, "meta.json"), map[string]interface{}{
				"dns_key": "阿里-蓝迅", "pfx_password": customPW,
			})

			m, err := New(certsDir, "t@example.com", ":80")
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			// 等价 store.MetaPFXPassword 的取值口径（明文兼容 ⇒ 默认；失败不回落）
			m.SetPFXPasswordResolver(func(meta map[string]interface{}) (string, error) {
				if v, ok := meta["pfx_password"].(string); ok && v != "" {
					return v, nil
				}
				return mycrypto.DefaultPFXPassword, nil
			})

			if err := m.UpdateCertMeta(certDir); err != nil {
				t.Fatalf("UpdateCertMeta: %v", err)
			}
			pfx, err := os.ReadFile(filepath.Join(certDir, "cert.pfx"))
			if err != nil {
				t.Fatalf("读 cert.pfx: %v", err)
			}
			if _, _, err := mycrypto.ParsePFXLeafChain(pfx, customPW); err != nil {
				t.Errorf("cert.pfx 不能用自定义口令解开 ⇒ 口令被覆盖: %v", err)
			}
			if _, _, err := mycrypto.ParsePFXLeafChain(pfx, mycrypto.DefaultPFXPassword); err == nil {
				t.Errorf("cert.pfx 竟可用默认口令解开 ⇒ 自定义口令被默认口令顶替（违反本批不变量）")
			}
			modern, err := os.ReadFile(filepath.Join(certDir, "cert-modern.pfx"))
			if err == nil {
				if _, _, err := mycrypto.ParsePFXLeafChain(modern, customPW); err != nil {
					t.Errorf("cert-modern.pfx 不能用自定义口令解开: %v", err)
				}
			}
		})
	}
}

func writeJSONT(t *testing.T, path string, v interface{}) {
	t.Helper()
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}
