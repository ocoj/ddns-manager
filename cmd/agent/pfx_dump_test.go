package main

import (
	"testing"

	"golang.org/x/text/encoding/simplifiedchinese"
)

// v1.6.65 回归测试: parsePFXInfoDump 中英文 certutil -dump 输出解析。
// 生产事故 (sp.example.com / win-test): 中文 Windows 输出中文标签
// (证书哈希(sha1):/使用者:)，旧代码只匹配英文 → 指纹提取失败 → IIS 绑定失败；
// 且旧代码取第一个证书块(根证书, 无私钥) → 指纹错误。
// 样例输出取自中文 Windows Server 实测 (go-pkcs12 LegacyDES PFX)。

// 中文输出: 4 个证书块，叶子(证书 3)带 "提供程序 ="。
const zhDump = `================ 证书 0 ================
================ 开始嵌套等级 1 ================
元素 0:
序列号: 6c8f1dc727c7117f7baf853ac980f9cd
颁发者: CN=ISRG Root X1, O=Internet Security Research Group, C=US
使用者: CN=ISRG Root X2, O=Internet Security Research Group, C=US
非根证书
证书哈希(sha1): 3c34e356c7fc17f5acf04824bc587c6c623951a2
---------------- 结束嵌套等级 1 ----------------
没有密钥提供程序信息
找不到解密的证书和私钥。

================ 证书 1 ================
================ 开始嵌套等级 1 ================
元素 1:
序列号: 872165fc34b6e5fba8add5b3705fb53a
颁发者: CN=ISRG Root X2, O=Internet Security Research Group, C=US
使用者: CN=Root YE, O=ISRG, C=US
证书哈希(sha1): f37620fc4b1cddd2a3d74b1d5e8db42e244ca006
---------------- 结束嵌套等级 1 ----------------
没有密钥提供程序信息

================ 证书 2 ================
元素 2:
使用者: CN=YE1, O=Let's Encrypt, C=US
证书哈希(sha1): d09370a9864982a5047da46373540256d08a3c81
没有密钥提供程序信息

================ 证书 3 ================
元素 3:
序列号: 0000
颁发者: CN=YE1, O=Let's Encrypt, C=US
使用者: CN=*.example.com
证书哈希(sha1): efba8a811b958121514c9700400e06451aff3517
提供程序 = Microsoft Software Key Storage Provider
无法以纯文本方式导出私钥
`

// 英文输出: 与中文同构，叶子带 "Provider ="。
const enDump = `================ Certificate 0 ================
================ Begin Nesting Level 1 ================
Element 0:
Serial Number: 6c8f1dc727c7117f7baf853ac980f9cd
Issuer: CN=ISRG Root X1, O=Internet Security Research Group, C=US
Subject: CN=ISRG Root X2, O=Internet Security Research Group, C=US
Cert Hash(sha1): 3c 34 e3 56 c7 fc 17 f5 ac f0 48 24 bc 58 7c 6c 62 39 51 a2
---------------- End Nesting Level 1 ----------------
No key provider information

================ Certificate 1 ================
Element 1:
Subject: CN=Root YE, O=ISRG, C=US
Cert Hash(sha1): f3 76 20 fc 4b 1c dd d2 a3 d7 4b 1d 5e 8d b4 2e 24 4c a0 06
No key provider information

================ Certificate 2 ================
Element 2:
Subject: CN=YE1, O=Let's Encrypt, C=US
Cert Hash(sha1): d0 93 70 a9 86 49 82 a5 04 7d a4 63 73 54 02 56 d0 8a 3c 81
No key provider information

================ Certificate 3 ================
Element 3:
Subject: CN=*.example.com
Cert Hash(sha1): ef ba 8a 81 1b 95 81 21 51 4c 97 00 40 0e 06 45 1a ff 35 17
Provider = Microsoft Software Key Storage Provider
Private key is not exportable.
`

// 无 Provider 标志的异常输出 → 应回退到第一个指纹
const noKeyDump = `================ Certificate 0 ================
Subject: CN=test.example.com
Cert Hash(sha1): aabbccddeeff00112233445566778899aabbccdd
`

func TestParsePFXInfoDump_ChineseOutput(t *testing.T) {
	thumb, cn := parsePFXInfoDump(zhDump)
	if thumb != "efba8a811b958121514c9700400e06451aff3517" {
		t.Errorf("中文输出指纹 = %q, want 叶子证书 efba8a81...", thumb)
	}
	if cn != "*.example.com" {
		t.Errorf("中文输出 CN = %q, want *.example.com", cn)
	}
}

func TestParsePFXInfoDump_EnglishOutput(t *testing.T) {
	thumb, cn := parsePFXInfoDump(enDump)
	if thumb != "efba8a811b958121514c9700400e06451aff3517" {
		t.Errorf("英文输出指纹 = %q, want 叶子证书 efba8a81... (含空格去空格)", thumb)
	}
	if cn != "*.example.com" {
		t.Errorf("英文输出 CN = %q, want *.example.com", cn)
	}
}

func TestParsePFXInfoDump_NotRootCert(t *testing.T) {
	// 关键回归: 绝不能取第一个(根证书)的指纹 3c34e356...
	thumb, _ := parsePFXInfoDump(zhDump)
	if thumb == "3c34e356c7fc17f5acf04824bc587c6c623951a2" {
		t.Error("取到了根证书指纹 — 必须提取叶子证书(带私钥)")
	}
}

func TestParsePFXInfoDump_FallbackFirstHash(t *testing.T) {
	// 无 Provider 标志(异常输出) → 回退第一个指纹
	thumb, _ := parsePFXInfoDump(noKeyDump)
	if thumb != "aabbccddeeff00112233445566778899aabbccdd" {
		t.Errorf("回退指纹 = %q, want aabbccdd...", thumb)
	}
}

func TestParsePFXInfoDump_Empty(t *testing.T) {
	thumb, cn := parsePFXInfoDump("")
	if thumb != "" || cn != "" {
		t.Errorf("空输出: thumb=%q cn=%q, want 空", thumb, cn)
	}
}

// toGBK 将 UTF-8 字符串转为 GBK 编码 (模拟中文 Windows certutil 输出)。
func toGBK(s string) []byte {
	enc := simplifiedchinese.GBK.NewEncoder()
	b, _ := enc.Bytes([]byte(s))
	return b
}

// TestParsePFXInfoDump_GBKEncodedChinese v1.6.67 回归测试:
// 中文 Windows 的 certutil 输出是 GBK 编码(非 UTF-8)。直接按 UTF-8 解析
// 中文标签会因字节序列不匹配而失败 (sp.example.com/win-test 实测: certutil
// -importpfx 成功但 "PFX 证书指纹提取失败")。decodeCertutilOutput 需先转 UTF-8。
func TestParsePFXInfoDump_GBKEncodedChinese(t *testing.T) {
	gbkOut := toGBK(zhDump) // 模拟真实 GBK 编码的 certutil -dump 输出
	text := decodeCertutilOutput(gbkOut)
	thumb, cn := parsePFXInfoDump(text)
	if thumb != "efba8a811b958121514c9700400e06451aff3517" {
		t.Errorf("GBK 输出指纹 = %q, want 叶子证书 efba8a81...", thumb)
	}
	if cn != "*.example.com" {
		t.Errorf("GBK 输出 CN = %q, want *.example.com", cn)
	}
}

// TestParsePFXInfoDump_GBKDirectFails 验证修复的必要性:
// 不转码直接按 UTF-8 解析 GBK 输出应失败 (中文标签字节不匹配)。
func TestParsePFXInfoDump_GBKDirectFails(t *testing.T) {
	gbkText := string(toGBK(zhDump)) // 未转码
	thumb, _ := parsePFXInfoDump(gbkText)
	if thumb == "efba8a811b958121514c9700400e06451aff3517" {
		t.Error("GBK 输出未转码竟然解析成功 — 说明测试样例有问题")
	}
}

// TestSiteMatchesCert v1.6.69 回归测试: 多站点 IIS 站点名匹配证书域名
func TestSiteMatchesCert(t *testing.T) {
	cases := []struct {
		site, certCN string
		want         bool
	}{
		{"sp.example.com", "sp.example.com", true},
		{"SP.EXAMPLE.COM", "sp.example.com", true},
		{"sp.example.com 站点", "sp.example.com", true},
		{"SharePoint - 80", "sp.example.com", false},
		{"SharePoint Web Services", "sp.example.com", false},
		{"", "sp.example.com", false},
		{"sp.example.com", "", false},
		{"Default Web Site", "sp.example.com", false},
	}
	for _, c := range cases {
		got := siteMatchesCert(c.site, c.certCN)
		if got != c.want {
			t.Errorf("siteMatchesCert(%q, %q) = %v, want %v", c.site, c.certCN, got, c.want)
		}
	}
}

// TestExtractSubjectCN v1.6.69 回归测试: 证书 Subject CN 提取
func TestExtractSubjectCN(t *testing.T) {
	cases := []struct {
		subject, want string
	}{
		{"CN=sp.example.com, O=Example, Inc.", "sp.example.com"},
		{"CN=*.example.com", "*.example.com"},
		{"sp.example.com", "sp.example.com"},
		{"", ""},
	}
	for _, c := range cases {
		got := extractSubjectCN(c.subject)
		if got != c.want {
			t.Errorf("extractSubjectCN(%q) = %q, want %q", c.subject, got, c.want)
		}
	}
}

// TestCertCNMatches v1.6.69 回归测试: 绑定当前证书 CN 与新证书 CN 匹配
func TestCertCNMatches(t *testing.T) {
	cases := []struct {
		curCN, certCN string
		want          bool
	}{
		{"sp.example.com", "sp.example.com", true},
		{"SP.EXAMPLE.COM", "sp.example.com", true},
		{"*.example.com", "sp.example.com", true},
		{"sp.example.com", "*.example.com", true},
		{"other.example.com", "sp.example.com", false},
		{"", "sp.example.com", false},
		{"sp.example.com", "", false},
	}
	for _, c := range cases {
		got := certCNMatches(c.curCN, c.certCN)
		if got != c.want {
			t.Errorf("certCNMatches(%q, %q) = %v, want %v", c.curCN, c.certCN, got, c.want)
		}
	}
}
