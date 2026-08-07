package main

import (
	"testing"
)

// v1.6.65 回归测试: parsePFXInfoDump 中英文 certutil -dump 输出解析。
// 生产事故 (sp.lanxun.pro / Win2022): 中文 Windows 输出中文标签
// (证书哈希(sha1):/使用者:)，旧代码只匹配英文 → 指纹提取失败 → IIS 绑定失败；
// 且旧代码取第一个证书块(根证书, 无私钥) → 指纹错误。
// 样例输出取自中文 Windows Server 2022 实测 (go-pkcs12 LegacyDES PFX)。

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
使用者: CN=*.lanxun.pro
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
Subject: CN=*.lanxun.pro
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
	if cn != "*.lanxun.pro" {
		t.Errorf("中文输出 CN = %q, want *.lanxun.pro", cn)
	}
}

func TestParsePFXInfoDump_EnglishOutput(t *testing.T) {
	thumb, cn := parsePFXInfoDump(enDump)
	if thumb != "efba8a811b958121514c9700400e06451aff3517" {
		t.Errorf("英文输出指纹 = %q, want 叶子证书 efba8a81... (含空格去空格)", thumb)
	}
	if cn != "*.lanxun.pro" {
		t.Errorf("英文输出 CN = %q, want *.lanxun.pro", cn)
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
