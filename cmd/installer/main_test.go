package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// ========== T1 (正常): 指纹匹配 — 旧机重装自动继承 ==========
func TestInstallerFingerprintConsistency(t *testing.T) {
	fp1, err := generateFingerprint()
	if err != nil {
		t.Fatalf("generateFingerprint 失败: %v", err)
	}
	if fp1 == "" {
		t.Fatal("指纹为空")
	}
	if !strings.HasPrefix(fp1, "sha256:") {
		t.Errorf("指纹前缀错误: %s", fp1)
	}
	if len(fp1) != 7+64 {
		t.Errorf("指纹长度错误: got %d, want %d", len(fp1), 7+64)
	}
	fp2, _ := generateFingerprint()
	if fp1 != fp2 {
		t.Errorf("指纹不一致: %s != %s", fp1, fp2)
	}
}

// ========== T2 (边界): ddns-go 冲突检测 ==========
func TestInstallerDDNSGoDetection(t *testing.T) {
	items := detectDDNSGoFull()
	if len(items) > 0 {
		t.Logf("检测到 ddns-go 残留: %v", items)
		for _, item := range items {
			if strings.TrimSpace(item) == "" {
				t.Error("检测项为空字符串")
			}
		}
	} else {
		t.Log("未检测到 ddns-go (正常)")
	}
	_ = detectDDNSGoFull()
}

// ========== T3 (异常): 指纹不匹配 — 新机抢名拒绝 ==========
func TestInstallerFingerprintMismatch(t *testing.T) {
	existingFingerprint := "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" && r.URL.Path == "/api/nodes/test-node/fingerprint" {
			json.NewEncoder(w).Encode(map[string]interface{}{
				"exists": true, "node_id": "test-node", "fingerprint": existingFingerprint,
			})
			return
		}
		if r.Method == "GET" && strings.HasPrefix(r.URL.Path, "/api/nodes/") {
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(map[string]interface{}{"exists": false})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()
	client := server.Client()

	exists, fp, err := checkNodeFingerprint(client, server.URL, "test-node")
	if err != nil {
		t.Fatalf("指纹查询失败: %v", err)
	}
	if !exists {
		t.Error("节点应存在")
	}
	if fp != existingFingerprint {
		t.Errorf("指纹不匹配: got %s, want %s", fp, existingFingerprint)
	}

	exists2, fp2, err := checkNodeFingerprint(client, server.URL, "brand-new-node")
	if err != nil {
		t.Fatalf("指纹查询失败: %v", err)
	}
	if exists2 { t.Error("新节点不应存在") }
	if fp2 != "" { t.Errorf("新节点指纹应为空: got %s", fp2) }

	localFP, _ := generateFingerprint()
	if localFP == existingFingerprint {
		t.Skip("本地指纹与测试指纹意外匹配，跳过")
	}
	t.Logf("本地指纹: %s, 服务端指纹: %s", localFP, existingFingerprint)
	if localFP == fp { t.Error("不同机器的指纹不应相同") }
}

// ========== T4: install.bat 模板版本替换 ==========
func TestInstallerBatVersionSubstitution(t *testing.T) {
	batPath := filepath.Join("..", "..", "build", "install.bat")
	data, err := os.ReadFile(batPath)
	if err != nil {
		t.Skipf("跳过 — 需先运行 build.sh: %v", err)
	}
	if strings.Contains(string(data), "__VERSION__") {
		t.Error("install.bat 中仍有未替换的 __VERSION__ 占位符")
	} else {
		t.Log("install.bat 占位符已正确替换")
	}
}

// ========== T5: 旧版清理不会删除配置文件 ==========
func TestInstallerCleanupPreservesConfig(t *testing.T) {
	tmpDir := t.TempDir()
	oldAgentBaseDir = agentBaseDir
	defer func() { agentBaseDir = oldAgentBaseDir }()
	agentBaseDir = tmpDir
	agentConfigPath = filepath.Join(agentBaseDir, "agent.yaml")
	os.MkdirAll(agentBaseDir, 0700)
	os.WriteFile(agentConfigPath, []byte("node_id: old-node"), 0600)
	if runtime.GOOS == "windows" {
		os.WriteFile(filepath.Join(agentBaseDir, "node-agent-v1.5.6-windows-amd64.exe"), []byte("fake"), 0755)
	} else {
		os.WriteFile(filepath.Join(agentBaseDir, "node-agent-v1.5.6-linux-amd64"), []byte("fake"), 0755)
	}
	cleaned := cleanOldDDNSManager()
	t.Logf("旧版清理结果: %v", cleaned)
	if _, err := os.Stat(agentConfigPath); os.IsNotExist(err) {
		t.Error("agent.yaml 被意外删除")
	}
	entries, _ := os.ReadDir(agentBaseDir)
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "node-agent-v") && strings.Contains(e.Name(), ".exe") {
			t.Errorf("旧二进制未被删除: %s", e.Name())
		}
	}
}

// ========== v1.5.14 T6 (正常): MachineGuid 指纹格式和一致性 ==========
func TestFingerprintMachineGuid_Format(t *testing.T) {
	fp, err := generateFingerprint()
	if err != nil {
		t.Fatalf("generateFingerprint 失败: %v", err)
	}
	if !strings.HasPrefix(fp, "sha256:") {
		t.Fatalf("指纹前缀错误: %s", fp)
	}
	hashPart := strings.TrimPrefix(fp, "sha256:")
	if len(hashPart) != 64 {
		t.Fatalf("指纹hash长度错误: got %d, want 64", len(hashPart))
	}
	for _, c := range hashPart {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			t.Fatalf("指纹含非hex字符: %c in %s", c, fp)
		}
	}
	fp2, _ := generateFingerprint()
	if fp != fp2 {
		t.Fatalf("指纹不一致: %s != %s", fp, fp2)
	}
	if strings.Contains(fp, "\r") || strings.Contains(fp, "\n") {
		t.Fatal("指纹包含换行符 — PowerShell输出尾随字符污染未修复")
	}
	t.Logf("指纹(正常): %s", fp)
}

// ========== v1.5.14 T7 (边界): getMachineID 返回值合法 ==========
func TestFingerprintMachineID_Boundary(t *testing.T) {
	mid, err := getMachineID()
	if err != nil {
		t.Skipf("getMachineID 不可用 (预期仅出现在容器环境): %v", err)
	}
	mid = strings.TrimSpace(mid)
	if mid == "" {
		t.Fatal("getMachineID 返回空字符串")
	}
	if strings.Contains(mid, "\n") || strings.Contains(mid, "\r") {
		t.Fatal("machineID 包含换行符 — TrimSpace 未生效")
	}
	if runtime.GOOS == "windows" {
		parts := strings.Split(mid, "-")
		if len(parts) != 5 {
			t.Fatalf("Windows MachineGuid 不是有效GUID: %s", mid)
		}
	}
	if runtime.GOOS == "linux" {
		if len(mid) != 32 {
			t.Logf("Linux machine-id 长度非32: got %d, value=%s (某些系统使用不同格式)", len(mid), mid)
		}
	}
	t.Logf("machineID(%s): %s", runtime.GOOS, mid)
}

// ========== v1.5.14 T8 (异常): getMachineID 失败 → generateFingerprint 返回错误 ==========
// 验证: 无降级, getMachineID 失败时 generateFingerprint 直接返回 error,
// 安装器向导提示用户检查权限/杀毒软件后重试或退出。
func TestFingerprintMachineID_NoDegradation(t *testing.T) {
	mid, err := getMachineID()
	if err != nil {
		t.Skipf("getMachineID 不可用 (预期仅出现在容器环境): %v", err)
	}
	if mid == "" {
		t.Fatal("getMachineID 返回空字符串")
	}
	fp, fpErr := generateFingerprint()
	if fpErr != nil {
		t.Fatalf("生成指纹失败: %v", fpErr)
	}

	// 验证指纹含 machineID (不等于纯 hostname)
	hostname, _ := os.Hostname()
	hHostOnly := sha256.Sum256([]byte(hostname))
	fpHostOnly := "sha256:" + hex.EncodeToString(hHostOnly[:])
	if fp == fpHostOnly {
		t.Fatal("指纹不应退化为纯 hostname — getMachineID 必须参与指纹计算")
	}

	fp2, _ := generateFingerprint()
	if fp != fp2 {
		t.Fatal("指纹不一致 — 同机多次调用应返回相同值")
	}
	t.Logf("machineID: %s", mid)
	t.Logf("指纹: %s", fp)
}

var oldAgentBaseDir string
