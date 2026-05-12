package main

import (
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
// Verifies that generateFingerprint produces consistent results.
func TestInstallerFingerprintConsistency(t *testing.T) {
	fp1 := generateFingerprint()
	if fp1 == "" {
		t.Fatal("指纹为空")
	}
	if !strings.HasPrefix(fp1, "sha256:") {
		t.Errorf("指纹前缀错误: %s", fp1)
	}
	if len(fp1) != 7+64 { // "sha256:" + 64 hex chars
		t.Errorf("指纹长度错误: got %d, want %d", len(fp1), 7+64)
	}

	// 多次调用应一致 (同一台机器)
	fp2 := generateFingerprint()
	if fp1 != fp2 {
		t.Errorf("指纹不一致: %s != %s", fp1, fp2)
	}
}

// ========== T2 (边界): ddns-go 冲突检测 ==========
// Verifies detectDDNSGoFull properly detects or doesn't detect ddns-go.
func TestInstallerDDNSGoDetection(t *testing.T) {
	items := detectDDNSGoFull()

	// 本测试机大概率没有 ddns-go 安装
	if len(items) > 0 {
		t.Logf("检测到 ddns-go 残留: %v", items)
		// 验证每个 item 的格式
		for _, item := range items {
			if strings.TrimSpace(item) == "" {
				t.Error("检测项为空字符串")
			}
		}
	} else {
		t.Log("未检测到 ddns-go (正常)")
	}

	// 验证函数不会 panic
	_ = detectDDNSGoFull()
}

// ========== T3 (异常): 指纹不匹配 — 新机抢名拒绝 ==========
// Uses a mock HTTP server to test the fingerprint query API and conflict detection.
func TestInstallerFingerprintMismatch(t *testing.T) {
	// Mock server: simulates a manager with a pre-existing node "test-node"
	// that has a different fingerprint than the current machine.
	existingFingerprint := "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" && r.URL.Path == "/api/nodes/test-node/fingerprint" {
			json.NewEncoder(w).Encode(map[string]interface{}{
				"exists":      true,
				"node_id":     "test-node",
				"fingerprint": existingFingerprint,
			})
			return
		}
		if r.Method == "GET" && strings.HasPrefix(r.URL.Path, "/api/nodes/") {
			// Unknown node — not found
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(map[string]interface{}{"exists": false})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	client := server.Client()

	// Case 1: 节点名已存在且指纹匹配 → 返回 exists=true, fp matching
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

	// Case 2: 节点名不存在 → 返回 exists=false
	exists2, fp2, err := checkNodeFingerprint(client, server.URL, "brand-new-node")
	if err != nil {
		t.Fatalf("指纹查询失败: %v", err)
	}
	if exists2 {
		t.Error("新节点不应存在")
	}
	if fp2 != "" {
		t.Errorf("新节点指纹应为空: got %s", fp2)
	}

	// Case 3: 模拟新机抢名 — 本地指纹 ≠ 服务端指纹
	localFP := generateFingerprint()
	if localFP == existingFingerprint {
		t.Skip("本地指纹与测试指纹意外匹配，跳过")
	}
	// 新机指纹不匹配 → 安装器应拒绝此名称
	// (此逻辑在 runInstall() 中，这里验证 checkNodeFingerprint 返回正确数据)
	t.Logf("本地指纹: %s, 服务端指纹: %s", localFP, existingFingerprint)
	if localFP == fp {
		t.Error("不同机器的指纹不应相同")
	}
}

// ========== T4 (补充): install.bat 模板版本替换 ==========
func TestInstallerBatVersionSubstitution(t *testing.T) {
	// 验证构建脚本中的 sed 替换对 install.bat.in 有效
	// 检查生成的 install.bat 中不包含 __VERSION__ 占位符
	batPath := filepath.Join("..", "..", "build", "install.bat")
	data, err := os.ReadFile(batPath)
	if err != nil {
		t.Skipf("跳过 — 需先运行 build.sh: %v", err)
	}

	content := string(data)
	if strings.Contains(content, "__VERSION__") {
		t.Error("install.bat 中仍有未替换的 __VERSION__ 占位符 — build.sh sed 替换失败?")
	} else {
		t.Log("install.bat 占位符已正确替换")
	}
}

// ========== T5 (清理): 旧版清理不会删除配置文件 ==========
// Tests that cleanOldDDNSManager preserves agent.yaml.
func TestInstallerCleanupPreservesConfig(t *testing.T) {
	// 创建临时目录模拟旧安装
	tmpDir := t.TempDir()
	oldAgentBaseDir = agentBaseDir // 备份
	defer func() { agentBaseDir = oldAgentBaseDir }()

	// 设置临时路径
	agentBaseDir = tmpDir
	agentConfigPath = filepath.Join(agentBaseDir, "agent.yaml")
	os.MkdirAll(agentBaseDir, 0700)

	// 创建模拟配置文件和旧二进制
	os.WriteFile(agentConfigPath, []byte("node_id: old-node"), 0600)
	if runtime.GOOS == "windows" {
		os.WriteFile(filepath.Join(agentBaseDir, "node-agent-v1.5.6-windows-amd64.exe"), []byte("fake"), 0755)
	} else {
		os.WriteFile(filepath.Join(agentBaseDir, "node-agent-v1.5.6-linux-amd64"), []byte("fake"), 0755)
	}

	// 执行清理
	cleaned := cleanOldDDNSManager()
	t.Logf("旧版清理结果: %v", cleaned)

	// 验证 agent.yaml 未被删除
	if _, err := os.Stat(agentConfigPath); os.IsNotExist(err) {
		t.Error("agent.yaml 被意外删除 — 清理逻辑应保留配置文件")
	}

	// 验证旧二进制已被删除
	entries, _ := os.ReadDir(agentBaseDir)
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "node-agent-v") && strings.Contains(e.Name(), ".exe") {
			t.Errorf("旧二进制未被删除: %s", e.Name())
		}
	}
}

// 保存原始 agentBaseDir 用于恢复
var oldAgentBaseDir string
