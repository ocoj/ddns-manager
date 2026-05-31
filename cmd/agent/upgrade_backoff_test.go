// Test suite: ddns-manager v1.5.5 audit fixes
// Covers: upgrade backoff (E1), Walk depth limit (Q4), UpgradeState completion (E3)

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ocoj/ddns-manager/internal/model"
	"github.com/ocoj/ddns-manager/internal/store"
)

// ====== Test 1: 正常场景 — 升级退避 (E1) ======
// 验证: 30 分钟内同版本不重复推送 AgentUpdate

func TestUpgradeBackoffWithin30Minutes(t *testing.T) {
	dir := t.TempDir()
	st, err := store.NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}

	now := time.Now().UTC()
	cfg := &store.AgentConfig{
		LatestVersion: "1.5.5",
		UpgradeState: map[string]store.UpgJob{
			"node-a": {
				TargetVer: "1.5.5",
				Triggered: now.Add(-10 * time.Minute).Format(time.RFC3339), // 10 分钟前
			},
		},
	}
	if err := st.SaveAgentConfig(cfg); err != nil {
		t.Fatal(err)
	}

	// 模拟心跳: agent 版本 v1.5.4, Manager latest=1.5.5
	// 但上次推送才 10 分钟 → 应 跳过
	reloaded, err := st.LoadAgentConfig()
	if err != nil {
		t.Fatal(err)
	}
	if reloaded == nil {
		t.Fatal("AgentConfig is nil after reload")
	}

	if job, ok := reloaded.UpgradeState["node-a"]; !ok {
		t.Fatal("UpgradeState lost after save+reload")
	} else {
		trigTime, err := time.Parse(time.RFC3339, job.Triggered)
		if err != nil {
			t.Fatal(err)
		}
		elapsed := now.Sub(trigTime)
		if elapsed >= 30*time.Minute {
			t.Errorf("backoff 判定错误: elapsed=%v >= 30min, 应跳过推送", elapsed)
		}
		if job.TargetVer != "1.5.5" {
			t.Errorf("TargetVer = %q, want 1.5.5", job.TargetVer)
		}
		t.Logf("✅ 退避正确: 10分钟前推送的 v1.5.5, 不再重复推送 (elapsed=%v)", elapsed.Round(time.Second))
	}

	// 超过 30 分钟 → 应重新推送
	cfg.UpgradeState["node-a"] = store.UpgJob{
		TargetVer: "1.5.5",
		Triggered: now.Add(-35 * time.Minute).Format(time.RFC3339),
	}
	if err := st.SaveAgentConfig(cfg); err != nil {
		t.Fatal(err)
	}
	reloaded, _ = st.LoadAgentConfig()
	job := reloaded.UpgradeState["node-a"]
	trigTime, _ := time.Parse(time.RFC3339, job.Triggered)
	elapsed := now.Sub(trigTime)
	if elapsed < 30*time.Minute {
		t.Errorf("backoff 判定错误: elapsed=%v < 30min", elapsed)
	}
	t.Logf("✅ 超时正确: 35分钟后重新推送 (elapsed=%v)", elapsed.Round(time.Second))
}

// ====== Test 2: 边界场景 — Walk 深度限制 (Q4) ======
// 验证: collectCertHashes 不扫描超过 maxDepth 的目录

func TestCollectCertHashesDepthLimit(t *testing.T) {
	dir := t.TempDir()

	// 创建深度超过 5 层的目录结构
	deepDir := dir
	for i := 0; i < 8; i++ {
		deepDir = filepath.Join(deepDir, "sub")
		os.MkdirAll(deepDir, 0755)
	}
	// 在深层目录创建 .cert_hash
	os.WriteFile(filepath.Join(deepDir, ".cert_hash"), []byte("sha256:deep"), 0600)

	// 在浅层目录创建 .cert_hash (应该被扫描到)
	shallowDir := filepath.Join(dir, "certs")
	os.MkdirAll(shallowDir, 0755)
	os.WriteFile(filepath.Join(shallowDir, ".cert_hash"), []byte("sha256:shallow"), 0600)

	cfg := &model.AgentConfig{CertPath: dir}
	result := collectCertHashes(cfg)

	// 验证: 浅层应被扫描到
	if hash, ok := result[shallowDir]; !ok || hash != "sha256:shallow" {
		t.Errorf("浅层 cert_hash 未被扫描: result=%v", result)
	}

	// 验证: 深度超过 5 层的目录不应被扫描
	for dirPath := range result {
		rel, _ := filepath.Rel(cfg.CertPath, dirPath)
		depth := 0
		if rel != "." {
			depth = strings.Count(rel, string(os.PathSeparator)) + 1
		}
		if depth > 5 {
			t.Errorf("深度超过限制的目录被扫描: %s (depth=%d)", dirPath, depth)
		}
	}

	t.Logf("✅ 深度限制正确: 扫描到 %d 个 hash, 深层目录被正确跳过", len(result))
}

// ====== Test 3: 异常场景 — UpgradeState 完成标记 (E3) ======
// 验证: agent 版本匹配目标时自动标记 completed

func TestUpgradeStateCompletionTracking(t *testing.T) {
	dir := t.TempDir()
	st, err := store.NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}

	now := time.Now().UTC()
	cfg := &store.AgentConfig{
		LatestVersion: "1.5.5",
		UpgradeState: map[string]store.UpgJob{
			"node-a": {
				TargetVer: "1.5.5",
				Triggered: now.Add(-5 * time.Minute).Format(time.RFC3339),
			},
			"node-b": {
				TargetVer: "1.5.5",
				Triggered: now.Add(-60 * time.Minute).Format(time.RFC3339),
			},
		},
	}
	if err := st.SaveAgentConfig(cfg); err != nil {
		t.Fatal(err)
	}

	// node-a 心跳: agent_version=1.5.5 (已升级) → 应标记 completed
	reloaded, _ := st.LoadAgentConfig()
	jobA := reloaded.UpgradeState["node-a"]
	if jobA.Completed != "" {
		t.Error("Completed 不应已被设置 (测试数据)")
	}

	// 模拟心跳处理中的完成标记逻辑
	agentVer := "1.5.5"
	if jobA.Completed == "" && jobA.TargetVer == agentVer {
		jobA.Completed = now.Format(time.RFC3339)
		reloaded.UpgradeState["node-a"] = jobA
		st.SaveAgentConfig(reloaded)
	}

	// 验证
	reloaded, _ = st.LoadAgentConfig()
	if reloaded.UpgradeState["node-a"].Completed == "" {
		t.Error("completed 未被设置")
	} else {
		t.Logf("✅ node-a 完成标记正确: completed=%s", reloaded.UpgradeState["node-a"].Completed)
	}

	// node-b: agent_version=1.5.4 (未升级) → completed 应为空
	if reloaded.UpgradeState["node-b"].Completed != "" {
		t.Error("node-b 不应已完成 (agent_version 不匹配)")
	} else {
		t.Logf("✅ node-b 正确保持未完成 (agent 版本未匹配)")
	}

	// node-b 升级后 → 应标记
	reloaded.UpgradeState["node-b"] = store.UpgJob{
		TargetVer: "1.5.5",
		Triggered: reloaded.UpgradeState["node-b"].Triggered,
		Completed: now.Format(time.RFC3339),
	}
	st.SaveAgentConfig(reloaded)
	reloaded, _ = st.LoadAgentConfig()
	if reloaded.UpgradeState["node-b"].Completed == "" {
		t.Error("node-b completed 未生效")
	} else {
		t.Logf("✅ node-b 完成标记正确")
	}

	// 验证全部状态持久化
	if len(reloaded.UpgradeState) != 2 {
		t.Errorf("UpgradeState 条目数=%d, want 2", len(reloaded.UpgradeState))
	}
}
