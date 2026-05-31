// v1.6.55 审计修复验证: 死代码删除 + DNS Key 引用一致性
package store

import (
	"testing"

	"github.com/ocoj/ddns-manager/internal/model"
)

// TestTrackDNSKeyUsageBatch_Atomic_Normal
// 正常场景: 多 key 批量追踪 — RemoveNodeFromDNSKeys 清空后,
// 多次 TrackDNSKeyUsage 逐 key 回加, 验证最终 used_by_nodes 一致性。
func TestTrackDNSKeyUsageBatch_Atomic_Normal(t *testing.T) {
	s, _ := NewStore(t.TempDir())

	// 准备: 创建 3 个 DNS Key, node-1 已关联 key-A, key-B
	keys := map[string]*model.DNSKeyRecord{
		"key-A": {Name: "key-A", Provider: "alidns", UsedByNodes: []string{"node-1", "node-2"}},
		"key-B": {Name: "key-B", Provider: "cloudflare", UsedByNodes: []string{"node-1"}},
		"key-C": {Name: "key-C", Provider: "dnspod", UsedByNodes: []string{}},
	}
	s.SaveDNSKeys(keys)

	// 模拟 handleSaveNodeConfig 的 Remove + 批量 Track 模式
	// node-1 从 key-A/key-B 全部移除
	if err := s.RemoveNodeFromDNSKeys("node-1"); err != nil {
		t.Fatalf("RemoveNodeFromDNSKeys 失败: %v", err)
	}

	// 逐个回加: node-1 → key-A, key-C (key-B 被替换)
	for _, kn := range []string{"key-A", "key-C"} {
		if err := s.TrackDNSKeyUsage(kn, "node-1"); err != nil {
			t.Fatalf("TrackDNSKeyUsage(%s) 失败: %v", kn, err)
		}
	}

	loaded, _ := s.LoadDNSKeys()

	// 验证 key-A: node-1 在, node-2 也在 (批量操作不影响其他节点)
	found1 := false
	for _, n := range loaded["key-A"].UsedByNodes {
		if n == "node-1" {
			found1 = true
		}
	}
	if !found1 {
		t.Error("node-1 应在 key-A 的 used_by_nodes 中")
	}

	found2 := false
	for _, n := range loaded["key-A"].UsedByNodes {
		if n == "node-2" {
			found2 = true
		}
	}
	if !found2 {
		t.Error("node-2 应仍在 key-A 的 used_by_nodes 中 (批量操作不影响其他节点)")
	}

	// 验证 key-B: node-1 已移除
	for _, n := range loaded["key-B"].UsedByNodes {
		if n == "node-1" {
			t.Error("node-1 应已从 key-B 移除 (key 被替换)")
		}
	}

	// 验证 key-C: node-1 已添加 (新 key)
	foundC := false
	for _, n := range loaded["key-C"].UsedByNodes {
		if n == "node-1" {
			foundC = true
		}
	}
	if !foundC {
		t.Error("node-1 应已添加到 key-C (新 key)")
	}
}

// TestTrackDNSKeyUsage_RemoveAll_Boundary
// 边界场景: RemoveNodeFromDNSKeys 清空所有 key 后, 不添加任何新 key
// → 节点应在所有 key 的 used_by_nodes 中消失。
func TestTrackDNSKeyUsage_RemoveAll_Boundary(t *testing.T) {
	s, _ := NewStore(t.TempDir())

	keys := map[string]*model.DNSKeyRecord{
		"key-A": {Name: "key-A", Provider: "alidns", UsedByNodes: []string{"node-1", "node-2"}},
		"key-B": {Name: "key-B", Provider: "cloudflare", UsedByNodes: []string{"node-1", "node-3"}},
		"key-C": {Name: "key-C", Provider: "dnspod", UsedByNodes: []string{"node-1"}},
	}
	s.SaveDNSKeys(keys)

	// 删除节点后应清理所有 DNS Key 引用
	// 节点引用清理: 模拟 handleDeleteNode 中的清理流程
	// 注意: 这里不通过 DeleteNode (需要节点记录), 直接测 DNS key 引用清理
	if err := s.RemoveNodeFromDNSKeys("node-1"); err != nil {
		t.Fatalf("RemoveNodeFromDNSKeys 失败: %v", err)
	}

	loaded, _ := s.LoadDNSKeys()

	// 验证: node-1 不应出现在任何 key 的 used_by_nodes 中
	for keyName, rec := range loaded {
		for _, n := range rec.UsedByNodes {
			if n == "node-1" {
				t.Errorf("node-1 不应在 %s 的 used_by_nodes 中 (节点已删除)", keyName)
			}
		}
	}

	// 验证其他节点不受影响
	for _, n := range loaded["key-A"].UsedByNodes {
		if n != "node-2" {
			t.Errorf("key-A 应只有 node-2, 但出现 %s", n)
		}
	}
	if len(loaded["key-A"].UsedByNodes) != 1 {
		t.Errorf("key-A used_by_nodes 应为1个, 实际 %d", len(loaded["key-A"].UsedByNodes))
	}
}

// TestTrackDNSKeyUsage_UnknownKey_Abnormal
// 异常场景: TrackDNSKeyUsage 追踪不存在的 DNS key → 不应报错, 不应 panic。
// 同时验证: RemoveNodeFromDNSKeys 在缓存为空 (刚启动) 时正确初始化。
func TestTrackDNSKeyUsage_UnknownKey_Abnormal(t *testing.T) {
	s, _ := NewStore(t.TempDir())

	// 异常1: 空缓存 — RemoveNodeFromDNSKeys 应无报错
	if err := s.RemoveNodeFromDNSKeys("ghost-node"); err != nil {
		t.Fatalf("空缓存 RemoveNodeFromDNSKeys 不应失败: %v", err)
	}

	// 异常2: TrackDNSKeyUsage 不存在的 key — 应静默返回 nil
	if err := s.TrackDNSKeyUsage("不存在的Key", "node-1"); err != nil {
		t.Errorf("TrackDNSKeyUsage 不存在的 key 不应失败: %v", err)
	}

	// 异常3: 空 key 名称
	if err := s.TrackDNSKeyUsage("", "node-1"); err != nil {
		t.Errorf("TrackDNSKeyUsage 空 key 名不应失败: %v", err)
	}

	// 验证: 空 key 追踪后缓存中不应出现异常条目
	loaded, _ := s.LoadDNSKeys()
	if len(loaded) > 0 {
		t.Error("空缓存中追踪不存在的 key 不应创建任何条目")
	}

	// 异常4: 正常创建 key → Remove → 再次 Remove (幂等)
	keys := map[string]*model.DNSKeyRecord{
		"key-A": {Name: "key-A", Provider: "alidns", UsedByNodes: []string{"node-1"}},
	}
	s.SaveDNSKeys(keys)

	// 第一次 Remove
	if err := s.RemoveNodeFromDNSKeys("node-1"); err != nil {
		t.Fatalf("第一次 RemoveNodeFromDNSKeys 失败: %v", err)
	}

	// 第二次 Remove (幂等 — 节点已不在列表中)
	if err := s.RemoveNodeFromDNSKeys("node-1"); err != nil {
		t.Fatalf("幂等 RemoveNodeFromDNSKeys 不应失败: %v", err)
	}

	loaded, _ = s.LoadDNSKeys()
	for _, n := range loaded["key-A"].UsedByNodes {
		if n == "node-1" {
			t.Error("node-1 应在两次 Remove 后从 key-A 中消失")
		}
	}
}
