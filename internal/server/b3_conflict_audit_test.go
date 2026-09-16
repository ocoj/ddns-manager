package server

// v1.6.73 B-3（T64b）：受管键冲突的 **Server 侧通道语义**：
//   ① 类别「证书 meta 受管键被权威覆盖」，级别 warning（不含值）
//   ② 跨 flush 去重：重复上报 ⇒ 恰好 1 条
//   ③ 不触发 fail-fast，也不得为 error 级

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestT64b_CertMetaConflict_IsolatedWarningChannel(t *testing.T) {
	s, _, dataDir := newCertConsistencyServer(t)
	s.reportCertMetaConflict("acme-x", "domains")
	s.flushAcmeWireIssues()
	s.reportCertMetaConflict("acme-x", "domains") // 重复 ⇒ 必须被跨 flush 去重
	s.flushAcmeWireIssues()

	if got := countInLog(t, dataDir, "受管键被权威覆盖"); got != 1 {
		t.Errorf("受管键冲突审计应恰好 1 条（跨 flush 去重），实际 %d", got)
	}
	if got := countInLog(t, dataDir, "acme.sh home 解析失败"); got != 0 {
		t.Errorf("受管键冲突不得进入 fail-fast 通道，实际 %d", got)
	}
	b, err := os.ReadFile(filepath.Join(dataDir, "events.log"))
	if err != nil {
		t.Fatalf("读 events.log: %v", err)
	}
	ev := string(b)
	if !strings.Contains(ev, `"action":"证书 meta 受管键被权威覆盖"`) || !strings.Contains(ev, `"status":"warning"`) {
		t.Errorf("events 应含该冲突的 warning 记录（含键名、不含值）")
	}
}
