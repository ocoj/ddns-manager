package server

// v1.6.73 B-2（T60）：非判定性提示的 **Server 侧通道语义**（物理隔离）：
//   ① 类别 = "home 告警"，级别 = warning（不得 error）
//   ② 跨 flush 去重：同一 (action, detail) 重复采集 ⇒ 恰好 1 条
//   ③ 不触发 fail-fast（fail-fast 只认 action 含「home 解析失败」）
//
// 说明：caveats 的**产生**由 internal/acme 的 T59 覆盖（真实 FS + 祖先组可写）；
// 本测试直接驱动通道层，避免依赖 tmpLike 祖先是否被排除等实现细节。

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestT60_HomeCaveats_IsolatedWarningChannel(t *testing.T) {
	s, _, dataDir := newCertConsistencyServer(t)
	caveat := "祖先目录 /x 对 group/other 可写"

	s.reportAcmeCaveats([]string{caveat})
	s.flushAcmeWireIssues()
	s.reportAcmeCaveats([]string{caveat}) // 重复采集 ⇒ 必须被跨 flush 去重
	s.flushAcmeWireIssues()

	if got := countInLog(t, dataDir, "home 告警"); got != 1 {
		t.Errorf("「home 告警」应恰好 1 条（跨 flush 去重），实际 %d", got)
	}
	if got := countInLog(t, dataDir, "acme.sh home 解析失败"); got != 0 {
		t.Errorf("caveats 不得进入 fail-fast 通道，实际 %d", got)
	}
	b, err := os.ReadFile(filepath.Join(dataDir, "events.log"))
	if err != nil {
		t.Fatalf("读 events.log: %v", err)
	}
	ev := string(b)
	if !strings.Contains(ev, `"action":"home 告警"`) {
		t.Errorf("events 中缺少 home 告警 记录")
	}
	if !strings.Contains(ev, `"status":"warning"`) {
		t.Errorf("home 告警 必须以 warning 落盘（不得 error）")
	}
}
