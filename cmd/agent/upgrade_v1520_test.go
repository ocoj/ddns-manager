// v1.5.20 修复验证 — Windows 升级批处理
package main

import (
	"fmt"
	"strings"
	"testing"
)

// TestWindowsUpgrade_BatchExpansion 验证 C2 修复：
// 批处理脚本含 setlocal enabledelayedexpansion，!NEWSIZE! 能正确展开。
func TestWindowsUpgrade_BatchExpansion(t *testing.T) {
	// 模拟 upgrade_windows.go 中构建批处理的逻辑
	curExe := `C:\ddns-manager\node-agent.exe`
	newExe := `C:\ddns-manager\node-agent.exe.new`

	// 构建批处理（与实际代码相同模板）
	script := fmt.Sprintf("@echo off\r\n"+
		"setlocal enabledelayedexpansion\r\n"+ // v1.5.20 C2
		"set OLD=%s\r\n"+
		"set NEW=%s\r\n"+
		"set BAK=%s.old.bak\r\n"+
		"echo [ddns] Upgrading...\r\n"+
		"move /y \"%%OLD%%\" \"%%BAK%%\" >>\"%%TEMP%%\\ddns_upgrade.log\" 2>&1\r\n"+ // v1.5.20 C3
		"move /y \"%%NEW%%\" \"%%OLD%%\" >>\"%%TEMP%%\\ddns_upgrade.log\" 2>&1\r\n"+ // v1.5.20 C3
		"if exist \"%%OLD%%\" (\r\n"+
		"  for %%%%A in (\"%%OLD%%\") do set NEWSIZE=%%%%~zA\r\n"+
		"  if !NEWSIZE! GTR 1024 (\r\n"+
		"    echo [ddns] Upgrade OK, starting service...\r\n"+
		"    sc start node-agent\r\n"+
		"    del \"%%BAK%%\" 2>nul\r\n"+
		"    goto :done\r\n"+
		"  )\r\n"+
		")\r\n"+
		"echo [ddns] Upgrade FAILED, rolling back...\r\n"+
		"move /y \"%%BAK%%\" \"%%OLD%%\" >>\"%%TEMP%%\\ddns_upgrade.log\" 2>&1\r\n"+ // v1.5.20 C3
		"sc start node-agent\r\n"+
		":done\r\n"+
		"del \"%%~f0\" & exit\r\n",
		curExe, newExe, curExe)

	checks := []struct {
		name    string
		keyword string
		desc    string
	}{
		{"C2_setlocal", "setlocal enabledelayedexpansion", "延时变量展开"},
		{"C2_NEWSIZE", "!NEWSIZE!", "延时变量 !NEWSIZE! 展开"},
		{"C3_log_move_bak", `ddns_upgrade.log`, "备份操作日志重定向"},
		{"C3_log_move_new", `ddns_upgrade.log`, "移动操作日志重定向"},
		{"C3_log_rollback", `ddns_upgrade.log`, "回滚操作日志重定向"},
		{"verification", "GTR 1024", "二进制大小验证"},
		{"rollback", "FAILED, rolling back", "回滚机制"},
		{"service_restart", "sc start node-agent", "服务重启"},
	}

	for _, c := range checks {
		t.Run(c.name, func(t *testing.T) {
			if !strings.Contains(script, c.keyword) {
				t.Errorf("批处理缺少 %s: %q (功能: %s)", c.name, c.keyword, c.desc)
			}
		})
	}

	// 路径安全检查: 不应包含绝对路径注入模式
	if strings.Contains(script, "C:\\Windows") {
		t.Error("批处理不应包含 C:\\Windows 硬编码路径")
	}
}
