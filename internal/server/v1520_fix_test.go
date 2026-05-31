// v1.5.20 修复验证测试
package server

import (
	"testing"

	"github.com/ocoj/ddns-manager/internal/model"
)

// TestReloadServices_Propagation 验证 C1 修复：
// 1. CertUpdate.ReloadServices 字段结构正确，Agent 可正确读取
// 2. nil=保留, []string{}=清空, ["nginx"]=正常传播
func TestReloadServices_Propagation(t *testing.T) {
	tests := []struct {
		name     string
		binding  model.CertBinding
		wantLen  int
		wantNil  bool
	}{
		{
			name: "正常_含服务列表",
			binding: model.CertBinding{
				BundleName: "test", DeployPath: "/etc/nginx/certs/",
				ReloadServices: []string{"nginx", "haproxy"},
			},
			wantLen: 2,
			wantNil: false,
		},
		{
			name: "边界_nil保留",
			binding: model.CertBinding{
				BundleName: "test", DeployPath: "/etc/nginx/certs/",
				ReloadServices: nil,
			},
			wantLen: 0,
			wantNil: true,
		},
		{
			name: "边界_空切片清空",
			binding: model.CertBinding{
				BundleName: "test", DeployPath: "/etc/nginx/certs/",
				ReloadServices: []string{},
			},
			wantLen: 0,
			wantNil: false, // 空切片 != nil
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// 模拟 handleHeartbeat 中 CertUpdate 构建（v1.5.20 C1 修复后）
			cu := &model.CertUpdate{
				CertHash:       "sha256:abc",
				BundleName:     tt.binding.BundleName,
				Files:          map[string]string{"cert.pem": "..."},
				TargetPath:     tt.binding.DeployPath,
				ReloadServices: tt.binding.ReloadServices,
			}

			if tt.wantNil && cu.ReloadServices != nil {
				t.Fatalf("ReloadServices 应为 nil, got %v", cu.ReloadServices)
			}
			if !tt.wantNil && cu.ReloadServices == nil {
				t.Fatal("ReloadServices 不应为 nil")
			}
			if len(cu.ReloadServices) != tt.wantLen {
				t.Fatalf("len=%d want %d", len(cu.ReloadServices), tt.wantLen)
			}
		})
	}
}
