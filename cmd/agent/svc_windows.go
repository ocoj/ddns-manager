//go:build windows

package main

import (
	"log"
	"time"

	"github.com/kk/ddns-manager/internal/model"
	"golang.org/x/sys/windows/svc"
)

type agentService struct {
	cfg    *model.AgentConfig
	stopCh chan struct{}
}

func (s *agentService) Execute(args []string, r <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	const cmdsAccepted = svc.AcceptStop | svc.AcceptShutdown
	status <- svc.Status{State: svc.StartPending}

	s.stopCh = make(chan struct{})

	go func() {
		// v1.5.33: Windows Service 初始化延迟到此处, main() 零 I/O 阻塞
		detectInstallDir()
		initAgentLog()
		log.Printf("[daemon] Windows Service started, version=%s", version)
		// v1.5.20 H1: 心跳失败后 30s×3 快速重试，防止网络抖动导致 DNS 中断 5 分钟
		doHeartbeatWithRetry := func() {
			if err := doHeartbeat(s.cfg); err != nil {
				log.Printf("[daemon] 心跳失败: %v", err)
				// 快速重试: 30s × 3 次，使用 select+stopCh 可中断
				for i := 0; i < 3; i++ {
					select {
					case <-time.After(30 * time.Second):
						log.Printf("[daemon] 第%d次重试...", i+1)
						if err := doHeartbeat(s.cfg); err != nil {
							log.Printf("[daemon] 重试%d失败: %v", i+1, err)
						} else {
							log.Printf("[daemon] 重试%d成功", i+1)
							return
						}
					case <-s.stopCh:
						return
					}
				}
				log.Printf("[daemon] 3次重试均失败, 等待下一轮心跳周期")
			}
		}
		// 首次心跳（带重试）
		doHeartbeatWithRetry()
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				doHeartbeatWithRetry()
			case <-s.stopCh:
				log.Printf("[daemon] Windows 服务正在停止")
				return
			}
		}
	}()

	status <- svc.Status{State: svc.Running, Accepts: cmdsAccepted}
	log.Printf("[daemon] Windows Service started, version=%s", version)

	for {
		c := <-r
		switch c.Cmd {
		case svc.Interrogate:
			status <- c.CurrentStatus
		case svc.Stop, svc.Shutdown:
			log.Printf("[daemon] 收到停止信号")
			status <- svc.Status{State: svc.StopPending}
			close(s.stopCh)
			// v1.5.20 H2: 可中断等待，SCM 重复 stop 时不再阻塞
			select {
			case <-time.After(3 * time.Second):
			case <-s.stopCh:
			}
			return false, 0
		}
	}
}

func runWindowsService(cfg *model.AgentConfig) {
	if err := svc.Run("node-agent", &agentService{cfg: cfg}); err != nil {
		log.Fatalf("[daemon] service failed: %v", err)
	}
}
