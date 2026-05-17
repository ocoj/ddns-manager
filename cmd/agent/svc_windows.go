//go:build windows

package main

import (
	"errors"
	"log"
	"time"

	"github.com/kk/ddns-manager/internal/model"
	"golang.org/x/sys/windows/svc"
)

type agentService struct {
	cfg             *model.AgentConfig
	stopCh          chan struct{}
	upgradeShutdown chan struct{} // v1.6.12 C6: 升级触发SCM标准退出通道
}

func (s *agentService) Execute(args []string, r <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	const cmdsAccepted = svc.AcceptStop | svc.AcceptShutdown
	status <- svc.Status{State: svc.StartPending}

	s.stopCh = make(chan struct{})
	// v1.6.12 C6: 升级退出通道 — replaceRunningBinary 关闭此通道触发干净退出
	s.upgradeShutdown = make(chan struct{})
	upgradeShutdownCh = s.upgradeShutdown

	go func() {
		// v1.5.33: Windows Service 初始化延迟到此处, main() 零 I/O 阻塞
		// v1.6.10 M6: ensureSymlink 是 Linux-only (Windows 不使用符号链接),
		// 此处无需调用
		detectInstallDir()
		initAgentLog()
		log.Printf("[daemon] Windows Service started, version=%s", version)
		// v1.5.20 H1+v1.6.29 M5: 心跳失败后 30s×3 快速重试 (认证失败不重试)
		doHeartbeatWithRetry := func() {
			if err := doHeartbeat(s.cfg); err != nil {
				log.Printf("[daemon] 心跳失败: %v", err)
				// v1.6.29 M5: 认证失败 (401/403) 不重试 — 凭证无效, 重试无意义
				if errors.Is(err, errAuthFailed) {
					log.Printf("[daemon] 认证失败, 跳过重试 (请检查节点凭证或审批状态)")
					return
				}
				for i := 0; i < 3; i++ {
					select {
					case <-time.After(30 * time.Second):
						log.Printf("[daemon] 第%d次重试...", i+1)
						if err := doHeartbeat(s.cfg); err != nil {
							log.Printf("[daemon] 重试%d失败: %v", i+1, err)
							if errors.Is(err, errAuthFailed) {
								log.Printf("[daemon] 认证失败(重试中), 停止重试")
								return
							}
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

	// v1.6.12 C6: select 同时监听 SCM 控制请求 和 升级退出信号
	for {
		select {
		case c := <-r:
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
		case <-s.upgradeShutdown:
			// v1.6.12 C6: 升级触发 — 通过SCM标准协议退出进程
			// 助手上已调度: ping等待3s→move新二进制→sc config auto→sc start
			log.Printf("[daemon] 升级触发服务停止 (SCM标准退出)")
			status <- svc.Status{State: svc.StopPending}
			close(s.stopCh)
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
