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
		// initial heartbeat
		if err := doHeartbeat(s.cfg); err != nil {
			log.Printf("[daemon] 首次心跳失败: %v", err)
		}
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				if err := doHeartbeat(s.cfg); err != nil {
					log.Printf("[daemon] 心跳失败: %v", err)
				}
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
			time.Sleep(3 * time.Second)
			return false, 0
		}
	}
}

func runWindowsService(cfg *model.AgentConfig) {
	if err := svc.Run("node-agent", &agentService{cfg: cfg}); err != nil {
		log.Fatalf("[daemon] service failed: %v", err)
	}
}
