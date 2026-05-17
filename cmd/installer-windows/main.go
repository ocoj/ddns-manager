//go:build windows

// ddns-manager Windows installer — lightweight interactive wizard.
// Packaged in ZIP alongside the agent binary for offline installation.
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/kk/ddns-manager/internal/installer"
	"github.com/kk/ddns-manager/internal/model"
)

var version = "dev"

var defaultBaseDir = `C:\ddns-agent`

func main() {
	uninstall := flag.Bool("uninstall", false, "remove all traces")
	flag.Parse()

	if *uninstall {
		installer.UninstallAgent(defaultBaseDir)
		fmt.Println("[OK] 卸载完成")
		return
	}

	runInstall()
}

func runInstall() {
	reader := bufio.NewReader(os.Stdin)
	installer.SetConsoleUTF8()

	if !installer.IsAdmin() {
		fmt.Println("[错误] 请右键以管理员身份运行 install.bat")
		fmt.Println()
		fmt.Print("按任意键退出...")
		installer.ReadLine(reader)
		os.Exit(1)
	}

	hostname, _ := os.Hostname()
	fmt.Println("+==========================================+")
	fmt.Println("|     ddns-manager v2 安装向导 (Windows)    |")
	fmt.Printf("|     v%-35s|\n", version)
	fmt.Println("+==========================================+")
	fmt.Printf("  主机名: %s\n\n", hostname)

	agentConfigPath := filepath.Join(defaultBaseDir, "agent.yaml")

	// ── Upgrade check ──
	if existingCfg, err := installer.LoadConfig(agentConfigPath); err == nil {
		fmt.Println()
		fmt.Println("  +-------------------------------------------+")
		fmt.Println("  |  [!] 检测到已有安装                         |")
		fmt.Printf("  |  节点名: %-34s|\n", existingCfg.NodeID)
		fmt.Printf("  |  管理端: %-34s|\n", existingCfg.ManagerURL)
		fmt.Println("  |                                            |")
		fmt.Println("  |  保留旧配置直接升级？[Y/n]: _                |")
		fmt.Println("  +-------------------------------------------+")
		fmt.Print("  > ")
		choice, _ := installer.ReadLine(reader)
		choice = strings.TrimSpace(strings.ToLower(choice))

		if choice == "" || choice == "y" || choice == "yes" {
			fmt.Println()
			fmt.Println("  [升级] 保留配置，安装最新 Agent ...")
			fmt.Println("  正在停止旧服务 ...")
			installer.StopAgent()

			binPath := installer.FindLocalAgent(installer.ExeDir())
			if binPath == "" {
				log.Fatal("未找到 node-agent-*.exe\n  请确保 ZIP 内所有文件已完整解压到同一目录")
			}
			agentBin := filepath.Join(defaultBaseDir, "node-agent.exe")
			fmt.Printf("  安装 %s ... ", filepath.Base(binPath))
			if err := installer.CopyFile(binPath, agentBin); err != nil {
				log.Fatalf("复制 Agent 失败: %v", err)
			}
			fmt.Println("[OK]")

			fmt.Println("  启动服务 ...")
			installer.StartAgent()
			fmt.Println()
			fmt.Println("  [OK] 升级完成，配置未变")
			return
		}

		fmt.Println()
		fmt.Println("  [清除] 正在清理旧配置...")
		os.Remove(agentConfigPath)
		os.Remove(filepath.Join(defaultBaseDir, "node-agent.exe"))
		os.Remove(filepath.Join(defaultBaseDir, "ddns_cache.yaml"))
		// v1.6.32: 同时卸载旧Windows服务，防止后续注册冲突
		exec.Command("sc", "stop", "node-agent").Run()
		exec.Command("sc", "delete", "node-agent").Run()
		fmt.Println("  [OK] 旧配置和服务已清理")
	}

	// ── Fresh install ──

	// Step 0: Environment check (ddns-go conflict)
	fmt.Println()
	fmt.Println("  [1/4] 环境检查")
	ddnsGoConflict := detectDDNSGoWindows()
	if len(ddnsGoConflict) > 0 {
		fmt.Println("  [!] 检测到已安装 ddns-go:")
		for _, item := range ddnsGoConflict {
			fmt.Printf("    · %s\n", item)
		}
		fmt.Print("  是否清除？[y/N]: ")
		confirm, _ := installer.ReadLine(reader)
		if strings.TrimSpace(strings.ToLower(confirm)) != "y" {
			log.Fatal("安装取消 — ddns-go 冲突未解决")
		}
		cleanDDNSGoWindows()
		fmt.Println("  [OK] ddns-go 已清除")
	} else {
		fmt.Println("  [OK] 未检测到冲突")
	}

	// Step 1: Manager URL
	time.Sleep(300 * time.Millisecond)
	fmt.Println()
	fmt.Println("  [2/4] 管理端地址")
	managerURL := ""
	baseURL := ""
	for {
		fmt.Print("  管理端地址 (如 https://manager.example.com:30443): ")
		var err error
		managerURL, err = installer.ReadLine(reader)
		if err != nil {
			log.Fatal("取消安装")
		}
		managerURL = strings.TrimSpace(managerURL)
		if managerURL == "" {
			fmt.Println("  [!] 地址不能为空")
			continue
		}
		baseURL = strings.TrimRight(managerURL, "/")
		fmt.Printf("  测试连接 %s/api/ping ... ", baseURL)
		pingResp, pingErr := http.Get(baseURL + "/api/ping")
		if pingErr != nil {
			fmt.Printf("失败: %v\n", pingErr)
			fmt.Print("  重新输入, 或输入 Q 退出: ")
			q, _ := installer.ReadLine(reader)
			if strings.ToLower(strings.TrimSpace(q)) == "q" {
				log.Fatal("安装取消")
			}
			continue
		}
		pingBody, _ := io.ReadAll(io.LimitReader(pingResp.Body, 1024))
		pingResp.Body.Close()
		if pingResp.StatusCode != 200 {
			fmt.Printf("HTTP %d (不是 ddns-manager 管理端)\n", pingResp.StatusCode)
			fmt.Print("  重新输入, 或输入 Q 退出: ")
			q, _ := installer.ReadLine(reader)
			if strings.ToLower(strings.TrimSpace(q)) == "q" {
				log.Fatal("安装取消")
			}
			continue
		}
		// 确认是 ddns-manager (检查响应含 version 字段)
		if !strings.Contains(string(pingBody), `"version"`) {
			fmt.Println("不是 ddns-manager 管理端")
			fmt.Print("  重新输入, 或输入 Q 退出: ")
			q, _ := installer.ReadLine(reader)
			if strings.ToLower(strings.TrimSpace(q)) == "q" {
				log.Fatal("安装取消")
			}
			continue
		}
		fmt.Println("[OK]")
		break
	}

	// Step 2: Node name + fingerprint
	time.Sleep(300 * time.Millisecond)
	fmt.Println()
	fmt.Println("  [2/4] 节点名称")
	machineID, err := installer.GetMachineID()
	if err != nil {
		log.Fatalf("无法获取机器标识: %v\n  请以管理员身份运行", err)
	}
	fingerprint := installer.GenerateFingerprint(machineID)

	fmt.Print("  节点名称 (如 win-pc): ")
	nodeName, err := installer.ReadLine(reader)
	if err != nil {
		log.Fatal("取消安装")
	}
	nodeName = strings.TrimSpace(nodeName)
	if nodeName == "" {
		log.Fatal("节点名称不能为空")
	}

	// Pre-check: fingerprint conflict with Manager
	exists, existingFP := checkNodeFingerprint(baseURL, nodeName)
	if exists {
		if existingFP == fingerprint {
			// Same machine → old reinstall, skip registration
			fmt.Printf("  [!] 节点名 %q 指纹匹配 — 这是旧机重装\n", nodeName)
			fmt.Println("  将保留原注册信息，无需重新注册")
		} else {
			// Different machine → name conflict
			fmt.Printf("  [!] 节点名 %q 已被其他机器注册 (指纹不同)\n", nodeName)
			for {
				fmt.Print("  请换一个节点名, 或输入 Q 退出: ")
				newName, _ := installer.ReadLine(reader)
				newName = strings.TrimSpace(newName)
				if strings.ToLower(newName) == "q" {
					log.Fatal("安装取消")
				}
				if newName == "" || newName == nodeName {
					continue
				}
				// Check new name
				e2, fp2 := checkNodeFingerprint(baseURL, newName)
				if e2 && fp2 != fingerprint {
					fmt.Printf("  [!] %q 也被占用, 请换一个\n", newName)
					continue
				}
				nodeName = newName
				break
			}
		}
	}

	// Step 3: Install agent binary (local only)
	time.Sleep(300 * time.Millisecond)
	fmt.Println()
	fmt.Println("  [3/4] 安装 Agent")
	binPath := installer.FindLocalAgent(installer.ExeDir())
	if binPath == "" {
		log.Fatal("未找到 node-agent-*.exe\n  请确保 ZIP 内所有文件已完整解压到同一目录")
	}
	agentBin := filepath.Join(defaultBaseDir, "node-agent.exe")
	fmt.Printf("  安装 %s ... ", filepath.Base(binPath))
	if err := installer.CopyFile(binPath, agentBin); err != nil {
		log.Fatalf("复制 Agent 失败: %v", err)
	}
	fmt.Println("[OK]")

	// Step 4: Register + config + service
	time.Sleep(300 * time.Millisecond)
	fmt.Println()
	fmt.Println("  [4/4] 安装服务")

	// v1.6.32: 指纹匹配时跳过注册(旧机重装), 否则注册新节点
	needRegister := !exists || existingFP != fingerprint
	var password string
	if needRegister {
		password = installer.GeneratePassword()
		if err := registerNode(baseURL, nodeName, fingerprint, password); err != nil {
			fmt.Printf("  [!] 注册失败: %v\n", err)
		}
	} else {
		fmt.Println("  [OK] 指纹匹配，复用原注册信息")
		password = installer.GeneratePassword() // 生成新密码更新本地配置
	}

	cfg := &model.AgentConfig{
		ManagerURL:  baseURL,
		NodeID:      nodeName,
		Fingerprint: fingerprint,
		Password:    password,
		CertPath:    filepath.Join(defaultBaseDir, "certs"),
		VerifySSL:   true,
	}
	if err := installer.SaveConfig(cfg, agentConfigPath); err != nil {
		log.Fatalf("写入配置失败: %v", err)
	}
	fmt.Printf("  配置已写入: %s\n", agentConfigPath)

	if err := installer.InstallService(defaultBaseDir); err != nil {
		log.Fatalf("安装 Windows 服务失败: %v", err)
	}
	fmt.Println("  [OK] Windows 服务已安装")

	if err := installer.StartAgent(); err != nil {
		fmt.Println("  [!] 服务启动失败，请检查日志")
	}

	fmt.Println()
	fmt.Println("  +========================================+")
	fmt.Printf("  |  安装完成!                               |\n")
	fmt.Printf("  |  节点名: %-31s|\n", nodeName)
	fmt.Printf("  |  安装目录: %-29s|\n", defaultBaseDir)
	fmt.Println("  |  请登录管理端 WebUI 审批并配置该节点      |")
	fmt.Println("  +========================================+")
}

// ── Networking ──

func registerNode(baseURL, nodeName, fingerprint, password string) error {
	body, _ := json.Marshal(map[string]string{
		"node_id":     nodeName,
		"fingerprint": fingerprint,
		"password":    password,
	})
	resp, err := http.Post(baseURL+"/api/register", "application/json", strings.NewReader(string(body)))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == 409 {
		return fmt.Errorf("节点名已被注册")
	}
	if resp.StatusCode != 200 {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return nil
}

type checkResult struct {
	Exists      bool   `json:"exists"`
	Fingerprint string `json:"fingerprint"`
}

func checkNodeFingerprint(baseURL, nodeName string) (bool, string) {
	resp, err := http.Get(baseURL + "/api/nodes/" + nodeName + "/fingerprint")
	if err != nil {
		return false, ""
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return false, ""
	}
	var r checkResult
	json.NewDecoder(resp.Body).Decode(&r)
	return r.Exists, r.Fingerprint
}

// ── ddns-go detection (Windows) ──

func detectDDNSGoWindows() []string {
	var items []string
	for _, p := range []string{
		`C:\ddns-go\ddns-go.exe`,
		`C:\Program Files\ddns-go\ddns-go.exe`,
	} {
		if _, err := os.Stat(p); err == nil {
			items = append(items, p)
		}
	}
	if exec.Command("sc", "query", "ddns-go").Run() == nil {
		items = append(items, "Windows 服务: ddns-go")
	}
	return items
}

func cleanDDNSGoWindows() {
	exec.Command("sc", "stop", "ddns-go").Run()
	exec.Command("sc", "delete", "ddns-go").Run()
	os.RemoveAll(`C:\ddns-go`)
}
