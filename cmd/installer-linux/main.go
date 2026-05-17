//go:build linux

// ddns-manager Linux installer — lightweight interactive wizard.
// Entry point: install.sh → downloads installer + agent → runs this.
package main

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
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

var defaultBaseDir = "/opt/ddns-agent"

func main() {
	managerURL := flag.String("manager-url", "", "manager server URL")
	nodeName := flag.String("name", "", "node name")
	installDir := flag.String("dir", "", "install directory (default: /opt/ddns-agent)")
	insecure := flag.Bool("insecure", false, "skip TLS verification")
	uninstall := flag.Bool("uninstall", false, "remove all traces")
	agentFile := flag.String("agent-file", "", "path to pre-downloaded agent binary (from install.sh)")
	flag.Parse()

	if *uninstall {
		installer.UninstallAgent(defaultBaseDir)
		fmt.Println("[OK] 卸载完成")
		return
	}

	if !installer.IsRoot() {
		log.Fatal("需要 root 权限，请用 sudo 运行")
	}

	runInstall(*managerURL, *nodeName, *installDir, *insecure, *agentFile)
}

// Default path to agent.yaml in the install directory.
// Must match the path that the agent binary reads (see cmd/agent/main.go:init()).
var agentConfigPath string

func runInstall(managerURL, nodeName, installDirParam string, insecure bool, agentFilePath string) {
	reader := bufio.NewReader(os.Stdin)

	hostname, _ := os.Hostname()
	fmt.Println("+==========================================+")
	fmt.Println("|     ddns-manager v2 安装向导 (Linux)      |")
	fmt.Printf("|     v%-35s|\n", version)
	fmt.Println("+==========================================+")
	fmt.Printf("  主机名: %s\n\n", hostname)

	// ── Install directory ──
	baseDir := defaultBaseDir
	if installDirParam != "" {
		baseDir = installDirParam
		for {
			if filepath.IsAbs(baseDir) {
				break
			}
			fmt.Printf("  [!] 必须是绝对路径 (如 %s)\n", defaultBaseDir)
			fmt.Printf("  安装目录 [默认 %s]: ", defaultBaseDir)
			input, _ := installer.ReadLine(reader)
			input = strings.TrimSpace(input)
			if input == "" {
				baseDir = defaultBaseDir
				break
			}
			baseDir = input
		}
	}
	agentConfigPath = filepath.Join(baseDir, "agent.yaml")

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
			installer.StopAgent()

			binPath := findAgentFile(agentFilePath)
			if binPath == "" {
				log.Fatal("未找到 Agent 二进制，请检查 install.sh 是否正确下载")
			}
			agentBin := filepath.Join(baseDir, "node-agent")
			fmt.Printf("  安装 %s ... ", filepath.Base(binPath))
			if err := installer.CopyFile(binPath, agentBin); err != nil {
				log.Fatalf("复制 Agent 失败: %v", err)
			}
			os.Chmod(agentBin, 0755)
			fmt.Println("[OK]")

			installer.StartAgent()
			fmt.Println()
			fmt.Println("  [OK] 升级完成，配置未变")
			return
		}

		fmt.Println()
		fmt.Println("  [清除] 正在清理旧配置...")
		installer.StopAgent()
		os.Remove(agentConfigPath)
		os.Remove(filepath.Join(baseDir, "node-agent"))
		os.Remove(filepath.Join(baseDir, "ddns_cache.yaml"))
		fmt.Println("  [OK] 旧配置和服务已清理")
	}

	// ── Fresh install ──

	// Step 0: Environment check (ddns-go conflict)
	fmt.Println()
	fmt.Println("  [0/4] 环境检查")
	ddnsGoConflict := detectDDNSGo()
	if len(ddnsGoConflict) > 0 {
		fmt.Println()
		fmt.Println("  [!] 检测到已安装 ddns-go:")
		for _, item := range ddnsGoConflict {
			fmt.Printf("    · %s\n", item)
		}
		fmt.Print("  是否清除？[y/N]: ")
		confirm, _ := installer.ReadLine(reader)
		if strings.TrimSpace(strings.ToLower(confirm)) != "y" {
			log.Fatal("安装取消 — ddns-go 冲突未解决")
		}
		cleanDDNSGo()
		fmt.Println("  [OK] ddns-go 已清除")
	} else {
		fmt.Println("  [OK] 未检测到冲突")
	}

	// Step 1: Manager URL
	time.Sleep(300 * time.Millisecond)
	fmt.Println()
	fmt.Println("  [1/4] 管理端地址")
	baseURL := ""
	if managerURL == "" {
		for {
			fmt.Print("  管理端地址 (如 https://your-server.com:30443): ")
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
			if err := testConnection(baseURL, insecure); err != nil {
				fmt.Printf("失败: %v\n", err)
				continue
			}
			fmt.Println("[OK]")
			break
		}
	} else {
		baseURL = strings.TrimRight(managerURL, "/")
		fmt.Printf("  管理端: %s\n", baseURL)
		fmt.Printf("  测试连接 ... ")
		if err := testConnection(baseURL, insecure); err != nil {
			log.Fatalf("连接失败: %v", err)
		}
		fmt.Println("[OK]")
	}

	// Step 2: Node name + fingerprint
	time.Sleep(300 * time.Millisecond)
	fmt.Println()
	fmt.Println("  [2/4] 节点名称")
	machineID, err := installer.GetMachineID()
	if err != nil {
		log.Fatalf("无法获取机器标识: %v", err)
	}
	fingerprint := installer.GenerateFingerprint(machineID)

	if nodeName == "" {
		fmt.Print("  节点名称 (如 client-a): ")
		var err error
		nodeName, err = installer.ReadLine(reader)
		if err != nil {
			log.Fatal("取消安装")
		}
		nodeName = strings.TrimSpace(nodeName)
		if nodeName == "" {
			log.Fatal("节点名称不能为空")
		}
	}

	// Pre-check: fingerprint conflict on manager
	exists, existingFP := checkNodeFingerprint(baseURL, nodeName, insecure)
	if exists {
		if existingFP == fingerprint {
			fmt.Printf("  [!] 节点名 %q 指纹匹配 — 这是旧机重装\n", nodeName)
		} else {
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
				e2, fp2 := checkNodeFingerprint(baseURL, newName, insecure)
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
	binPath := findAgentFile(agentFilePath)
	if binPath == "" {
		log.Fatal("未找到 Agent 二进制\n  确保 install.sh 已将 node-agent-v*-linux-* 下载到同目录")
	}
	agentBin := filepath.Join(baseDir, "node-agent")
	fmt.Printf("  安装 %s ... ", filepath.Base(binPath))
	if err := installer.CopyFile(binPath, agentBin); err != nil {
		log.Fatalf("复制 Agent 失败: %v", err)
	}
	os.Chmod(agentBin, 0755)
	fmt.Println("[OK]")

	// Step 4: Register + write config + install service
	time.Sleep(300 * time.Millisecond)
	fmt.Println()
	fmt.Println("  [4/4] 安装服务")

	// v1.6.33 P10: 始终调用注册API
	// Manager端指纹匹配时只更新密码,不重建节点(审批/配置/证书均保留)
	var password string
	password = installer.GeneratePassword()
	if err := registerNode(baseURL, nodeName, fingerprint, password, insecure); err != nil {
		if strings.Contains(err.Error(), "409") || strings.Contains(err.Error(), "已注册") {
			fmt.Printf("  [!] 节点名被其他机器占用, 请换名或联系管理员\n")
			os.Exit(1)
		}
		fmt.Printf("  [!] 注册失败: %v\n", err)
	}

	cfg := &model.AgentConfig{
		ManagerURL:  baseURL,
		NodeID:      nodeName,
		Fingerprint: fingerprint,
		Password:    password,
		CertPath:    filepath.Join(baseDir, "certs"),
		VerifySSL:   !insecure,
	}
	if err := installer.SaveConfig(cfg, agentConfigPath); err != nil {
		log.Fatalf("写入配置失败: %v", err)
	}
	fmt.Printf("  配置已写入: %s\n", agentConfigPath)

	if err := installer.InstallService(baseDir); err != nil {
		log.Fatalf("安装系统服务失败: %v", err)
	}
	fmt.Println("  [OK] systemd 服务已安装")

	fmt.Println()
	fmt.Println("  +========================================+")
	fmt.Printf("  |  安装完成!                               |\n")
	fmt.Printf("  |  节点名: %-31s|\n", nodeName)
	fmt.Printf("  |  安装目录: %-29s|\n", baseDir)
	fmt.Println("  |  请登录管理端 WebUI 审批并配置该节点      |")
	fmt.Println("  +========================================+")
}

// ── Helpers ──

// findAgentFile locates the agent binary: -agent-file flag > local directory scan.
func findAgentFile(agentFilePath string) string {
	if agentFilePath != "" {
		if _, err := os.Stat(agentFilePath); err == nil {
			return agentFilePath
		}
	}
	if found := installer.FindLocalAgent(installer.ExeDir()); found != "" {
		return found
	}
	return ""
}

// ── HTTP client (lightweight, no external deps) ──

type httpClient struct {
	insecure bool
	timeout  time.Duration
}

func (c *httpClient) client() *http.Client {
	hc := &http.Client{Timeout: c.timeout}
	if c.insecure {
		hc.Transport = &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	}
	return hc
}

func (c *httpClient) Get(url string) (*http.Response, error) {
	return c.client().Get(url)
}

func (c *httpClient) Post(url, contentType string, body []byte) error {
	resp, err := c.client().Post(url, contentType, strings.NewReader(string(body)))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return nil
}

func testConnection(baseURL string, insecure bool) error {
	client := &httpClient{insecure: insecure, timeout: 10 * time.Second}
	resp, err := client.Get(baseURL + "/api/ping")
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return nil
}

// ── ddns-go detection ──

func detectDDNSGo() []string {
	var items []string
	if _, err := os.Stat("/usr/bin/ddns-go"); err == nil {
		items = append(items, "/usr/bin/ddns-go")
	}
	for _, dir := range []string{"/etc/systemd/system", "/usr/lib/systemd/system"} {
		if _, err := os.Stat(filepath.Join(dir, "ddns-go.service")); err == nil {
			items = append(items, "systemd service: ddns-go")
			break
		}
	}
	return items
}

func cleanDDNSGo() {
	exec.Command("systemctl", "stop", "ddns-go").Run()
	exec.Command("systemctl", "disable", "ddns-go").Run()
	os.Remove("/etc/systemd/system/ddns-go.service")
	os.Remove("/usr/lib/systemd/system/ddns-go.service")
	os.Remove("/usr/bin/ddns-go")
	os.Remove("/opt/ddns-go")
	exec.Command("systemctl", "daemon-reload").Run()
}

// ── Networking ──

func registerNode(baseURL, nodeName, fingerprint, password string, insecure bool) error {
	body, _ := json.Marshal(map[string]string{
		"node_id":     nodeName,
		"fingerprint": fingerprint,
		"password":    password,
	})
	client := &httpClient{insecure: insecure, timeout: 15 * time.Second}
	return client.Post(baseURL+"/api/register", "application/json", body)
}

type checkResult struct {
	Exists      bool   `json:"exists"`
	Fingerprint string `json:"fingerprint"`
}

func checkNodeFingerprint(baseURL, nodeName string, insecure bool) (bool, string) {
	client := &httpClient{insecure: insecure, timeout: 10 * time.Second}
	resp, err := client.Get(baseURL + "/api/nodes/" + nodeName + "/fingerprint")
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
