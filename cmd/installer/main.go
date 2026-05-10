// ddns-manager installer — lightweight install wizard (no ddns-go deps).
// Downloads the full agent binary from the manager during installation.
package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/kk/ddns-manager/internal/model"
	"gopkg.in/yaml.v3"
)

var version = "dev"

// base paths
var (
	agentBaseDir    string
	agentConfigPath string
	defaultCertPath string
)

func init() {
	if runtime.GOOS == "windows" {
		agentBaseDir = `C:\ddns-manager`
	} else {
		agentBaseDir = "/opt/ddns-manager"
	}
	agentConfigPath = filepath.Join(agentBaseDir, "agent.yaml")
	defaultCertPath = filepath.Join(agentBaseDir, "certs")
}

// ========== main ==========

func main() {
	managerURL := flag.String("manager-url", "", "manager server URL")
	nodeName := flag.String("name", "", "node name")
	installDir := flag.String("dir", "", "install directory")
	insecure := flag.Bool("insecure", false, "skip TLS verification")
	uninstall := flag.Bool("uninstall", false, "remove all traces")
	flag.Parse()

	if *uninstall {
		runUninstall()
		return
	}

	runInstall(*managerURL, *nodeName, *installDir, *insecure)
}

// ========== install wizard ==========

func runInstall(managerURL, nodeName, installDir string, insecure bool) {
	reader := bufio.NewReader(os.Stdin)

	if runtime.GOOS == "windows" {
		exec.Command("chcp", "65001").Run()
	}

	// 统一使用 Go 标准架构名 (amd64/arm64/arm)，不再映射为 x86_64/i386
	// 构建脚本产物与下载 URL 均以此为标准，避免名称不匹配导致 404
	goos := runtime.GOOS
	goarch := runtime.GOARCH
	switch goarch {
	case "386":
		goarch = "i386" // 历史兼容：Go → deb 命名
	case "arm":
		// runtime.GOARCH 对 armv7 也是 "arm"，保持不变
	}

	hostname, _ := os.Hostname()
	osName := goos + "/" + goarch
	if data, err := os.ReadFile("/etc/os-release"); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			if strings.HasPrefix(line, "PRETTY_NAME=") {
				osName = strings.Trim(strings.TrimPrefix(line, "PRETTY_NAME="), "\"")
				break
			}
		}
	}

	client := &http.Client{Timeout: 10 * time.Second}
	if insecure {
		client.Transport = &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	}

	fmt.Println("+==========================================+")
	fmt.Println("|     ddns-manager v2 安装向导              |")
	fmt.Printf("|     v%-35s|\n", version)
	fmt.Println("+==========================================+")
	fmt.Printf("  系统: %s  主机名: %s\n\n", osName, hostname)

	// Step 0/5: detect & clean old ddns-go
	stepWait(0, 5, "检测旧 ddns-go 服务")
	ddnsInfo := detectOldDDNS()
	if ddnsInfo != "" {
		fmt.Printf("  [!] 检测到旧 ddns-go: %s\n", ddnsInfo)
		fmt.Print("  是否完全清除（服务+程序+配置）？[y/N]: ")
		confirm, _ := reader.ReadString('\n')
		if strings.TrimSpace(strings.ToLower(confirm)) != "y" {
			fmt.Println("  [FAIL] 用户取消")
			os.Exit(1)
		}
		cleanOldDDNS()
		fmt.Println("  [OK] 已清除")
	} else {
		fmt.Println("  [OK] 未检测到旧 ddns-go")
	}

	// Step 1/5: manager URL + connectivity test
	stepWait(1, 5, "管理端地址")
	if managerURL == "" {
		for {
			fmt.Print("  管理端地址 (如 http://192.168.1.100:9877): ")
			managerURL, _ = reader.ReadString('\n')
			managerURL = strings.TrimSpace(managerURL)
			if managerURL == "" {
				continue
			}
			fmt.Printf("  测试连接 %s/api/ping ... ", strings.TrimRight(managerURL, "/"))
			resp, err := client.Get(strings.TrimRight(managerURL, "/") + "/api/ping")
			if err != nil {
				fmt.Printf("失败: %v\n  请重试\n", err)
				continue
			}
			resp.Body.Close()
			if resp.StatusCode == 200 {
				fmt.Println("[OK]")
				break
			}
			fmt.Printf("HTTP %d\n", resp.StatusCode)
		}
	} else {
		fmt.Printf("  测试连接 %s ... ", managerURL)
		resp, err := client.Get(strings.TrimRight(managerURL, "/") + "/api/ping")
		if err != nil || resp.StatusCode != 200 {
			if resp != nil {
				resp.Body.Close()
			}
			log.Fatalf("管理端连接失败: %v", err)
		}
		resp.Body.Close()
		fmt.Println("[OK]")
	}
	baseURL := strings.TrimRight(managerURL, "/")

	// Step 2/5: install directory
	stepWait(2, 5, "安装目录")
	if installDir == "" {
		fmt.Printf("  安装目录 [默认 %s]: ", agentBaseDir)
		input, _ := reader.ReadString('\n')
		input = strings.TrimSpace(input)
		if input != "" {
			installDir = input
		}
	}
	for installDir != "" {
		if !filepath.IsAbs(installDir) {
			fmt.Printf("  [!] 路径格式不正确，必须是绝对路径 (如 %s)\n", agentBaseDir)
			fmt.Printf("  安装目录 [默认 %s]: ", agentBaseDir)
			input, _ := reader.ReadString('\n')
			input = strings.TrimSpace(input)
			if input == "" {
				installDir = "" // use default
				break
			}
			installDir = input
			continue
		}
		agentBaseDir = installDir
		agentConfigPath = filepath.Join(agentBaseDir, "agent.yaml")
		defaultCertPath = filepath.Join(agentBaseDir, "certs")
		break
	}
	if err := os.MkdirAll(agentBaseDir, 0700); err != nil {
		log.Fatalf("创建目录失败: %v", err)
	}
	fmt.Printf("  [OK] 安装目录: %s\n", agentBaseDir)

	// Step 3/5: node name
	stepWait(3, 5, "节点名称")
	fingerprint := generateFingerprint()
	if nodeName == "" {
		fmt.Print("  节点名称 (如 node-01): ")
		nodeName, _ = reader.ReadString('\n')
		nodeName = strings.TrimSpace(nodeName)
	}

	// same-machine reinstall
	if existingCfg, err := loadConfig(agentConfigPath); err == nil && existingCfg.Fingerprint == fingerprint {
		fmt.Printf("  [!] 同机已有注册: %s\n", existingCfg.NodeID)
		fmt.Print("  是否替换原注册？[Y/n]: ")
		confirm, _ := reader.ReadString('\n')
		if strings.TrimSpace(strings.ToLower(confirm)) != "" && strings.TrimSpace(strings.ToLower(confirm)) != "y" {
			fmt.Println("  [FAIL] 取消")
			os.Exit(1)
		}
		fmt.Printf("  [OK] %s -> %s\n", existingCfg.NodeID, nodeName)
	}

	// uniqueness check
	for {
		checkBody, _ := json.Marshal(map[string]string{
			"node_id": nodeName, "fingerprint": fingerprint, "password": generatePassword(),
		})
		resp, err := client.Post(baseURL+"/api/register", "application/json", bytes.NewReader(checkBody))
		if err == nil && resp.StatusCode == 409 {
			resp.Body.Close()
			fmt.Printf("  [!] 名称 '%s' 已占用\n", nodeName)
			fmt.Print("  新名称: ")
			n, _ := reader.ReadString('\n')
			n = strings.TrimSpace(n)
			if n == "" {
				os.Exit(1)
			}
			nodeName = n
			continue
		}
		if resp != nil {
			resp.Body.Close()
		}
		break
	}
	fmt.Printf("  [OK] 节点名: %s\n", nodeName)

	// Step 4/5: download agent binary — 使用版本化文件名
	stepWait(4, 5, "下载 Agent")
	agentName := "node-agent-v" + version + "-" + goos + "-" + goarch
	agentBin := filepath.Join(agentBaseDir, agentName)
	agentLink := filepath.Join(agentBaseDir, "node-agent")
	if runtime.GOOS == "windows" {
		agentBin += ".exe"
		agentLink += ".exe"
	}

	// determine download URL from manifest
	agentURL := baseURL + "/bin/node-agent-" + goos + "-" + goarch
	if runtime.GOOS == "windows" {
		agentURL += ".exe"
	}

	fmt.Printf("  下载 %s ... ", agentURL)
	if err := retryDo(3, "下载 agent", func() error {
		resp, err := client.Get(agentURL)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if resp.StatusCode != 200 {
			return fmt.Errorf("HTTP %d", resp.StatusCode)
		}
		f, err := os.Create(agentBin)
		if err != nil {
			return err
		}
		defer f.Close()
		_, err = io.Copy(f, resp.Body)
		return err
	}); err != nil {
		// fallback: try common names
		fmt.Println("失败，尝试备选名称...")
		for _, name := range []string{
			"node-agent-latest", "node-agent-v2",
			"node-agent-linux-amd64", "node-agent-linux-x86_64", "node-agent-windows-amd64.exe",
		} {
			u := baseURL + "/bin/" + name
			fmt.Printf("  尝试 %s ... ", u)
			resp, err := client.Get(u)
			if err == nil && resp.StatusCode == 200 {
				f, _ := os.Create(agentBin)
				io.Copy(f, resp.Body)
				f.Close()
				resp.Body.Close()
				fmt.Println("[OK]")
				break
			}
			if resp != nil {
				resp.Body.Close()
			}
			fmt.Println("失败")
		}
	}

	if _, err := os.Stat(agentBin); err != nil {
		log.Fatalf("下载失败: 管理端 /bin/ 目录缺少 %s 系统的 agent 二进制", goos)
	}
	os.Chmod(agentBin, 0755)
	// 创建符号链接, systemd 引用 node-agent → 自动指向当前版本
	os.Remove(agentLink)
	if err := os.Symlink(agentName, agentLink); err != nil {
		log.Fatalf("创建符号链接失败: %v", err)
	}
	fmt.Printf("  [OK] Agent 已安装 (%s → %s)\n", agentLink, agentName)

	// Step 5/5: register + install service
	stepWait(5, 5, "注册节点 & 安装服务")
	password := generatePassword()
	cfg := &model.AgentConfig{
		ManagerURL: baseURL, NodeID: nodeName, Fingerprint: fingerprint,
		Password: password, CertPath: defaultCertPath, VerifySSL: !insecure,
	}

	regBody, _ := json.Marshal(map[string]string{
		"node_id": cfg.NodeID, "fingerprint": cfg.Fingerprint, "password": cfg.Password,
	})
	resp, err := client.Post(baseURL+"/api/register", "application/json", bytes.NewReader(regBody))
	if err != nil {
		log.Fatalf("注册请求失败: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 {
		log.Fatalf("注册失败 HTTP %d: %s", resp.StatusCode, string(body))
	}

	if err := saveConfig(cfg, agentConfigPath); err != nil {
		log.Fatalf("保存配置: %v", err)
	}
	fmt.Println("  [OK] 注册成功")

	// install service
	if runtime.GOOS == "windows" {
		binPath := fmt.Sprintf(`"%s" -daemon`, agentLink)
		if serviceExists("node-agent") {
			exec.Command("sc", "stop", "node-agent").Run()
			exec.Command("sc", "delete", "node-agent").Run()
			time.Sleep(time.Second)
		}
		exec.Command("sc", "create", "node-agent",
			"binPath=", binPath, "start=", "auto",
			"DisplayName=", "ddns-manager Node Agent").Run()
		exec.Command("sc", "failure", "node-agent", "reset=", "86400",
			"actions=", "restart/5000").Run()
		exec.Command("sc", "start", "node-agent").Run()
		fmt.Println("  [OK] Windows 服务已安装")
	} else {
		svc := fmt.Sprintf(`[Unit]
Description=ddns-manager Node Agent
After=network-online.target

[Service]
Type=oneshot
ExecStart=%s -heartbeat
`, agentLink)
		timer := `[Unit]
Description=ddns-manager Node Agent Timer

[Timer]
OnBootSec=30s
OnUnitActiveSec=300s
RandomizedDelaySec=30s

[Install]
WantedBy=timers.target
`
		os.WriteFile("/etc/systemd/system/node-agent.service", []byte(svc), 0644)
		os.WriteFile("/etc/systemd/system/node-agent.timer", []byte(timer), 0644)
		exec.Command("systemctl", "daemon-reload").Run()
		exec.Command("systemctl", "enable", "node-agent.timer").Run()
		exec.Command("systemctl", "start", "node-agent.timer").Run()
		fmt.Println("  [OK] systemd timer 已安装 (5分钟)")
	}

	fmt.Println()
	fmt.Println("+==========================================+")
	fmt.Println("|     *** 部署完成!                         |")
	fmt.Println("+==========================================+")
	fmt.Println()
	fmt.Printf("  节点名称: %s\n", cfg.NodeID)
	fmt.Printf("  安装目录: %s\n", agentBaseDir)
	fmt.Println()
	fmt.Println("  [!] 下一步：")
	fmt.Println("     1. 登录管理端 WebUI → 节点页面")
	fmt.Println("     2. 找到此节点，点击「分配」")
	fmt.Println("     3. 选择 DNS 提供商、填入域名、保存")
	fmt.Println("     4. 下次心跳自动下发配置并开始 DDNS")
}

// ========== uninstall ==========

func runUninstall() {
	fmt.Println("正在卸载 ddns-manager...")
	if runtime.GOOS == "windows" {
		exec.Command("sc", "stop", "node-agent").Run()
		exec.Command("sc", "delete", "node-agent").Run()
		os.RemoveAll(`C:\ddns-manager`)
		os.RemoveAll(filepath.Join(os.Getenv("ProgramData"), "ddns-manager"))
	} else {
		exec.Command("systemctl", "stop", "node-agent.timer").Run()
		exec.Command("systemctl", "disable", "node-agent.timer").Run()
		os.Remove("/etc/systemd/system/node-agent.service")
		os.Remove("/etc/systemd/system/node-agent.timer")
		exec.Command("systemctl", "daemon-reload").Run()
		os.RemoveAll("/opt/ddns-manager")
	}
	fmt.Println("[OK] 卸载完成")
}

// ========== ddns-go detection & cleanup ==========

func detectOldDDNS() string {
	var parts []string
	if runtime.GOOS == "windows" {
		if out, _ := exec.Command("sc", "query", "ddns-go").Output(); strings.Contains(string(out), "SERVICE_NAME") {
			parts = append(parts, "Windows服务")
		}
	} else {
		out, _ := exec.Command("systemctl", "is-active", "ddns-go").Output()
		s := strings.TrimSpace(string(out))
		if s == "active" || s == "inactive" {
			parts = append(parts, "systemd("+s+")")
		}
		if _, err := os.Stat("/usr/local/bin/ddns-go"); err == nil {
			parts = append(parts, "程序")
		}
		if _, err := os.Stat("/opt/ddns-go/.ddns_go_config.yaml"); err == nil {
			parts = append(parts, "配置")
		}
		if _, err := os.Stat("/root/.ddns_go_config.yaml"); err == nil {
			parts = append(parts, "配置(/root)")
		}
	}
	return strings.Join(parts, ",")
}

func cleanOldDDNS() {
	if runtime.GOOS == "windows" {
		exec.Command("sc", "stop", "ddns-go").Run()
		exec.Command("sc", "delete", "ddns-go").Run()
		os.RemoveAll(`C:\ddns-go`)
		os.RemoveAll(`C:\ddns-manager\ddns-go`)
		os.RemoveAll(`C:\ddns\ddns-go`)
	} else {
		exec.Command("systemctl", "stop", "ddns-go").Run()
		exec.Command("systemctl", "disable", "ddns-go").Run()
		os.Remove("/etc/systemd/system/ddns-go.service")
		exec.Command("systemctl", "daemon-reload").Run()
		os.Remove("/usr/local/bin/ddns-go")
		os.RemoveAll("/opt/ddns-go")
		os.Remove("/root/.ddns_go_config.yaml")
	}
}

// ========== shared utilities ==========


func generateFingerprint() string {
	hostname, _ := os.Hostname()
	var mid []byte
	if runtime.GOOS == "windows" {
		out, _ := exec.Command("powershell", "-NoProfile", "-Command",
			"(Get-CimInstance Win32_ComputerSystemProduct).UUID").Output()
		mid = out
	} else {
		mid, _ = os.ReadFile("/etc/machine-id")
	}
	h := sha256.Sum256([]byte(hostname + string(mid)))
	return "sha256:" + hex.EncodeToString(h[:])
}

func generatePassword() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		log.Fatalf("随机数生成失败: %v", err)
	}
	return hex.EncodeToString(b)
}

func loadConfig(path string) (*model.AgentConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg model.AgentConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func saveConfig(cfg *model.AgentConfig, path string) error {
	os.MkdirAll(filepath.Dir(path), 0700)
	yamlData, err := yaml.Marshal(cfg)
	if err != nil {
		return err
	}
	return os.WriteFile(path, yamlData, 0600)
}

func retryDo(maxRetries int, desc string, fn func() error) error {
	var lastErr error
	for i := 0; i < maxRetries; i++ {
		lastErr = fn()
		if lastErr == nil {
			return nil
		}
		if i < maxRetries-1 {
			time.Sleep(time.Duration(i+1) * 2 * time.Second)
		}
	}
	return fmt.Errorf("%s: %w (重试%d次)", desc, lastErr, maxRetries)
}

func stepWait(step, total int, title string) {
	time.Sleep(300 * time.Millisecond)
	fmt.Printf("\n  [%d/%d] %s\n", step, total, title)
}

func serviceExists(name string) bool {
	if runtime.GOOS == "windows" {
		return exec.Command("sc", "query", name).Run() == nil
	}
	// Check if systemd unit file exists (in installed paths)
	for _, dir := range []string{"/etc/systemd/system", "/usr/lib/systemd/system", "/run/systemd/system"} {
		if _, err := os.Stat(filepath.Join(dir, name+".service")); err == nil {
			return true
		}
		if _, err := os.Stat(filepath.Join(dir, name+".timer")); err == nil {
			return true
		}
	}
	return false
}


