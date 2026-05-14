// ddns-manager installer — lightweight install wizard (no ddns-go deps).
// Packs self + node-agent into a zip for offline Windows deployment.
// On Linux, downloads the full agent binary from the manager during installation.
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

	"golang.org/x/term"

	"github.com/kk/ddns-manager/internal/model"
	"gopkg.in/yaml.v3"
)

var version = "dev"

// base paths — set per-platform defaults, overridden by user input
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
// ⚠️ 安装接口契约: 本文档定义的所有行为受 docs/安装接口规范.md 约束
//    安装器 v1.0.0 冻结 — 修改接口逻辑需升级安装器主版本号
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

// readLine reads a line from stdin with proper line editing (backspace, Ctrl+C).
// Uses terminal raw mode to prevent kernel echo interference.
func readLine(reader *bufio.Reader) (string, error) {
	// Put terminal in raw mode so we control echo
	fd := int(os.Stdin.Fd())
	oldState, err := term.MakeRaw(fd)
	if err == nil {
		defer term.Restore(fd, oldState)
	}

	var buf []byte
	for {
		b, err := reader.ReadByte()
		if err != nil {
			return "", err
		}
		// Enter (CR or LF)
		if b == '\r' || b == '\n' {
			fmt.Print("\r\n")
			return strings.TrimSpace(string(buf)), nil
		}
		// Backspace / DEL
		if b == 0x7f || b == 0x08 {
			if len(buf) > 0 {
				buf = buf[:len(buf)-1]
				fmt.Print("\b \b")
			}
			continue
		}
		// Ctrl+C → interrupt
		if b == 0x03 {
			fmt.Print("^C\r\n")
			return "", fmt.Errorf("interrupted")
		}
		// Ctrl+U → clear line
		if b == 0x15 {
			for range buf {
				fmt.Print("\b \b")
			}
			buf = buf[:0]
			continue
		}
		// Printable
		buf = append(buf, b)
		fmt.Print(string(b))
	}
}

func runInstall(managerURL, nodeName, installDir string, insecure bool) {
	reader := bufio.NewReader(os.Stdin)

	// Windows: set console to UTF-8 for proper CJK display
	if runtime.GOOS == "windows" {
		exec.Command("chcp", "65001").Run()
	}

	// Normalize arch name to Go standard naming (build.sh output format)
	goos := runtime.GOOS
	goarch := runtime.GOARCH
	switch goarch {
	case "386":
		goarch = "i386" // historical compat: Go → deb naming
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

	// ================================================================
	// 重装检测: 已有旧配置时让用户选保留升级还是清除重装
	// v1.0.0: 安装器统一入口，不再在 install.sh 中分流
	// ================================================================
	if existingCfg, err := loadConfig(agentConfigPath); err == nil {
		fmt.Println()
		fmt.Println("  +-------------------------------------------+")
		fmt.Println("  |  [!] 检测到已有安装                         |")
		fmt.Printf("  |                                            |\n")
		fmt.Printf("  |  节点名: %-34s|\n", existingCfg.NodeID)
		fmt.Printf("  |  管理端: %-34s|\n", existingCfg.ManagerURL)
		fmt.Println("  |                                            |")
		fmt.Println("  |  保留旧配置直接升级？[Y/n]: _                |")
		fmt.Println("  +-------------------------------------------+")
		fmt.Print("  > ")
		choice, _ := readLine(reader)
		choice = strings.TrimSpace(strings.ToLower(choice))

		if choice == "" || choice == "y" {
			// ── 保留旧配置，直接升级 ──
			fmt.Println()
			fmt.Printf("  [升级] 保留配置，下载最新 Agent ...\n")

			// 使用旧配置中的 manager_url
			if existingCfg.ManagerURL != "" {
				managerURL = existingCfg.ManagerURL
			}
			baseURL := strings.TrimRight(managerURL, "/")

			agentURL := baseURL + "/bin/node-agent-" + goos + "-" + goarch
			if runtime.GOOS == "windows" {
				agentURL += ".exe"
			}

			// 使用旧配置中的安装目录
			dir := filepath.Dir(agentConfigPath)
			agentBin := filepath.Join(dir, "node-agent")
			if runtime.GOOS == "windows" {
				agentBin += ".exe"
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
				log.Fatalf("下载失败: %v", err)
			}
			os.Chmod(agentBin, 0755)
			fmt.Println("[OK]")

			// 更新 symlink (如果存在) 并重启 timer
			if runtime.GOOS != "windows" {
				exec.Command("systemctl", "restart", "node-agent.timer").Run()
			}
			fmt.Println()
			fmt.Println("  [OK] 升级完成，配置未变")
			return
		}

		// ── 清除旧配置，走全新安装 ──
		fmt.Println()
		fmt.Println("  [清除] 正在清理旧配置...")
		// v1.0.0: 只删除 agent 配置文件，不删整个目录 (可能和 Manager 共享)
		os.Remove(agentConfigPath)
		os.Remove(filepath.Join(filepath.Dir(agentConfigPath), "node-agent"))
		os.Remove(filepath.Join(filepath.Dir(agentConfigPath), "ddns_cache.yaml"))
		// 保留 certs/ 目录内容，用户可能在其他地方引用
	}

	// ================================================================
	// Step 0/5: 环境检查 — 旧版清理 + ddns-go 冲突检测
	// ================================================================
	stepWait(0, 5, "环境检查")

	// 0a. 检测并清理旧版 ddns-manager (自动，不询问)
	oldDDNSManagerFound := cleanOldDDNSManager()
	if oldDDNSManagerFound {
		fmt.Println("  [OK] 旧版 ddns-manager 已清理，配置已保留")
	}

	// 0b. 检测并处理 ddns-go 冲突
	ddnsGoConflict := detectDDNSGoFull()
	if len(ddnsGoConflict) > 0 {
		fmt.Println()
		fmt.Println("  +-------------------------------------------+")
		fmt.Println("  |  [!] 检测到已安装 ddns-go                    |")
		fmt.Println("  |                                            |")
		fmt.Println("  |  ddns-go 与本软件使用相同的 DNS 更新机制      |")
		fmt.Println("  |  同时运行可能导致:                            |")
		fmt.Println("  |    · DNS 记录被反复覆写                      |")
		fmt.Println("  |    · DNS API 调用频率超限                    |")
		fmt.Println("  |    · 域名解析异常                            |")
		fmt.Println("  |                                            |")
		fmt.Println("  |  检测到以下残留:                              |")
		for _, item := range ddnsGoConflict {
			fmt.Printf("  |    · %s\n", item)
		}
		fmt.Println("  |                                            |")
		fmt.Println("  |  是否清除 ddns-go？[y/N]: _                  |")
		fmt.Println("  +-------------------------------------------+")
		fmt.Print("  > ")
		confirm, _ := readLine(reader)
		if strings.TrimSpace(strings.ToLower(confirm)) != "y" {
			fmt.Println("  [FAIL] 用户取消安装 — ddns-go 冲突未解决")
			os.Exit(1)
		}
		cleanDDNSGoFull()
		fmt.Println("  [OK] ddns-go 已完全清除")
	} else {
		fmt.Println("  [OK] 未检测到 ddns-go 冲突")
	}

	// ================================================================
	// Step 1/5: 管理端地址 + 连通性测试
	// ================================================================
	stepWait(1, 5, "管理端地址")
	if managerURL == "" {
		for {
			fmt.Print("  管理端地址 (如 http://192.168.1.100:9877): ")
			managerURL, _ = readLine(reader)
			managerURL = strings.TrimSpace(managerURL)
			if managerURL == "" {
				fmt.Println("  [!] 地址不能为空")
				continue
			}
			fmt.Printf("  测试连接 %s/api/ping ... ", strings.TrimRight(managerURL, "/"))
			resp, err := client.Get(strings.TrimRight(managerURL, "/") + "/api/ping")
			if err != nil {
				fmt.Printf("失败: %v\n", err)
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

	// ================================================================
	// Step 2/5: 安装目录
	// ================================================================
	stepWait(2, 5, "安装目录")
	if installDir == "" {
		fmt.Printf("  安装目录 [默认 %s]: ", agentBaseDir)
		input, _ := readLine(reader)
		input = strings.TrimSpace(input)
		if input != "" {
			installDir = input
		}
	}
	for installDir != "" {
		if !filepath.IsAbs(installDir) {
			fmt.Printf("  [!] 必须是绝对路径 (如 %s)\n", agentBaseDir)
			fmt.Printf("  安装目录 [默认 %s]: ", agentBaseDir)
			input, _ := readLine(reader)
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

	// ================================================================
	// Step 3/5: 节点名称 + 服务端重名指纹检查
	// ================================================================
	stepWait(3, 5, "节点名称")

	// 生成机器指纹 (Go原生, 无外部依赖)
	var fingerprint string
	for {
		var fpErr error
		fingerprint, fpErr = generateFingerprint()
		if fpErr == nil {
			break
		}
		fmt.Println()
		fmt.Printf("  [错误] 无法获取机器标识: %v\n", fpErr)
		fmt.Println("  可能原因:")
		fmt.Println("    1. 权限不足 — 请以管理员身份运行安装向导")
		fmt.Println("    2. 杀毒软件拦截 — 尝试临时关闭实时防护")
		fmt.Println("    3. 系统文件损坏 — 检查注册表或 /etc/machine-id")
		fmt.Println()
		fmt.Print("  按 R 重试, 其他键退出安装: ")
		choice, err := readLine(reader)
		if err != nil {
			fmt.Println("\n  [FAIL] 用户退出安装")
			os.Exit(1)
		}
		choice = strings.TrimSpace(strings.ToLower(choice))
		if choice != "r" {
			fmt.Println("  [FAIL] 用户退出安装")
			os.Exit(1)
		}
	}

	if nodeName == "" {
		fmt.Print("  节点名称 (如 win-pc): ")
		var err error
		nodeName, err = readLine(reader)  // v1.5.29: 修复变量遮蔽 — 用 = 而非 :=
		if err != nil {
			fmt.Println("\n  [FAIL] 取消安装")
			os.Exit(1)
		}
		nodeName = strings.TrimSpace(nodeName)
		if nodeName == "" {
			log.Fatal("节点名称不能为空")
		}
	}

	// 检查本地是否已有旧配置 (同目录残留)
	if existingCfg, err := loadConfig(agentConfigPath); err == nil && existingCfg.Fingerprint == fingerprint {
		fmt.Printf("  [!] 检测到本机已有注册: %s\n", existingCfg.NodeID)
		fmt.Printf("  指纹匹配 — 这是旧机重装\n")
		// 用户可能想保留原节点名或换新名
		if existingCfg.NodeID != nodeName {
			fmt.Printf("  原节点名: %s, 新节点名: %s\n", existingCfg.NodeID, nodeName)
			fmt.Print("  是否替换原注册？[Y/n]: ")
			confirm, _ := readLine(reader)
			confirm = strings.TrimSpace(strings.ToLower(confirm))
			if confirm != "" && confirm != "y" {
				// 用户选择保留原名称
				nodeName = existingCfg.NodeID
				fmt.Printf("  [OK] 保留原节点名: %s\n", nodeName)
			} else {
				fmt.Printf("  [OK] %s -> %s (将重新注册)\n", existingCfg.NodeID, nodeName)
			}
		} else {
			fmt.Printf("  [OK] 节点名一致: %s (旧机重装，将继承配置)\n", nodeName)
		}
	}

	// 服务端重名 + 指纹检查 (调用新 API)
	for {
		ok, remoteFp, err := checkNodeFingerprint(client, baseURL, nodeName)
		if err != nil {
			// API 调用失败 (如 404 管理端不支持新 API) — 走旧逻辑: 直接注册看结果
			fmt.Printf("  [!] 管理端暂不支持指纹查询，跳过预检\n")
			break
		}
		if !ok {
			// 节点名可用
			break
		}
		// 节点名已存在 → 比对指纹
		if remoteFp == fingerprint {
			fmt.Printf("  [!] 节点 '%s' 已存在，指纹匹配 — 旧机重装\n", nodeName)
			fmt.Print("  是否继承原配置并覆盖安装？[Y/n]: ")
			confirm, _ := readLine(reader)
			confirm = strings.TrimSpace(strings.ToLower(confirm))
			if confirm == "" || confirm == "y" {
				fmt.Printf("  [OK] 将继承原节点配置\n")
				break
			}
			fmt.Print("  请输入新节点名: ")
			n, _ := readLine(reader)
			n = strings.TrimSpace(n)
			if n == "" {
				fmt.Println("  [FAIL] 取消安装")
				os.Exit(1)
			}
			nodeName = n
			continue
		}
		// 指纹不匹配 → 新机抢名，拒绝
		fmt.Printf("  [!] 节点名 '%s' 已被其他机器占用 (指纹不匹配)\n", nodeName)
		fmt.Print("  请输入新节点名 (或回车取消): ")
		n, _ := readLine(reader)
		n = strings.TrimSpace(n)
		if n == "" {
			fmt.Println("  [FAIL] 取消安装")
			os.Exit(1)
		}
		nodeName = n
	}
	fmt.Printf("  [OK] 节点名: %s\n", nodeName)

	// ================================================================
	// Step 4/5: 安装 Agent 二进制 (本地优先 → 网络下载兜底)
	// v1.0.0: 安装器版本独立于 Agent 版本，始终下载符号链接指向的最新版
	// ================================================================
	stepWait(4, 5, "安装 Agent")
	// 使用符号链接名下载（服务器上指向最新版 agent），本地直接存为 node-agent
	downloadName := "node-agent-" + goos + "-" + goarch  // 服务器符号链接名
	agentBin := filepath.Join(agentBaseDir, "node-agent") // 直接存为 node-agent
	if runtime.GOOS == "windows" {
		downloadName += ".exe"
		agentBin += ".exe"
	}

	installed := false

	// 策略1: 同目录本地文件 (zip 包场景，零网络依赖)
	if agentFile := findLocalAgent(exeDir()); agentFile != "" {
		fmt.Printf("  从本地复制 %s ... ", filepath.Base(agentFile))
		if err := copyFile(agentFile, agentBin); err != nil {
			fmt.Printf("失败: %v\n", err)
		} else {
			fmt.Println("[OK]")
			installed = true
		}
	}

	// 策略2: 从管理端下载 (网络兜底)
	if !installed {
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
			fallbackNames := []string{"node-agent-latest"}
			if runtime.GOOS == "windows" {
				fallbackNames = append(fallbackNames,
					"node-agent-latest-windows-amd64.exe",
					"node-agent-windows-amd64.exe")
			} else {
				fallbackNames = append(fallbackNames,
					"node-agent-latest-linux-amd64",
					"node-agent-linux-amd64")
			}
			for _, name := range fallbackNames {
				u := baseURL + "/bin/" + name
				fmt.Printf("  尝试 %s ... ", u)
				resp, err := client.Get(u)
				if err == nil && resp.StatusCode == 200 {
					f, _ := os.Create(agentBin)
					io.Copy(f, resp.Body)
					f.Close()
					resp.Body.Close()
					fmt.Println("[OK]")
					installed = true
					break
				}
				if resp != nil {
					resp.Body.Close()
				}
				fmt.Println("失败")
			}
		} else {
			installed = true
		}
	}

	if !installed {
		// 最终检查
		if _, err := os.Stat(agentBin); err != nil {
			log.Fatalf("下载失败: 管理端 /bin/ 目录缺少 %s 系统的 agent 二进制", goos)
		}
	}
	os.Chmod(agentBin, 0755)
	// v1.0.0: 安装器直接下载 node-agent 符号链接指向的最新版
	// 保存为 node-agent，不再需要版本化文件名+符号链接的二次跳转
	fmt.Printf("  [OK] Agent 已安装\n")

	// ================================================================
	// Step 5/5: 注册节点 & 安装服务
	// ================================================================
	stepWait(5, 5, "注册节点 & 安装服务")
	password := generatePassword()
	cfg := &model.AgentConfig{
		ManagerURL: baseURL, NodeID: nodeName, Fingerprint: fingerprint,
		Password: password, CertPath: defaultCertPath, VerifySSL: !insecure,
	}

	// 注册到管理端
	regBody, _ := json.Marshal(map[string]string{
		"node_id": cfg.NodeID, "fingerprint": cfg.Fingerprint, "password": cfg.Password,
	})
	resp, err := client.Post(baseURL+"/api/register", "application/json", bytes.NewReader(regBody))
	if err != nil {
		log.Fatalf("注册请求失败: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode == 409 {
		// 节点已存在 (可能是旧机重装未走指纹预检)
		fmt.Printf("  [!] 节点 '%s' 已注册，检查指纹...\n", cfg.NodeID)
		ok, remoteFp, fpErr := checkNodeFingerprint(client, baseURL, cfg.NodeID)
		if fpErr == nil && ok && remoteFp != "" && remoteFp == cfg.Fingerprint {
			fmt.Printf("  [OK] 指纹匹配，旧机重装 — 跳过注册\n")
			// 读取旧 agent.yaml 保留原 password
			if oldCfg, oldErr := loadConfig(agentConfigPath); oldErr == nil && oldCfg.Password != "" {
				cfg.Password = oldCfg.Password
			}
		} else {
			log.Fatalf("注册失败 HTTP 409: 节点名已被占用且指纹不匹配，请更换节点名重试")
		}
	} else if resp.StatusCode != 200 {
		log.Fatalf("注册失败 HTTP %d: %s", resp.StatusCode, string(body))
	} else {
		fmt.Println("  [OK] 注册成功")
	}

	if err := saveConfig(cfg, agentConfigPath); err != nil {
		log.Fatalf("保存配置: %v", err)
	}

	// 安装系统服务
	if runtime.GOOS == "windows" {
		binPath := fmt.Sprintf(`"%s" -daemon`, agentBin)
		if serviceExists("node-agent") {
			exec.Command("sc", "stop", "node-agent").Run()
			time.Sleep(time.Second)
			exec.Command("sc", "delete", "node-agent").Run()
			time.Sleep(time.Second)
		}
		// 创建服务
		out, err := exec.Command("sc", "create", "node-agent",
			"binPath=", binPath, "start=", "auto",
			"DisplayName=", "ddns-manager Node Agent").CombinedOutput()
		if err != nil {
			log.Fatalf("创建 Windows 服务失败: %v: %s", err, string(out))
		}
		exec.Command("sc", "failure", "node-agent", "reset=", "86400",
			"actions=", "restart/5000").Run()
		// 启动服务
		out, err = exec.Command("sc", "start", "node-agent").CombinedOutput()
		if err != nil {
			fmt.Printf("  [!] 服务启动失败: %v: %s\n  请检查安装目录权限\n", err, string(out))
		} else {
			fmt.Println("  [OK] Windows 服务已安装并启动")
		}
	} else {
		svc := fmt.Sprintf(`[Unit]
Description=ddns-manager Node Agent
After=network-online.target

[Service]
Type=oneshot
ExecStart=%s -heartbeat
`, agentBin)
		timer := `[Unit]
Description=ddns-manager Node Agent Timer

[Timer]
OnBootSec=30s
# OnCalendar触发独立于service激活历史，timer重启不会卡死
OnCalendar=*:0/3
RandomizedDelaySec=15s

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

// ========== 环境检查: 旧版 ddns-manager 清理 (自动) ==========

// cleanOldDDNSManager stops and removes old ddns-manager agent service + binaries.
// Keeps agent.yaml config so the new install can inherit or the user can review.
// Returns true if an old installation was found and cleaned.
func cleanOldDDNSManager() bool {
	cleaned := false

	// Stop & remove Windows service
	if runtime.GOOS == "windows" {
		if out, _ := exec.Command("sc", "query", "node-agent").Output(); strings.Contains(string(out), "SERVICE_NAME") {
			fmt.Println("  [!] 检测到旧版 ddns-manager Windows 服务")
			exec.Command("sc", "stop", "node-agent").Run()
			time.Sleep(500 * time.Millisecond)
			exec.Command("sc", "delete", "node-agent").Run()
			cleaned = true
		}
		// Remove old binaries but keep agent.yaml
		entries, _ := os.ReadDir(agentBaseDir)
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			name := strings.ToLower(e.Name())
			// Keep agent.yaml for config inheritance
			if name == "agent.yaml" || name == "ddns_cache.yaml" {
				continue
			}
			if strings.HasPrefix(name, "node-agent") && strings.HasSuffix(name, ".exe") {
				os.Remove(filepath.Join(agentBaseDir, e.Name()))
				cleaned = true
			}
		}
	} else {
		// Linux: stop systemd timer + service
		if _, err := os.Stat("/etc/systemd/system/node-agent.service"); err == nil {
			fmt.Println("  [!] 检测到旧版 ddns-manager systemd 服务")
			exec.Command("systemctl", "stop", "node-agent.timer").Run()
			exec.Command("systemctl", "disable", "node-agent.timer").Run()
			time.Sleep(500 * time.Millisecond)
			exec.Command("systemctl", "daemon-reload").Run()
			cleaned = true
		}
		// Remove old versioned binaries
		entries, _ := os.ReadDir(agentBaseDir)
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			if strings.HasPrefix(e.Name(), "node-agent-v") {
				os.Remove(filepath.Join(agentBaseDir, e.Name()))
				cleaned = true
			}
		}
		// Remove symlink
		os.Remove(filepath.Join(agentBaseDir, "node-agent"))
	}
	return cleaned
}

// ========== ddns-go 完整检测 ==========

// detectDDNSGoFull returns a list of detected ddns-go artifacts (service, binaries, configs, directories).
// Returns nil if nothing is found.
func detectDDNSGoFull() []string {
	var items []string

	if runtime.GOOS == "windows" {
		// Windows: sc query + directories
		if out, _ := exec.Command("sc", "query", "ddns-go").Output(); strings.Contains(string(out), "SERVICE_NAME") {
			state := "已安装"
			if strings.Contains(string(out), "RUNNING") {
				state = "运行中"
			}
			items = append(items, fmt.Sprintf("Windows 服务: ddns-go (%s)", state))
		}
		for _, dir := range []string{`C:\ddns-go`, `C:\ddns-manager\ddns-go`, `C:\ddns\ddns-go`} {
			if info, err := os.Stat(dir); err == nil && info.IsDir() {
				items = append(items, fmt.Sprintf("程序目录: %s", dir))
			}
		}
		// Check common config file locations
		for _, cfg := range []string{`C:\ddns-go\.ddns_go_config.yaml`, `C:\Users\Administrator\.ddns_go_config.yaml`} {
			if _, err := os.Stat(cfg); err == nil {
				items = append(items, fmt.Sprintf("配置文件: %s", cfg))
			}
		}
	} else {
		// Linux: systemd + bin + configs
		// v1.0.0: 用 exit code 判断而非 stdout — 服务已删除后 is-active 仍可能输出 "inactive"
		cmd := exec.Command("systemctl", "is-active", "ddns-go")
		out, err := cmd.Output()
		s := strings.TrimSpace(string(out))
		// exit 0=active, exit 3=inactive(known unit, not running)
		// exit 4=unknown(unit not found) — ignore, service already cleaned
		if err == nil || (cmd.ProcessState != nil && cmd.ProcessState.ExitCode() == 3) {
			items = append(items, fmt.Sprintf("systemd 服务: ddns-go (%s)", s))
		}
		for _, cfg := range []string{
			"/opt/ddns-go/.ddns_go_config.yaml",
			"/root/.ddns_go_config.yaml",
			"/etc/ddns-go/.ddns_go_config.yaml",
		} {
			if _, err := os.Stat(cfg); err == nil {
				items = append(items, fmt.Sprintf("配置文件: %s", cfg))
			}
		}
		if _, err := os.Stat("/usr/local/bin/ddns-go"); err == nil {
			items = append(items, "二进制程序: /usr/local/bin/ddns-go")
		}
		if info, err := os.Stat("/opt/ddns-go"); err == nil && info.IsDir() {
			items = append(items, "程序目录: /opt/ddns-go")
		}
		if _, err := os.Stat("/etc/systemd/system/ddns-go.service"); err == nil {
			items = append(items, "systemd unit: ddns-go.service")
		}
	}
	return items
}

// cleanDDNSGoFull removes all detected ddns-go artifacts.
func cleanDDNSGoFull() {
	if runtime.GOOS == "windows" {
		exec.Command("sc", "stop", "ddns-go").Run()
		time.Sleep(500 * time.Millisecond)
		exec.Command("sc", "delete", "ddns-go").Run()
		os.RemoveAll(`C:\ddns-go`)
		os.RemoveAll(`C:\ddns-manager\ddns-go`)
		os.RemoveAll(`C:\ddns\ddns-go`)
		os.Remove(`C:\Users\Administrator\.ddns_go_config.yaml`)
	} else {
		exec.Command("systemctl", "stop", "ddns-go").Run()
		exec.Command("systemctl", "disable", "ddns-go").Run()
		time.Sleep(300 * time.Millisecond)
		os.Remove("/etc/systemd/system/ddns-go.service")
		exec.Command("systemctl", "daemon-reload").Run()
		os.Remove("/usr/local/bin/ddns-go")
		os.RemoveAll("/opt/ddns-go")
		os.Remove("/root/.ddns_go_config.yaml")
		os.Remove("/etc/ddns-go/.ddns_go_config.yaml")
	}
}

// ========== 服务端指纹查询 ==========

// checkNodeFingerprint queries the manager for a node's fingerprint.
// Returns (exists, fingerprint, error).
// Uses the public /api/nodes/{name}/fingerprint endpoint.
func checkNodeFingerprint(client *http.Client, baseURL, nodeName string) (exists bool, fingerprint string, err error) {
	url := fmt.Sprintf("%s/api/nodes/%s/fingerprint", baseURL, nodeName)
	resp, err := client.Get(url)
	if err != nil {
		return false, "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode == 404 {
		return false, "", nil
	}
	if resp.StatusCode != 200 {
		return false, "", fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	var result struct {
		Exists      bool   `json:"exists"`
		Fingerprint string `json:"fingerprint"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return false, "", err
	}
	return result.Exists, result.Fingerprint, nil
}

// ========== uninstall ==========

func runUninstall() {
	fmt.Println("正在卸载 ddns-manager...")
	if runtime.GOOS == "windows" {
		exec.Command("sc", "stop", "node-agent").Run()
		time.Sleep(time.Second)
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

// ========== shared utilities ==========

// exeDir returns the directory containing the currently running executable.
func exeDir() string {
	exe, err := os.Executable()
	if err != nil {
		return "."
	}
	return filepath.Dir(exe)
}

// findLocalAgent 扫描同目录，查找 node-agent*.exe (版本化命名)。
// 返回第一个匹配的完整路径，未找到返回空。
func findLocalAgent(dir string) string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return ""
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		n := strings.ToLower(e.Name())
		if strings.HasPrefix(n, "node-agent") && strings.HasSuffix(n, ".exe") {
			return filepath.Join(dir, e.Name())
		}
		// Linux: 无 .exe 后缀
		if runtime.GOOS != "windows" && strings.HasPrefix(n, "node-agent") && !strings.Contains(n, ".") {
			return filepath.Join(dir, e.Name())
		}
	}
	return ""
}

// copyFile copies a file from src to dst. Creates dst with the same permissions.
func copyFile(src, dst string) error {
	s, err := os.Open(src)
	if err != nil {
		return err
	}
	defer s.Close()

	d, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer d.Close()

	if _, err := io.Copy(d, s); err != nil {
		return err
	}
	return d.Sync()
}

func generateFingerprint() (string, error) {
	// ⚠️ 禁止使用外部工具 (PowerShell/WMI) 获取机器标识 ——
	// Windows PowerShell 版本/模块差异导致输出尾随字符不稳定 (\r\n vs \n vs 无),
	// 同一台机器产生不同指纹, v1.5.13 已造成生产故障。
	// 改为 Go 原生注册表 MachineGuid (Windows) / /etc/machine-id (Linux)。
	// 详见 machineid_windows.go / machineid_unix.go。
	hostname, _ := os.Hostname()
	machineID, err := getMachineID()
	if err != nil {
		return "", err
	}
	h := sha256.Sum256([]byte(hostname + machineID))
	return "sha256:" + hex.EncodeToString(h[:]), nil
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
