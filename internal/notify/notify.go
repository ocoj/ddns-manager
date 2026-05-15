// Package notify provides email notifications via SMTP.
package notify

import (
	"crypto/tls"
	_ "embed"
	"encoding/base64"
	"fmt"
	"net"
	"net/smtp"
	"strings"
	"time"
)

//go:embed email-logo.png
var emailLogoPNG []byte
var emailLogoBase64 = "data:image/png;base64," + base64.StdEncoding.EncodeToString(emailLogoPNG)

// Config holds SMTP connection settings.
type Config struct {
	Host           string `json:"host"`
	Port           int    `json:"port"`
	Username       string `json:"username"`
	Password       string `json:"password"`
	To             string `json:"to"`
	ManagerURL     string `json:"manager_url"` // 管理端域名 (邮件中可点击链接)
	CertExpiryDays int    `json:"cert_expiry_days"`
	Timezone       string `json:"timezone"` // 时区，默认 Asia/Shanghai
	// event notification toggles
	NotifyHeartbeatFail bool `json:"notify_heartbeat_fail"`
	NotifySecurity      bool `json:"notify_security"`
	NotifyConfigChange  bool `json:"notify_config_change"`
	NotifySystemError   bool `json:"notify_system_error"`
	NotifyCertExpiry    bool `json:"notify_cert_expiry"`
}

func (c *Config) now() time.Time {
	loc, err := time.LoadLocation(c.Timezone)
	if err != nil || c.Timezone == "" {
		loc = time.Local
	}
	return time.Now().In(loc)
}

// Masked returns a copy with the password replaced by asterisks.
func (c *Config) Masked() Config {
	m := *c
	if len(m.Password) > 4 {
		m.Password = m.Password[:2] + strings.Repeat("*", len(m.Password)-4) + m.Password[len(m.Password)-2:]
	} else if m.Password != "" {
		m.Password = "****"
	}
	return m
}

// IsConfigured returns true if the minimum required fields are set.
func (c *Config) IsConfigured() bool {
	return c.Host != "" && c.Port > 0 && c.Username != "" && c.Password != "" && c.To != ""
}

// SendTest sends a test email to verify SMTP configuration.
func (c *Config) SendTest() error {
	if !c.IsConfigured() {
		return fmt.Errorf("SMTP 未完整配置 (服务器/端口/发件人/授权码/收件人 缺一不可)")
	}
	subject := "[DDNS-Manager] SMTP 配置验证"
	body := fmt.Sprintf("您好，\n\nSMTP 邮件配置验证成功！\n\n发送时间: %s\n服务器: %s:%d\n发件人: %s\n管理端: %s\n\n此邮件由 DDNS-Manager 系统自动发送，请勿回复。",
		c.now().Format("2006-01-02 15:04:05"), c.Host, c.Port, c.Username, c.managerURL())
	return c.send(subject, body)
}

// SendCertAlert sends a certificate expiry warning. Respects NotifyCertExpiry toggle.
func (c *Config) SendCertAlert(alerts []CertAlert) error {
	if !c.NotifyCertExpiry {
		return nil
	}
	var lines []string
	lines = append(lines, "您好，", "")
	lines = append(lines, "以下 SSL 证书即将过期，请登录管理面板续签：", "")
	for _, a := range alerts {
		lines = append(lines, fmt.Sprintf("  • %s — %d 天后到期 (%s)", a.BundleName, a.DaysLeft, a.ExpiresAt))
	}
	lines = append(lines, "", fmt.Sprintf("管理端地址: %s", c.managerURL()))
	lines = append(lines, "", fmt.Sprintf("发送时间: %s", c.now().Format("2006-01-02 15:04:05")))
	lines = append(lines, "", "此邮件由 ddns-manager 系统自动发送，请勿回复。")
	body := strings.Join(lines, "\n")
	subject := fmt.Sprintf("[ddns-manager] %d 个证书即将到期", len(alerts))
	return c.send(subject, body)
}

// SendEventAlert sends a notification for a high-severity event.
// eventType should match one of the notification toggle fields.
// Returns nil if the event type is not enabled.
func (c *Config) SendEventAlert(eventType, title, detail string) error {
	if !c.IsConfigured() {
		return nil
	}
	enabled := false
	switch eventType {
	case "heartbeat_fail":
		enabled = c.NotifyHeartbeatFail
	case "security":
		enabled = c.NotifySecurity
	case "config_change":
		enabled = c.NotifyConfigChange
	case "system_error":
		enabled = c.NotifySystemError
	case "cert_expiry":
		enabled = c.NotifyCertExpiry
	}
	if !enabled {
		return nil
	}
	body := fmt.Sprintf("您好，\n\nddns-manager 系统通知\n\n事件类型: %s\n详情: %s\n时间: %s\n管理端: %s\n\n此邮件由 ddns-manager 系统自动发送，请勿回复。",
		title, detail, c.now().Format("2006-01-02 15:04:05"), c.managerURL())
	subject := fmt.Sprintf("[ddns-manager] %s", title)
	return c.send(subject, body)
}

// CertAlert describes a certificate that needs attention.
type CertAlert struct {
	BundleName string `json:"bundle_name"`
	DaysLeft   int    `json:"days_left"`
	ExpiresAt  string `json:"expires_at"`
}

// wrapHTML 将纯文本邮件包装为带 Logo + 样式的 HTML 邮件。
// v1.5.33: 自动将纯文本 URL 转为可点击链接。
func wrapHTML(subject, body string) string {
	// 纯文本 → HTML (换行转 <br>)
	htmlBody := strings.ReplaceAll(body, "\n", "<br>\n")
	// 自动识别 https?:// 开头的 URL 并转为可点击链接
	htmlBody = autoLinkURLs(htmlBody)
	return fmt.Sprintf(`<!DOCTYPE html>
<html><head><meta charset="UTF-8"></head>
<body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; color: #333;">
<div style="padding: 12px 0; border-bottom: 3px solid #2563eb; display: flex; align-items: flex-end;">
  <img src="%s" alt="DDNS-Manager" style="width: 36px; height: auto; margin-right: 8px;">
  <span style="font-size: 18px; font-weight: 700; color: #2563eb;">DDNS-Manager</span>
  <span style="font-size: 11px; color: #888; margin-left: auto; padding-bottom: 2px;">DDNS 多节点管理平台</span>
</div>
<div style="padding: 24px 16px; line-height: 1.8; font-size: 15px;">
%s
</div>
<div style="margin-top: 24px; padding: 16px; background: #f8f9fa; border-radius: 8px; font-size: 12px; color: #888; text-align: center;">
  此邮件由 DDNS-Manager 系统自动发送，请勿回复。<br>
  Powered by ddns-manager | Lanxun CO.,Ltd.
</div>
</body></html>`, emailLogoBase64, htmlBody)
}

// autoLinkURLs 将文本中的 https?:// 开头的 URL 替换为可点击的 <a> 链接。
func autoLinkURLs(text string) string {
	// 匹配 https?:// 后跟非空白、非 < 字符
	var result strings.Builder
	start := 0
	for {
		idx := strings.Index(text[start:], "https://")
		if idx == -1 {
			idx = strings.Index(text[start:], "http://")
		}
		if idx == -1 {
			result.WriteString(text[start:])
			break
		}
		absIdx := start + idx
		result.WriteString(text[start:absIdx])
		// 找到 URL 结束位置 (空格、<br>、行尾)
		end := absIdx
		for end < len(text) && text[end] != ' ' && text[end] != '<' && text[end] != '\n' && text[end] != '\r' {
			end++
		}
		url := text[absIdx:end]
		result.WriteString(fmt.Sprintf("<a href=\"%s\" style=\"color:#2563eb;\">%s</a>", url, url))
		start = end
	}
	return result.String()
}

// managerURL returns the configured management URL for email links.
// Falls back to server host:port notation when not configured.
func (c *Config) managerURL() string {
	if c.ManagerURL != "" {
		return c.ManagerURL
	}
	return fmt.Sprintf("%s:%d (请配置管理端域名)", c.Host, c.Port)
}

// SendRaw sends a plain-text email with custom subject and body.
// Used for DNS key invalidity notifications and other simple alerts.
func (c *Config) SendRaw(subject, body string) error {
	if !c.IsConfigured() {
		return nil
	}
	return c.send(subject, body)
}

func (c *Config) send(subject, body string) error {
	addr := fmt.Sprintf("%s:%d", c.Host, c.Port)
	// v1.5.33: 发件人显示名 "DDNS-Manager", HTML 邮件支持
	displayFrom := fmt.Sprintf("DDNS-Manager <%s>", c.Username)
	htmlBody := wrapHTML(subject, body)
	msg := fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\nMIME-Version: 1.0\r\nContent-Type: text/html; charset=UTF-8\r\n\r\n%s",
		displayFrom, c.To, subject, htmlBody)

	if c.Port == 465 {
		return c.sendTLS(addr, msg)
	}
	return c.sendSTARTTLS(addr, msg)
}

func (c *Config) sendTLS(addr, msg string) error {
	tlsConfig := &tls.Config{ServerName: c.Host}
	conn, err := tls.Dial("tcp", addr, tlsConfig)
	if err != nil {
		return fmt.Errorf("TLS dial: %w", err)
	}
	defer conn.Close()

	client, err := smtp.NewClient(conn, c.Host)
	if err != nil {
		return fmt.Errorf("SMTP client: %w", err)
	}
	defer client.Quit()

	auth := smtp.PlainAuth("", c.Username, c.Password, c.Host)
	if err := client.Auth(auth); err != nil {
		return fmt.Errorf("auth: %w", err)
	}
	if err := client.Mail(c.Username); err != nil {
		return fmt.Errorf("mail: %w", err)
	}
	if err := client.Rcpt(c.To); err != nil {
		return fmt.Errorf("rcpt: %w", err)
	}
	w, err := client.Data()
	if err != nil {
		return fmt.Errorf("data: %w", err)
	}
	_, err = w.Write([]byte(msg))
	if err != nil {
		return fmt.Errorf("write: %w", err)
	}
	return w.Close()
}

func (c *Config) sendSTARTTLS(addr, msg string) error {
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	defer conn.Close()
	client, err := smtp.NewClient(conn, c.Host)
	if err != nil {
		return fmt.Errorf("SMTP client: %w", err)
	}
	defer client.Quit()

	if ok, _ := client.Extension("STARTTLS"); ok {
		tlsConfig := &tls.Config{ServerName: c.Host}
		if err := client.StartTLS(tlsConfig); err != nil {
			return fmt.Errorf("STARTTLS: %w", err)
		}
	}

	auth := smtp.PlainAuth("", c.Username, c.Password, c.Host)
	if err := client.Auth(auth); err != nil {
		return fmt.Errorf("auth: %w", err)
	}
	if err := client.Mail(c.Username); err != nil {
		return fmt.Errorf("mail: %w", err)
	}
	if err := client.Rcpt(c.To); err != nil {
		return fmt.Errorf("rcpt: %w", err)
	}
	w, err := client.Data()
	if err != nil {
		return fmt.Errorf("data: %w", err)
	}
	_, err = w.Write([]byte(msg))
	if err != nil {
		return fmt.Errorf("write: %w", err)
	}
	return w.Close()
}
