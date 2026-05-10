// Package notify provides email notifications via SMTP.
package notify

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/smtp"
	"strings"
	"time"
)

// Config holds SMTP connection settings.
type Config struct {
	Host           string `json:"host"`
	Port           int    `json:"port"`
	Username       string `json:"username"`
	Password       string `json:"password"`
	To             string `json:"to"`
	ManagerURL     string `json:"manager_url"` // 管理端域名 (邮件中可点击链接)
	CertExpiryDays int    `json:"cert_expiry_days"`
	// event notification toggles
	NotifyHeartbeatFail bool `json:"notify_heartbeat_fail"`
	NotifySecurity      bool `json:"notify_security"`
	NotifyConfigChange  bool `json:"notify_config_change"`
	NotifySystemError   bool `json:"notify_system_error"`
	NotifyCertExpiry    bool `json:"notify_cert_expiry"`
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
	subject := "[ddns-manager] SMTP 配置验证"
	body := fmt.Sprintf("您好，\n\nSMTP 邮件配置验证成功！\n\n发送时间: %s\n服务器: %s:%d\n发件人: %s\n管理端: %s\n\n此邮件由 ddns-manager 系统自动发送，请勿回复。",
		time.Now().Format("2006-01-02 15:04:05"), c.Host, c.Port, c.Username, c.managerURL())
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
	lines = append(lines, "", fmt.Sprintf("发送时间: %s", time.Now().Format("2006-01-02 15:04:05")))
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
		title, detail, time.Now().Format("2006-01-02 15:04:05"), c.managerURL())
	subject := fmt.Sprintf("[ddns-manager] %s", title)
	return c.send(subject, body)
}

// CertAlert describes a certificate that needs attention.
type CertAlert struct {
	BundleName string `json:"bundle_name"`
	DaysLeft   int    `json:"days_left"`
	ExpiresAt  string `json:"expires_at"`
}

// managerURL returns the configured management URL for email links.
// Falls back to server host:port notation when not configured.
func (c *Config) managerURL() string {
	if c.ManagerURL != "" {
		return c.ManagerURL
	}
	return fmt.Sprintf("%s:%d (请配置管理端域名)", c.Host, c.Port)
}

func (c *Config) send(subject, body string) error {
	addr := fmt.Sprintf("%s:%d", c.Host, c.Port)
	msg := fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\n%s",
		c.Username, c.To, subject, body)

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
