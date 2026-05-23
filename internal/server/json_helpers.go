package server

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
)

func tokenFromPassword(pass string) string {
	// v1.6.46 H4: 无 salt 版本保留向后兼容 (旧 admin.json 不含 instance_salt)
	h := sha256.Sum256([]byte("admin:" + pass))
	return fmt.Sprintf("%x", h)
}

// tokenFromPasswordWithSalt derives admin token with instance-specific salt.
// v1.6.46 H4: 防止同密码在不同 Manager 实例上产生相同 token。
func tokenFromPasswordWithSalt(pass, salt string) string {
	h := sha256.Sum256([]byte(salt + "\x00" + "admin:" + pass))
	return fmt.Sprintf("%x", h)
}


// jsonOK v1.6.42 M4: 大响应 (>1KB) 预编码并设置 Content-Length, 浏览器可显进度条
func jsonOK(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Cache-Control", "no-store, max-age=0")
	data, err := json.Marshal(v)
	if err != nil {
		log.Printf("[http] JSON 编码失败: %v", err)
		return
	}
	w.Header().Set("Content-Length", strconv.Itoa(len(data)))
	w.Write(data)
}

func jsonErr(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(code)
	if err := json.NewEncoder(w).Encode(map[string]string{"error": msg}); err != nil {
		log.Printf("[http] JSON 错误编码失败: %v", err)
	}
}
