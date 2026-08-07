package util

import (
	"crypto/md5"
	"fmt"
	"io"
	"net/http"
	"time"
)

// HTTPClient 全局 HTTP 客户端
var HTTPClient = &http.Client{Timeout: 15 * time.Second}

// Md5 计算 MD5 哈希
// 对应 kugoumusic 的 cryptoMd5
func Md5(data string) string {
	h := md5.New()
	io.WriteString(h, data)
	return fmt.Sprintf("%x", h.Sum(nil))
}

// GetString 从 map 中获取字符串值
func GetString(m map[string]interface{}, key, defaultVal string) string {
	if v, ok := m[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return defaultVal
}

// GetInt 从 map 中获取整数值
func GetInt(m map[string]interface{}, key string, defaultVal int) int {
	if v, ok := m[key]; ok {
		switch n := v.(type) {
		case int:
			return n
		case float64:
			return int(n)
		case string:
			var i int
			fmt.Sscanf(n, "%d", &i)
			return i
		}
	}
	return defaultVal
}
