package server

import (
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"sync"
)

// Handler 模块处理函数签名
// 对应 kugoumusic 的 module.exports = (params, useAxios) => {...}
type Handler func(params map[string]interface{}, r *http.Request) (map[string]interface{}, error)

// Server HTTP 服务器
type Server struct {
	mu       sync.RWMutex
	modules  map[string]Handler
	mux      *http.ServeMux
}

// New 创建服务器并自动加载 module/ 目录下的所有模块
func New() *Server {
	s := &Server{
		modules: make(map[string]Handler),
		mux:     http.NewServeMux(),
	}
	s.loadModules()
	s.setupRoutes()
	return s
}

// ServeHTTP 实现 http.Handler 接口
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// CORS
	if r.Method == "OPTIONS" {
		w.WriteHeader(204)
		return
	}
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET,POST,PUT,DELETE,OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Authorization,Content-Type")
	w.Header().Set("Content-Type", "application/json; charset=utf-8")

	s.mux.ServeHTTP(w, r)
}

// setupRoutes 设置路由
func (s *Server) setupRoutes() {
	// 首页
	s.mux.HandleFunc("/", s.handleIndex)

	// 动态注册模块路由
	// 对应 kugoumusic 的 server.js: app.use(moduleDef.route, ...)
	s.mu.RLock()
	for name, handler := range s.modules {
		route := "/" + strings.ReplaceAll(name, "_", "/")
		h := handler
		s.mux.HandleFunc(route, s.wrapHandler(h))
	}
	s.mu.RUnlock()
}

// wrapHandler 包装模块处理函数为 HTTP handler
// 对应 kugoumusic 的 server.js 路由处理逻辑
func (s *Server) wrapHandler(handler Handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// 解析参数（合并 query + body）
		params := make(map[string]interface{})

		// Query 参数
		for k, v := range r.URL.Query() {
			if len(v) == 1 {
				params[k] = v[0]
			} else {
				params[k] = v
			}
		}

		// Body 参数（JSON）
		if r.Body != nil {
			var body map[string]interface{}
			if err := json.NewDecoder(r.Body).Decode(&body); err == nil {
				for k, v := range body {
					params[k] = v
				}
			}
		}

		// Cookie
		cookies := make(map[string]string)
		for _, c := range r.Cookies() {
			cookies[c.Name] = c.Value
		}
		params["cookie"] = cookies

		// 调用模块处理函数
		result, err := handler(params, r)
		if err != nil {
			log.Printf("[ERR] %s %v", r.URL.Path, err)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"code": 500,
				"msg":  err.Error(),
			})
			return
		}

		log.Printf("[OK] %s", r.URL.Path)
		json.NewEncoder(w).Encode(result)
	}
}

// handleIndex 首页
func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	s.mu.RLock()
	endpoints := make([]string, 0, len(s.modules))
	for name := range s.modules {
		route := "/" + strings.ReplaceAll(name, "_", "/")
		endpoints = append(endpoints, "GET/POST "+route)
	}
	s.mu.RUnlock()

	json.NewEncoder(w).Encode(map[string]interface{}{
		"name":      "kuwoapi-go",
		"version":   "2.0.0",
		"endpoints": endpoints,
	})
}
