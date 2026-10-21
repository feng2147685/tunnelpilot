package api

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"tunnelpilot/internal/config"
	"tunnelpilot/internal/fakeip"
	"tunnelpilot/internal/rule"
	"tunnelpilot/internal/tunengine"
)

// TUNController 抽象 utun 的启停，避免 api 包直接依赖实现
type TUNController interface {
	Start() error
	Stop() error
	Running() bool
	InterfaceName() string
}

// Server 提供管理用的 HTTP 接口，供 Web 界面与菜单栏调用
type Server struct {
	mu         sync.RWMutex
	profile    *config.Profile
	rules      *rule.Engine
	handler    *tunengine.Handler
	pool       *fakeip.Pool
	tun        TUNController
	configPath string
	startedAt  time.Time
	logs       []string
}

type Options struct {
	Profile    *config.Profile
	Rules      *rule.Engine
	Handler    *tunengine.Handler
	Pool       *fakeip.Pool
	ConfigPath string
	TUN        TUNController
}

func New(opts Options) *Server {
	return &Server{
		profile:    opts.Profile,
		rules:      opts.Rules,
		handler:    opts.Handler,
		pool:       opts.Pool,
		tun:        opts.TUN,
		configPath: opts.ConfigPath,
		startedAt:  time.Now(),
	}
}

func (s *Server) AppendLog(line string) {
	s.mu.Lock()
	s.logs = append(s.logs, time.Now().Format("15:04:05")+" "+line)
	if len(s.logs) > 500 {
		s.logs = s.logs[len(s.logs)-500:]
	}
	s.mu.Unlock()
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/status", s.handleStatus)
	mux.HandleFunc("/api/tun/start", s.handleTUNStart)
	mux.HandleFunc("/api/tun/stop", s.handleTUNStop)
	mux.HandleFunc("/api/connections", s.handleConnections)
	mux.HandleFunc("/api/profile", s.handleProfile)
	mux.HandleFunc("/api/fakeip", s.handleFakeIP)
	mux.HandleFunc("/api/logs", s.handleLogs)
	mux.HandleFunc("/api/ppx/export", s.handleExportPPX)
	mux.HandleFunc("/api/ppx/import", s.handleImportPPX)

	// 静态资源位于内嵌的 web/ 子目录下
	sub, err := fs.Sub(webFS, "web")
	if err == nil {
		mux.Handle("/", http.FileServer(http.FS(sub)))
	}
	return mux
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	var running bool
	var tunName string
	if s.tun != nil {
		running = s.tun.Running()
		tunName = s.tun.InterfaceName()
	}
	s.mu.RLock()
	listen := s.profile.ListenPort
	s.mu.RUnlock()
	writeJSON(w, map[string]any{
		"running":  running,
		"tun_name": tunName,
		"uptime":   formatUptime(time.Since(s.startedAt)),
		"pid":      os.Getpid(),
		"uid":      os.Getuid(),
		"listen":   listen,
	})
}

func (s *Server) handleTUNStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost && r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "不支持的方法")
		return
	}
	if s.tun == nil {
		writeError(w, http.StatusServiceUnavailable, "当前进程无权限接管流量（请用 root 运行 daemon）")
		return
	}
	if err := s.tun.Start(); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, map[string]any{"ok": true, "running": true, "tun_name": s.tun.InterfaceName()})
}

func (s *Server) handleTUNStop(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost && r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "不支持的方法")
		return
	}
	if s.tun == nil {
		writeError(w, http.StatusServiceUnavailable, "当前进程未接管流量")
		return
	}
	if err := s.tun.Stop(); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, map[string]any{"ok": true, "running": false})
}

// formatUptime 把时长转成「1 天 2 小时」「3 分 5 秒」这类可读文本
func formatUptime(d time.Duration) string {
	d = d.Round(time.Second)
	days := int(d.Hours()) / 24
	hours := int(d.Hours()) % 24
	mins := int(d.Minutes()) % 60
	secs := int(d.Seconds()) % 60

	switch {
	case days > 0:
		return fmt.Sprintf("%d 天 %d 小时", days, hours)
	case hours > 0:
		return fmt.Sprintf("%d 小时 %d 分", hours, mins)
	case mins > 0:
		return fmt.Sprintf("%d 分 %d 秒", mins, secs)
	default:
		return fmt.Sprintf("%d 秒", secs)
	}
}

func (s *Server) handleConnections(w http.ResponseWriter, r *http.Request) {
	if s.handler == nil {
		writeJSON(w, []any{})
		return
	}
	writeJSON(w, s.handler.Snapshot(300))
}

func (s *Server) handleFakeIP(w http.ResponseWriter, r *http.Request) {
	if s.pool == nil {
		writeJSON(w, map[string]string{})
		return
	}
	writeJSON(w, s.pool.Mappings())
}

func (s *Server) handleLogs(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	out := append([]string(nil), s.logs...)
	s.mu.RUnlock()
	writeJSON(w, out)
}

func (s *Server) handleProfile(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.mu.RLock()
		p := s.profile
		s.mu.RUnlock()
		writeJSON(w, p)

	case http.MethodPut, http.MethodPost:
		var p config.Profile
		if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
			writeError(w, http.StatusBadRequest, "配置解析失败: "+err.Error())
			return
		}
		s.mu.Lock()
		s.profile = &p
		s.mu.Unlock()
		s.rules.Update(&p)
		if err := SaveProfile(&p, s.configPath); err != nil {
			writeError(w, http.StatusInternalServerError, "保存配置失败: "+err.Error())
			return
		}
		writeJSON(w, map[string]any{"ok": true})

	default:
		writeError(w, http.StatusMethodNotAllowed, "不支持的方法")
	}
}

func (s *Server) handleExportPPX(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	p := s.profile
	s.mu.RUnlock()

	tmp := filepath.Join(os.TempDir(), "tunnelpilot-export.ppx")
	if err := p.ExportPPX(tmp); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	data, err := os.ReadFile(tmp)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/xml; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="tunnelpilot.ppx"`)
	_, _ = w.Write(data)
}

func (s *Server) handleImportPPX(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseMultipartForm(8 << 20); err != nil {
		writeError(w, http.StatusBadRequest, "上传解析失败: "+err.Error())
		return
	}
	file, _, err := r.FormFile("file")
	if err != nil {
		writeError(w, http.StatusBadRequest, "缺少文件字段 file")
		return
	}
	defer file.Close()

	tmp := filepath.Join(os.TempDir(), "tunnelpilot-import.ppx")
	dst, err := os.Create(tmp)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if _, err = readAllInto(dst, file); err != nil {
		dst.Close()
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	dst.Close()

	profile, err := config.ImportPPX(tmp)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	profile.ListenPort = s.profile.ListenPort
	profile.TUNName = s.profile.TUNName
	profile.FakeIPPrefix = s.profile.FakeIPPrefix

	s.mu.Lock()
	s.profile = profile
	s.mu.Unlock()
	s.rules.Update(profile)
	if err = SaveProfile(profile, s.configPath); err != nil {
		writeError(w, http.StatusInternalServerError, "保存配置失败: "+err.Error())
		return
	}
	writeJSON(w, map[string]any{"ok": true, "rules": len(profile.Rules), "servers": len(profile.ProxyServers)})
}

// ---------------------------------------------------------------------------
// 配置持久化
// ---------------------------------------------------------------------------

func SaveProfile(p *config.Profile, path string) error {
	if path == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

func LoadProfile(path string) (*config.Profile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var p config.Profile
	if err = json.Unmarshal(data, &p); err != nil {
		return nil, err
	}
	return &p, nil
}
