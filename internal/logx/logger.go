package logx

import (
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
	"time"
)

// Logger 实现 sing 的 logger.Logger 接口，输出带时间与级别的中文日志。
type Logger struct {
	mu      sync.Mutex
	verbose bool
	out     *log.Logger
}

func New(verbose bool) *Logger {
	return &Logger{
		verbose: verbose,
		out:     log.New(os.Stdout, "", 0),
	}
}

func (l *Logger) write(level string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	var sb strings.Builder
	sb.WriteString(time.Now().Format("15:04:05.000"))
	sb.WriteString(" [")
	sb.WriteString(level)
	sb.WriteString("] ")
	sb.WriteString(fmt.Sprintln(args...))
	l.out.Print(strings.TrimRight(sb.String(), "\n"))
}

func (l *Logger) Trace(args ...any) {
	if l.verbose {
		l.write("TRACE", args...)
	}
}

func (l *Logger) Debug(args ...any) {
	if l.verbose {
		l.write("DEBUG", args...)
	}
}

func (l *Logger) Info(args ...any)  { l.write("INFO ", args...) }
func (l *Logger) Warn(args ...any)  { l.write("WARN ", args...) }
func (l *Logger) Error(args ...any) { l.write("ERROR", args...) }

func (l *Logger) Fatal(args ...any) {
	l.write("FATAL", args...)
	os.Exit(1)
}

func (l *Logger) Panic(args ...any) {
	msg := fmt.Sprintln(args...)
	l.write("PANIC", args...)
	panic(msg)
}
