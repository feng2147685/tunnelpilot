package tunengine

import (
	"context"
	"errors"
	"fmt"
	"net"
	"syscall"
)

// networkFailure 将可能包含域名、代理口令的底层错误转换为可公开的故障类别。
// param err 为底层错误；返回超时、解析、连接等分类，不回显原始目标或错误文本。
func networkFailure(err error) string {
	var networkError net.Error
	var dnsError *net.DNSError
	switch {
	case errors.Is(err, context.Canceled):
		return "操作已取消"
	case errors.As(err, &networkError) && networkError.Timeout():
		return "网络操作超时"
	case errors.Is(err, syscall.ECONNREFUSED):
		return "对端拒绝连接"
	case errors.Is(err, syscall.ENETUNREACH), errors.Is(err, syscall.EHOSTUNREACH):
		return "目标网络不可达"
	case errors.As(err, &dnsError):
		return "独立 DNS 解析失败"
	case errors.Is(err, net.ErrClosed):
		return "连接已关闭"
	default:
		return fmt.Sprintf("协议或连接操作失败 (%T)", err)
	}
}
