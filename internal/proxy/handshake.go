package proxy

import (
	"context"
	"net"
	"time"
)

// proxyHandshakeTimeout 限制代理接受 TCP 后不响应握手时的等待时间。
const proxyHandshakeTimeout = 10 * time.Second

// beginHandshake 为代理协商设置超时，并在调用方取消时关闭连接。
// param ctx 为连接生命周期，conn 为已连通 socket；返回结束协商的清理函数，设置超时失败时返回错误。
func beginHandshake(ctx context.Context, conn net.Conn) (func(), error) {
	deadline := time.Now().Add(proxyHandshakeTimeout)
	if end, ok := ctx.Deadline(); ok && end.Before(deadline) {
		deadline = end
	}
	if err := conn.SetDeadline(deadline); err != nil {
		return nil, err
	}
	stopped := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		defer close(stopped)
		conn.Close()
	})
	return func() {
		if !stop() {
			<-stopped
		}
		// 协商结束后恢复长连接；取消导致的已关闭连接由调用方处理。
		if err := conn.SetDeadline(time.Time{}); err != nil {
			conn.Close()
		}
	}, nil
}
