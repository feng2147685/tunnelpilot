package proxy

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"time"

	"tunnelpilot/internal/config"
)

// UDPRelay 是一条通过 SOCKS5 UDP ASSOCIATE 建立的中继。
// 控制连接（TCP）必须全程保持，一旦断开代理服务器会回收 UDP 端口。
type UDPRelay struct {
	ctrlConn net.Conn
	udpConn  net.Conn
	relay    string
}

// SupportsUDP 判断某个代理服务器是否支持 UDP 转发。
// 目前只有 SOCKS5 支持（HTTP CONNECT 只能承载 TCP）。
// param server 为代理配置；返回协议能力，未知协议返回 false。
func SupportsUDP(server config.ProxyServer) bool {
	return server.Protocol == config.ProtocolSOCKS5
}

// AssociateUDP 与 SOCKS5 服务器建立 UDP 关联，返回可收发的中继。
// param ctx/server 为期限及代理配置；返回中继，握手、解析或建连失败关闭控制连接。
func (d *Dialer) AssociateUDP(ctx context.Context, server config.ProxyServer) (*UDPRelay, error) {
	ctrl, err := d.newNetDialer().DialContext(ctx, "tcp",
		net.JoinHostPort(server.Address, strconv.Itoa(int(server.Port))))
	if err != nil {
		return nil, fmt.Errorf("连接代理 %s:%d 失败: %w", server.Address, server.Port, err)
	}

	finish, err := beginHandshake(ctx, ctrl)
	if err != nil {
		ctrl.Close()
		return nil, err
	}
	defer finish()
	if err = socks5Auth(ctrl, server); err != nil {
		ctrl.Close()
		return nil, err
	}

	// UDP ASSOCIATE 请求：CMD=0x03，地址填 0.0.0.0:0 表示由服务器决定
	req := []byte{0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
	if _, err = ctrl.Write(req); err != nil {
		ctrl.Close()
		return nil, err
	}

	header := make([]byte, 4)
	if _, err = io.ReadFull(ctrl, header); err != nil {
		ctrl.Close()
		return nil, err
	}
	if header[0] != 0x05 || header[2] != 0x00 {
		ctrl.Close()
		return nil, errors.New("SOCKS5 UDP 响应头无效")
	}
	if header[1] != 0x00 {
		ctrl.Close()
		return nil, fmt.Errorf("SOCKS5 UDP ASSOCIATE 被拒绝，错误码 0x%02x", header[1])
	}

	var relayHost string
	switch header[3] {
	case 0x01:
		buf := make([]byte, 4)
		if _, err = io.ReadFull(ctrl, buf); err != nil {
			ctrl.Close()
			return nil, err
		}
		relayHost = net.IP(buf).String()
	case 0x04:
		buf := make([]byte, 16)
		if _, err = io.ReadFull(ctrl, buf); err != nil {
			ctrl.Close()
			return nil, err
		}
		relayHost = net.IP(buf).String()
	case 0x03:
		lenByte := make([]byte, 1)
		if _, err = io.ReadFull(ctrl, lenByte); err != nil {
			ctrl.Close()
			return nil, err
		}
		buf := make([]byte, int(lenByte[0]))
		if _, err = io.ReadFull(ctrl, buf); err != nil {
			ctrl.Close()
			return nil, err
		}
		relayHost = string(buf)
	default:
		ctrl.Close()
		return nil, fmt.Errorf("未知的 SOCKS5 地址类型 0x%02x", header[3])
	}

	portBuf := make([]byte, 2)
	if _, err = io.ReadFull(ctrl, portBuf); err != nil {
		ctrl.Close()
		return nil, err
	}
	relayPort := binary.BigEndian.Uint16(portBuf)

	// 服务器返回 0.0.0.0 时表示与 TCP 同一主机
	if relayHost == "0.0.0.0" || relayHost == "::" || relayHost == "" {
		relayHost = server.Address
	}
	relayAddr := net.JoinHostPort(relayHost, strconv.Itoa(int(relayPort)))

	udpConn, err := d.newNetDialer().DialContext(ctx, "udp", relayAddr)
	if err != nil {
		ctrl.Close()
		return nil, fmt.Errorf("建立 UDP 中继失败: %w", err)
	}

	return &UDPRelay{ctrlConn: ctrl, udpConn: udpConn, relay: relayAddr}, nil
}

// Send 把 payload 封装成 SOCKS5 UDP 数据报发给中继。
// param targetHost/targetPort/payload 为目标及负载；返回写入错误。
func (r *UDPRelay) Send(targetHost string, targetPort uint16, payload []byte) error {
	packet := buildUDPDatagram(targetHost, targetPort, payload)
	_, err := r.udpConn.Write(packet)
	return err
}

// ReadPayload 读取一个数据报，剥离 SOCKS5 头后把净荷搬到 buf 开头。
// param buf 为接收空间；返回净荷长度，调用方用 buf[:n]，无效协议帧返回错误。
func (r *UDPRelay) ReadPayload(buf []byte) (int, error) {
	n, err := r.udpConn.Read(buf)
	if err != nil {
		return 0, err
	}
	offset, _, _, err := parseUDPDatagram(buf[:n])
	if err != nil {
		return 0, err
	}
	payloadLen := n - offset
	copy(buf, buf[offset:n])
	return payloadLen, nil
}

// Close 同时释放中继与 TCP 控制连接；param 无；返回聚合的关闭错误。
func (r *UDPRelay) Close() error {
	var errs []error
	if r.udpConn != nil {
		errs = append(errs, r.udpConn.Close())
	}
	if r.ctrlConn != nil {
		errs = append(errs, r.ctrlConn.Close())
	}
	return errors.Join(errs...)
}

// SetDeadline 设置 UDP 收发期限。
// param t 为期限；返回 socket 设置错误。
func (r *UDPRelay) SetDeadline(t time.Time) error {
	return r.udpConn.SetDeadline(t)
}

// buildUDPDatagram 封装 SOCKS5 UDP 报文。
// param host/port/payload 为目的端点及负载；返回报文字节，调用者负责有效目标。
func buildUDPDatagram(host string, port uint16, payload []byte) []byte {
	buf := make([]byte, 0, len(payload)+300)
	buf = append(buf, 0x00, 0x00, 0x00) // RSV + FRAG

	if ip := net.ParseIP(host); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			buf = append(buf, 0x01)
			buf = append(buf, ip4...)
		} else {
			buf = append(buf, 0x04)
			buf = append(buf, ip.To16()...)
		}
	} else {
		if len(host) > 255 {
			host = host[:255]
		}
		buf = append(buf, 0x03, byte(len(host)))
		buf = append(buf, []byte(host)...)
	}

	buf = append(buf, byte(port>>8), byte(port&0xFF))
	buf = append(buf, payload...)
	return buf
}

// parseUDPDatagram 校验 SOCKS5 UDP 地址头和非分片约束。
// param data 为完整报文；返回负载偏移和端点，格式错误时返回错误。
func parseUDPDatagram(data []byte) (payloadOffset int, host string, port uint16, err error) {
	if len(data) < 5 {
		return 0, "", 0, errors.New("UDP 数据报过短")
	}
	if data[2] != 0x00 {
		return 0, "", 0, errors.New("不支持分片的 SOCKS5 UDP 数据报")
	}

	offset := 4
	switch data[3] {
	case 0x01:
		if len(data) < offset+4+2 {
			return 0, "", 0, errors.New("UDP 数据报 IPv4 段不完整")
		}
		host = net.IP(data[offset : offset+4]).String()
		offset += 4
	case 0x04:
		if len(data) < offset+16+2 {
			return 0, "", 0, errors.New("UDP 数据报 IPv6 段不完整")
		}
		host = net.IP(data[offset : offset+16]).String()
		offset += 16
	case 0x03:
		hostLen := int(data[offset])
		offset++
		if len(data) < offset+hostLen+2 {
			return 0, "", 0, errors.New("UDP 数据报域名片不完整")
		}
		host = string(data[offset : offset+hostLen])
		offset += hostLen
	default:
		return 0, "", 0, fmt.Errorf("未知的 UDP 地址类型 0x%02x", data[3])
	}

	port = binary.BigEndian.Uint16(data[offset : offset+2])
	offset += 2
	return offset, host, port, nil
}

// socks5Auth 只完成 SOCKS5 的版本协商与认证，供 TCP / UDP 复用。
// param conn/server 为控制连接及认证配置；返回认证、协议或 I/O 错误。
func socks5Auth(conn net.Conn, server config.ProxyServer) error {
	methods := []byte{0x05, 0x01, 0x00}
	if server.Username != "" {
		methods = []byte{0x05, 0x02, 0x00, 0x02}
	}
	if _, err := conn.Write(methods); err != nil {
		return err
	}
	reply := make([]byte, 2)
	if _, err := io.ReadFull(conn, reply); err != nil {
		return err
	}
	if reply[0] != 0x05 {
		return fmt.Errorf("SOCKS5 版本错误: 0x%02x", reply[0])
	}
	if reply[1] == 0x02 {
		user := []byte(server.Username)
		pass := []byte(server.Password)
		if len(user) > 255 || len(pass) > 255 {
			return errors.New("SOCKS5 用户名或密码过长")
		}
		auth := []byte{0x01, byte(len(user))}
		auth = append(auth, user...)
		auth = append(auth, byte(len(pass)))
		auth = append(auth, pass...)
		if _, err := conn.Write(auth); err != nil {
			return err
		}
		authReply := make([]byte, 2)
		if _, err := io.ReadFull(conn, authReply); err != nil {
			return err
		}
		if authReply[0] != 0x01 || authReply[1] != 0x00 {
			return errors.New("SOCKS5 用户名密码认证被拒绝")
		}
	} else if reply[1] != 0x00 {
		return fmt.Errorf("SOCKS5 不支持的认证方式: 0x%02x", reply[1])
	}
	return nil
}
