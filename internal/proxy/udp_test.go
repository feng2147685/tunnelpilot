package proxy

import (
	"bytes"
	"testing"

	"tunnelpilot/internal/config"
)

func configServer(protocol string) config.ProxyServer {
	return config.ProxyServer{Protocol: protocol}
}

func TestUDPDatagramRoundTripDomain(t *testing.T) {
	payload := []byte("hello socks5 udp")
	packet := buildUDPDatagram("api.openai.com", 443, payload)

	offset, host, port, err := parseUDPDatagram(packet)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if host != "api.openai.com" {
		t.Errorf("域名不一致: %s", host)
	}
	if port != 443 {
		t.Errorf("端口不一致: %d", port)
	}
	if !bytes.Equal(packet[offset:], payload) {
		t.Errorf("载荷不一致: %q", packet[offset:])
	}
}

func TestUDPDatagramRoundTripIPv4(t *testing.T) {
	packet := buildUDPDatagram("1.2.3.4", 53, []byte{0xde, 0xad})

	offset, host, port, err := parseUDPDatagram(packet)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if host != "1.2.3.4" || port != 53 {
		t.Errorf("地址解析错误: %s:%d", host, port)
	}
	if len(packet[offset:]) != 2 {
		t.Errorf("载荷长度错误: %d", len(packet[offset:]))
	}
}

func TestUDPDatagramRejectsFragment(t *testing.T) {
	packet := buildUDPDatagram("1.2.3.4", 53, []byte{1})
	packet[2] = 0x01 // 标记为分片

	if _, _, _, err := parseUDPDatagram(packet); err == nil {
		t.Error("分片数据报应返回错误")
	}
}

func TestUDPDatagramRejectsShort(t *testing.T) {
	if _, _, _, err := parseUDPDatagram([]byte{0, 0, 0}); err == nil {
		t.Error("过短的数据报应返回错误")
	}
}

func TestSupportsUDP(t *testing.T) {
	if !SupportsUDP(configServer("SOCKS5")) {
		t.Error("SOCKS5 应支持 UDP")
	}
	if SupportsUDP(configServer("HTTPS")) {
		t.Error("HTTPS 不支持 UDP")
	}
	if SupportsUDP(configServer("SOCKS4")) {
		t.Error("SOCKS4 不支持 UDP")
	}
}
