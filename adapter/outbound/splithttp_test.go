package outbound

import (
	"context"
	"net"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
)

type mockDialer struct{}

func (m *mockDialer) DialContext(ctx context.Context, n, a string) (net.Conn, error) { return nil, nil }
func (m *mockDialer) ListenPacket(ctx context.Context, n, a string, r netip.AddrPort) (net.PacketConn, error) {
	return nil, nil
}

func TestAdapter_SplitHTTP_Factory(t *testing.T) {
	opts := SplitHTTPOptions{Path: "/test", Mode: "packet-up"}
	transport, err := NewSplitHTTPTransport(
		opts, &mockDialer{}, "1.1.1.1:443", false, "", false, "", "", "", "", nil, nil, nil,
	)
	assert.NoError(t, err)
	assert.NotNil(t, transport)

	// ✨ 修正：XHTTP 默认使用 HTTP/2 (H2C)，不再支持 1.1
	// 预期值应为 "2"
	assert.Equal(t, "2", transport.HTTPVersion())
}
