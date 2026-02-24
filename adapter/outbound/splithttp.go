package outbound

import (
	"context"
	"net"

	"github.com/metacubex/mihomo/component/ca"
	"github.com/metacubex/mihomo/component/ech"
	tlsC "github.com/metacubex/mihomo/component/tls"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/transport/splithttp"
	"github.com/metacubex/tls"
)

// connectedPacketConn 包装一个已连接的 net.Conn 以支持 net.PacketConn 接口。
// 这是为了解决 QUIC 库在已连接的 UDP 运行上调用 WriteTo 导致的错误。
type connectedPacketConn struct {
	net.Conn
}

func (c *connectedPacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	// 忽略传入的地址，因为连接已经 Dial 过了
	return c.Conn.Write(p)
}

func (c *connectedPacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	n, err = c.Conn.Read(p)
	return n, c.RemoteAddr(), err
}

type SplitHTTPOptions struct {
	Host                 string                 `proxy:"host,omitempty"`
	Path                 string                 `proxy:"path,omitempty"`
	Mode                 string                 `proxy:"mode,omitempty"`
	Headers              map[string]string      `proxy:"headers,omitempty"`
	XPaddingBytes        *splithttp.RangeConfig `proxy:"x-padding-bytes,omitempty"`
	XPaddingObfsMode     bool                   `proxy:"x-padding-obfs-mode,omitempty"`
	XPaddingKey          string                 `proxy:"x-padding-key,omitempty"`
	XPaddingHeader       string                 `proxy:"x-padding-header,omitempty"`
	XPaddingPlacement    string                 `proxy:"x-padding-placement,omitempty"`
	XPaddingMethod       string                 `proxy:"x-padding-method,omitempty"`
	UplinkHTTPMethod     string                 `proxy:"uplink-http-method,omitempty"`
	NoGRPCHeader         bool                   `proxy:"no-grpc-header,omitempty"`
	NoSSEHeader          bool                   `proxy:"no-sse-header,omitempty"`
	SessionPlacement     string                 `proxy:"session-placement,omitempty"`
	SessionKey           string                 `proxy:"session-key,omitempty"`
	SeqPlacement         string                 `proxy:"seq-placement,omitempty"`
	SeqKey               string                 `proxy:"seq-key,omitempty"`
	UplinkDataPlacement  string                 `proxy:"uplink-data-placement,omitempty"`
	UplinkDataKey        string                 `proxy:"uplink-data-key,omitempty"`
	UplinkChunkSize      uint32                 `proxy:"uplink-chunk-size,omitempty"`
	ScMaxEachPostBytes   *splithttp.RangeConfig `proxy:"max-each-post-bytes,omitempty"`
	ScMinPostsIntervalMs *splithttp.RangeConfig `proxy:"min-posts-interval,omitempty"`
	ScMaxBufferedPosts   int                    `proxy:"max-buffered-posts,omitempty"`
	ScStreamUpServerSecs *splithttp.RangeConfig `proxy:"stream-up-server-secs,omitempty"`
	Xmux                 *splithttp.XmuxConfig  `proxy:"xmux,omitempty"`
}

func ParseSplitHTTPConfig(opts SplitHTTPOptions, defaultHost string) *splithttp.Config {
	conf := &splithttp.Config{
		Host:                 opts.Host,
		Path:                 opts.Path,
		Mode:                 opts.Mode,
		Headers:              opts.Headers,
		XPaddingBytes:        opts.XPaddingBytes,
		XPaddingObfsMode:     opts.XPaddingObfsMode,
		XPaddingKey:          opts.XPaddingKey,
		XPaddingHeader:       opts.XPaddingHeader,
		XPaddingPlacement:    opts.XPaddingPlacement,
		XPaddingMethod:       opts.XPaddingMethod,
		UplinkHTTPMethod:     opts.UplinkHTTPMethod,
		NoGRPCHeader:         opts.NoGRPCHeader,
		NoSSEHeader:          opts.NoSSEHeader,
		SessionPlacement:     opts.SessionPlacement,
		SessionKey:           opts.SessionKey,
		SeqPlacement:         opts.SeqPlacement,
		SeqKey:               opts.SeqKey,
		UplinkDataPlacement:  opts.UplinkDataPlacement,
		UplinkDataKey:        opts.UplinkDataKey,
		UplinkChunkSize:      opts.UplinkChunkSize,
		ScMaxEachPostBytes:   opts.ScMaxEachPostBytes,
		ScMinPostsIntervalMs: opts.ScMinPostsIntervalMs,
		ScMaxBufferedPosts:   int32(opts.ScMaxBufferedPosts),
		ScStreamUpServerSecs: opts.ScStreamUpServerSecs,
		Xmux:                 opts.Xmux,
	}
	if conf.Host == "" {
		conf.Host = defaultHost
	}
	return conf
}

// NewSplitHTTPTransport 为各协议适配器提供统一的传输层实例创建工厂
func NewSplitHTTPTransport(
	opts SplitHTTPOptions, dialer C.Dialer, addr string, tlsEnabled bool,
	sni string, skipCertVerify bool, fingerprint, certificate, privateKey, clientFingerprint string,
	alpn []string, echConfig *ech.Config, realityConfig *tlsC.RealityConfig,
) (*splithttp.TransportWrap, error) {

	// 定义承载数据的 TCP 拨号闭包
	dialFn := func(ctx context.Context, network, dAddr string) (net.Conn, error) {
		return dialer.DialContext(ctx, "tcp", addr)
	}

	// 定义承载 H3 的 UDP 拨号闭包
	listenPacketFn := func(ctx context.Context) (net.PacketConn, net.Addr, error) {
		c, err := dialer.DialContext(ctx, "udp", addr)
		if err != nil {
			return nil, nil, err
		}
		// ✨ 核心修复：使用 connectedPacketConn 包装拨号后的 UDP 连接
		// 防止 quic-go 在已连接的套接字上调用 WriteTo
		return &connectedPacketConn{Conn: c}, c.RemoteAddr(), nil
	}

	// 构建 TLS 配置
	var tlsConfig *tls.Config
	if tlsEnabled {
		var err error
		tlsConfig, err = ca.GetTLSConfig(ca.Option{
			TLSConfig: &tls.Config{
				InsecureSkipVerify: skipCertVerify,
				ServerName:         sni,
				NextProtos:         alpn,
			},
			Fingerprint: fingerprint,
			Certificate: certificate,
			PrivateKey:  privateKey,
		})
		if err != nil {
			return nil, err
		}
		if tlsConfig.ServerName == "" {
			host, _, _ := net.SplitHostPort(addr)
			tlsConfig.ServerName = host
		}
	}

	defaultHost := sni
	if defaultHost == "" && tlsConfig != nil {
		defaultHost = tlsConfig.ServerName
	}
	if defaultHost == "" {
		defaultHost, _, _ = net.SplitHostPort(addr)
	}

	conf := ParseSplitHTTPConfig(opts, defaultHost)

	// 传入 certificate 和 privateKey 给传输层，支持 mTLS
	return splithttp.NewTransport(dialFn, listenPacketFn, tlsConfig, conf, clientFingerprint, certificate, privateKey, echConfig, realityConfig), nil
}
