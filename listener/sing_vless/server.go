package sing_vless

import (
	"context"
	"errors"
	"net"
	"strings"

	"github.com/metacubex/mihomo/adapter/inbound"
	"github.com/metacubex/mihomo/component/ca"
	"github.com/metacubex/mihomo/component/ech"
	ws "github.com/metacubex/mihomo/component/transport/websocket"
	C "github.com/metacubex/mihomo/constant"
	LC "github.com/metacubex/mihomo/listener/config"
	"github.com/metacubex/mihomo/listener/reality"
	"github.com/metacubex/mihomo/listener/sing"
	"github.com/metacubex/mihomo/ntp"
	"github.com/metacubex/mihomo/transport/gun"
	"github.com/metacubex/mihomo/transport/splithttp"
	"github.com/metacubex/mihomo/transport/vless/encryption"

	"github.com/metacubex/http"
	"github.com/metacubex/sing/common"
	"github.com/metacubex/sing/common/metadata"
	"github.com/metacubex/tls"
)

type Listener struct {
	closed     bool
	config     LC.VlessServer
	listeners  []net.Listener
	service    *Service[string]
	decryption *encryption.ServerInstance
}

func New(config LC.VlessServer, tunnel C.Tunnel, additions ...inbound.Addition) (sl *Listener, err error) {
	if len(additions) == 0 {
		additions = []inbound.Addition{
			inbound.WithInName("DEFAULT-VLESS"),
			inbound.WithSpecialRules(""),
		}
	}
	h, err := sing.NewListenerHandler(sing.ListenerConfig{
		Tunnel:    tunnel,
		Type:      C.VLESS,
		Additions: additions,
		MuxOption: config.MuxOption,
	})
	if err != nil {
		return nil, err
	}

	service := NewService[string](h)
	service.UpdateUsers(
		common.Map(config.Users, func(it LC.VlessUser) string {
			return it.Username
		}),
		common.Map(config.Users, func(it LC.VlessUser) string {
			return it.UUID
		}),
		common.Map(config.Users, func(it LC.VlessUser) string {
			return it.Flow
		}))

	sl = &Listener{config: config, service: service}

	sl.decryption, err = encryption.NewServer(config.Decryption)
	if err != nil {
		return nil, err
	}
	if sl.decryption != nil {
		defer func() { // decryption must be closed to avoid the goroutine leak
			if err != nil {
				_ = sl.decryption.Close()
				sl.decryption = nil
			}
		}()
	}

	tlsConfig := &tls.Config{Time: ntp.Now}
	var realityBuilder *reality.Builder

	if config.Certificate != "" && config.PrivateKey != "" {
		certLoader, err := ca.NewTLSKeyPairLoader(config.Certificate, config.PrivateKey)
		if err != nil {
			return nil, err
		}
		tlsConfig.GetCertificate = func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			return certLoader()
		}

		if config.EchKey != "" {
			err = ech.LoadECHKey(config.EchKey, tlsConfig)
			if err != nil {
				return nil, err
			}
		}
	}
	tlsConfig.ClientAuth = ca.ClientAuthTypeFromString(config.ClientAuthType)
	if len(config.ClientAuthCert) > 0 {
		if tlsConfig.ClientAuth == tls.NoClientCert {
			tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
		}
	}
	if tlsConfig.ClientAuth == tls.VerifyClientCertIfGiven || tlsConfig.ClientAuth == tls.RequireAndVerifyClientCert {
		pool, err := ca.LoadCertificates(config.ClientAuthCert)
		if err != nil {
			return nil, err
		}
		tlsConfig.ClientCAs = pool
	}
	if config.RealityConfig.PrivateKey != "" {
		if tlsConfig.GetCertificate != nil {
			return nil, errors.New("certificate is unavailable in reality")
		}
		if tlsConfig.ClientAuth != tls.NoClientCert {
			return nil, errors.New("client-auth is unavailable in reality")
		}
		realityBuilder, err = config.RealityConfig.Build(tunnel)
		if err != nil {
			return nil, err
		}
	}

	// 初始化多路复用 HTTP Mux
	var sharedHttpMux *http.ServeMux
	if config.WsPath != "" || config.SplitHTTP.Path != "" {
		sharedHttpMux = http.NewServeMux()
		tlsConfig.NextProtos = append(tlsConfig.NextProtos, "h2")
		// ✨ 修正：仅当且仅当配置了 WebSocket 时，才附加 http/1.1 支持
		if config.WsPath != "" {
			tlsConfig.NextProtos = append(tlsConfig.NextProtos, "http/1.1")
		}
	}

	if config.WsPath != "" {
		sharedHttpMux.HandleFunc(config.WsPath, func(w http.ResponseWriter, r *http.Request) {
			conn, err := ws.StreamUpgradedWebsocketConn(w, r)
			if err != nil {
				http.Error(w, err.Error(), 500)
				return
			}
			sl.HandleConn(conn, tunnel, additions...)
		})
	}

	if config.SplitHTTP.Path != "" {
		shConfig := &splithttp.Config{
			Path:                 config.SplitHTTP.Path,
			Mode:                 config.SplitHTTP.Mode,
			Headers:              config.SplitHTTP.Headers,
			XPaddingBytes:        config.SplitHTTP.XPaddingBytes,
			XPaddingObfsMode:     config.SplitHTTP.XPaddingObfsMode,
			XPaddingKey:          config.SplitHTTP.XPaddingKey,
			XPaddingHeader:       config.SplitHTTP.XPaddingHeader,
			XPaddingPlacement:    config.SplitHTTP.XPaddingPlacement,
			XPaddingMethod:       config.SplitHTTP.XPaddingMethod,
			UplinkHTTPMethod:     config.SplitHTTP.UplinkHTTPMethod,
			NoGRPCHeader:         config.SplitHTTP.NoGRPCHeader,
			NoSSEHeader:          config.SplitHTTP.NoSSEHeader,
			SessionPlacement:     config.SplitHTTP.SessionPlacement,
			SessionKey:           config.SplitHTTP.SessionKey,
			SeqPlacement:         config.SplitHTTP.SeqPlacement,
			SeqKey:               config.SplitHTTP.SeqKey,
			UplinkDataPlacement:  config.SplitHTTP.UplinkDataPlacement,
			UplinkDataKey:        config.SplitHTTP.UplinkDataKey,
			UplinkChunkSize:      config.SplitHTTP.UplinkChunkSize,
			ScMaxEachPostBytes:   config.SplitHTTP.ScMaxEachPostBytes,
			ScMinPostsIntervalMs: config.SplitHTTP.ScMinPostsIntervalMs,
			ScMaxBufferedPosts:   int32(config.SplitHTTP.ScMaxBufferedPosts),
			ScStreamUpServerSecs: config.SplitHTTP.ScStreamUpServerSecs,
		}

		shHandler := splithttp.NewServerHandler(shConfig, func(conn net.Conn) {
			sl.HandleConn(conn, tunnel, additions...)
		})

		sharedHttpMux.Handle(shConfig.GetNormalizedPath(), shHandler)
	}

	protocols := new(http.Protocols)
	protocols.SetHTTP1(true)
	protocols.SetUnencryptedHTTP2(true) // ✨ 开启 H2C 支持
	protocols.SetHTTP2(true)

	for _, addr := range strings.Split(config.Listen, ",") {
		addr := addr

		//TCP
		l, err := inbound.Listen("tcp", addr)
		if err != nil {
			return nil, err
		}
		if realityBuilder != nil {
			l = realityBuilder.NewListener(l)
		} else if tlsConfig.GetCertificate != nil {
			l = tls.NewListener(l, tlsConfig)
		} else if sl.decryption == nil && config.WsPath == "" && config.SplitHTTP.Path == "" && config.GrpcServiceName == "" {
			return nil, errors.New("disallow using Vless without any certificates/reality/decryption/transport config")
		}
		sl.listeners = append(sl.listeners, l)

		srv := &http.Server{
			TLSConfig: tlsConfig,
			Protocols: protocols,
		}
		if sharedHttpMux != nil {
			srv.Handler = sharedHttpMux
		}

		if config.GrpcServiceName != "" {
			srv.Handler = gun.NewServerHandler(gun.ServerOption{
				ServiceName: config.GrpcServiceName,
				ConnHandler: func(conn net.Conn) {
					sl.HandleConn(conn, tunnel, additions...)
				},
				HttpHandler: srv.Handler, // 嵌套原有的 Mux
			})
		}

		go func() {
			// 情况 A: 开启了传输层 (WS, gRPC, SplitHTTP/XHTTP)
			// 此时 srv.Handler 不为空
			if srv.Handler != nil {
				// http.Server 会根据 Path 自动分发流量
				// XHTTP 和 gRPC 流量会在这里被正确接管
				if err := srv.Serve(l); err != nil && !sl.closed {
					// 这里可以记录 debug 日志
				}
				return
			}

			// 情况 B: 纯 Raw TCP 模式 (测试用例中的 raw 模式)
			// 严禁启动 http.Server，直接进行同步 Accept
			for {
				c, err := l.Accept()
				if err != nil {
					if sl.closed {
						break
					}
					continue
				}
				// ⚠️ 必须回传 additions，否则用户匹配会失效
				go sl.HandleConn(c, tunnel, additions...)
			}
		}()
	}

	return sl, nil
}

func (l *Listener) Close() error {
	l.closed = true
	var retErr error
	for _, lis := range l.listeners {
		err := lis.Close()
		if err != nil {
			retErr = err
		}
	}
	if l.decryption != nil {
		_ = l.decryption.Close()
	}
	return retErr
}

func (l *Listener) Config() string {
	return l.config.String()
}

func (l *Listener) AddrList() (addrList []net.Addr) {
	for _, lis := range l.listeners {
		addrList = append(addrList, lis.Addr())
	}
	return
}

func (l *Listener) HandleConn(conn net.Conn, tunnel C.Tunnel, additions ...inbound.Addition) {
	ctx := sing.WithAdditions(context.TODO(), additions...)
	if l.decryption != nil {
		var err error
		conn, err = l.decryption.Handshake(conn, nil)
		if err != nil {
			return
		}
	}
	err := l.service.NewConnection(ctx, conn, metadata.Metadata{
		Protocol: "vless",
		Source:   metadata.SocksaddrFromNet(conn.RemoteAddr()),
	})
	if err != nil {
		_ = conn.Close()
		return
	}
}
