package sing_vmess

import (
	"context"
	"errors"
	"net"
	"net/url"
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

	"github.com/metacubex/http"
	vmess "github.com/metacubex/sing-vmess"
	"github.com/metacubex/sing/common"
	"github.com/metacubex/sing/common/metadata"
	"github.com/metacubex/tls"
)

type Listener struct {
	closed    bool
	config    LC.VmessServer
	listeners []net.Listener
	service   *vmess.Service[string]
}

var _listener *Listener

func New(config LC.VmessServer, tunnel C.Tunnel, additions ...inbound.Addition) (sl *Listener, err error) {
	if len(additions) == 0 {
		additions = []inbound.Addition{
			inbound.WithInName("DEFAULT-VMESS"),
			inbound.WithSpecialRules(""),
		}
		defer func() {
			_listener = sl
		}()
	}
	h, err := sing.NewListenerHandler(sing.ListenerConfig{
		Tunnel:    tunnel,
		Type:      C.VMESS,
		Additions: additions,
		MuxOption: config.MuxOption,
	})
	if err != nil {
		return nil, err
	}

	service := vmess.NewService[string](h, vmess.ServiceWithDisableHeaderProtection(), vmess.ServiceWithTimeFunc(ntp.Now))
	err = service.UpdateUsers(
		common.Map(config.Users, func(it LC.VmessUser) string {
			return it.Username
		}),
		common.Map(config.Users, func(it LC.VmessUser) string {
			return it.UUID
		}),
		common.Map(config.Users, func(it LC.VmessUser) int {
			return it.AlterID
		}))
	if err != nil {
		return nil, err
	}

	err = service.Start()
	if err != nil {
		return nil, err
	}

	sl = &Listener{false, config, nil, service}

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

	// ✨ 初始化多路复用 HTTP Mux
	var sharedHttpMux *http.ServeMux
	if config.WsPath != "" || config.SplitHTTP.Path != "" {
		sharedHttpMux = http.NewServeMux()
		tlsConfig.NextProtos = append(tlsConfig.NextProtos, "h2")
		// ✨ 修正：仅当且仅当配置了 WebSocket 时，才附加 http/1.1 支持
		if config.WsPath != "" {
			tlsConfig.NextProtos = append(tlsConfig.NextProtos, "http/1.1")
		}
	}

	// 注册原有的 WebSocket
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

	// 注册新增的 SplitHTTP
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

	// ✨ 修复：配置全局 Protocols
	protocols := new(http.Protocols)
	protocols.SetHTTP1(true)
	protocols.SetUnencryptedHTTP2(true) // ✨ 关键：开启 H2C 支持
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
			tlsConfig.NextProtos = append([]string{"h2"}, tlsConfig.NextProtos...) // h2 must before http/1.1
		}

        go func() {
            // 1. 判断是否真的需要启动 HTTP 栈 (WS, SplitHTTP 或 gRPC)
            // 如果 Handler 为 nil，说明是纯 Raw TCP 协议（测试中的 raw 模式）
            if srv.Handler != nil {
                _ = srv.Serve(l)
                return
            }

            // 2. 如果是纯 TCP (Vmess 流)，走原始 Accept 循环
            for {
                c, err := l.Accept()
                if err != nil {
                    if sl.closed {
                        break
                    }
                    continue
                }

                // ⚠️ 必须传入 additions，否则测试框架无法识别这个入站
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
	err := l.service.Close()
	if err != nil {
		retErr = err
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
	err := l.service.NewConnection(ctx, conn, metadata.Metadata{
		Protocol: "vmess",
		Source:   metadata.SocksaddrFromNet(conn.RemoteAddr()),
	})
	if err != nil {
		_ = conn.Close()
		return
	}
}

func HandleVmess(conn net.Conn, tunnel C.Tunnel, additions ...inbound.Addition) bool {
	if _listener != nil && _listener.service != nil {
		go _listener.HandleConn(conn, tunnel, additions...)
		return true
	}
	return false
}

func ParseVmessURL(s string) (addr, username, password string, err error) {
	u, err := url.Parse(s)
	if err != nil {
		return
	}

	addr = u.Host
	if u.User != nil {
		username = u.User.Username()
		password, _ = u.User.Password()
	}
	return
}
