package trojan

import (
	"errors"
	"io"
	"net"
	"strings"

	"github.com/metacubex/mihomo/adapter/inbound"
	N "github.com/metacubex/mihomo/common/net"
	"github.com/metacubex/mihomo/common/utils"
	"github.com/metacubex/mihomo/component/ca"
	"github.com/metacubex/mihomo/component/ech"
	ws "github.com/metacubex/mihomo/component/transport/websocket"
	C "github.com/metacubex/mihomo/constant"
	LC "github.com/metacubex/mihomo/listener/config"
	"github.com/metacubex/mihomo/listener/reality"
	"github.com/metacubex/mihomo/listener/sing"
	"github.com/metacubex/mihomo/ntp"
	"github.com/metacubex/mihomo/transport/gun"
	"github.com/metacubex/mihomo/transport/shadowsocks/core"
	"github.com/metacubex/mihomo/transport/socks5"
	"github.com/metacubex/mihomo/transport/splithttp"
	"github.com/metacubex/mihomo/transport/trojan"

	"github.com/metacubex/http"
	"github.com/metacubex/smux"
	"github.com/metacubex/tls"
)

type Listener struct {
	closed     bool
	config     LC.TrojanServer
	listeners  []net.Listener
	keys       map[[trojan.KeyLength]byte]string
	pickCipher core.Cipher
	handler    *sing.ListenerHandler
}

func New(config LC.TrojanServer, tunnel C.Tunnel, additions ...inbound.Addition) (sl *Listener, err error) {
	if len(additions) == 0 {
		additions = []inbound.Addition{
			inbound.WithInName("DEFAULT-TROJAN"),
			inbound.WithSpecialRules(""),
		}
	}
	h, err := sing.NewListenerHandler(sing.ListenerConfig{
		Tunnel:    tunnel,
		Type:      C.TROJAN,
		Additions: additions,
		MuxOption: config.MuxOption,
	})
	if err != nil {
		return nil, err
	}

	keys := make(map[[trojan.KeyLength]byte]string)
	for _, user := range config.Users {
		keys[trojan.Key(user.Password)] = user.Username
	}

	var pickCipher core.Cipher
	if config.TrojanSSOption.Enabled {
		if config.TrojanSSOption.Password == "" {
			return nil, errors.New("empty password")
		}
		if config.TrojanSSOption.Method == "" {
			config.TrojanSSOption.Method = "AES-128-GCM"
		}
		pickCipher, err = core.PickCipher(config.TrojanSSOption.Method, nil, config.TrojanSSOption.Password)
		if err != nil {
			return nil, err
		}
	}
	sl = &Listener{false, config, nil, keys, pickCipher, h}

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

	// 统一处理 HTTP Mux 逻辑
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
		} else if !config.TrojanSSOption.Enabled && config.WsPath == "" && config.SplitHTTP.Path == "" && config.GrpcServiceName == "" {
			return nil, errors.New("disallow using Trojan without any certificates/reality/ss/transport config")
		}
		sl.listeners = append(sl.listeners, l)

		srv := &http.Server{
			TLSConfig: tlsConfig,
			Protocols: protocols, // ✨ 注入配置
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
			// 1. 判断是否真的需要启动 HTTP 栈 (WS, SplitHTTP 或 gRPC)
			// 如果 Handler 为 nil，说明是纯 Raw TCP 协议（测试中的 raw 模式）
			if srv.Handler != nil {
				_ = srv.Serve(l)
				return
			}

			// 2. 如果是纯 TCP (Trojan 流)，走原始 Accept 循环
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

	if l.pickCipher != nil {
		conn = l.pickCipher.StreamConn(conn)
	}

	var key [trojan.KeyLength]byte
	if _, err := io.ReadFull(conn, key[:]); err != nil {
		//log.Warnln("read key error: %s", err.Error())
		return
	}

	if user, ok := l.keys[key]; ok {
		additions = append(additions, inbound.WithInUser(user))
	} else {
		//log.Warnln("no such key")
		return
	}

	var crlf [2]byte
	if _, err := io.ReadFull(conn, crlf[:]); err != nil {
		//log.Warnln("read crlf error: %s", err.Error())
		return
	}

	l.handleConn(false, conn, tunnel, additions...)
}

func (l *Listener) handleConn(inMux bool, conn net.Conn, tunnel C.Tunnel, additions ...inbound.Addition) {
	if inMux {
		defer conn.Close()
	}

	command, err := socks5.ReadByte(conn)
	if err != nil {
		//log.Warnln("read command error: %s", err.Error())
		return
	}

	switch command {
	case trojan.CommandTCP, trojan.CommandUDP, trojan.CommandMux:
	default:
		//log.Warnln("unknown command: %d", command)
		return
	}

	target, err := socks5.ReadAddr0(conn)
	if err != nil {
		//log.Warnln("read target error: %s", err.Error())
		return
	}

	if !inMux {
		var crlf [2]byte
		if _, err := io.ReadFull(conn, crlf[:]); err != nil {
			//log.Warnln("read crlf error: %s", err.Error())
			return
		}
	}

	switch command {
	case trojan.CommandTCP:
		//tunnel.HandleTCPConn(inbound.NewSocket(target, conn, C.TROJAN, additions...))
		l.handler.HandleSocket(target, conn, additions...)
	case trojan.CommandUDP:
		pc := trojan.NewPacketConn(conn)
		remoteAddr := conn.RemoteAddr()
		connID := utils.NewUUIDV4().String() // make a new SNAT key

		for {
			data, put, addr, err := pc.WaitReadFrom()
			if err != nil {
				if put != nil {
					put()
				}
				break
			}
			target := socks5.ParseAddrToSocksAddr(addr)
			cPacket := &packet{
				pc:      pc,
				rAddr:   remoteAddr,
				payload: data,
				put:     put,
			}
			cPacket.rAddr = N.NewCustomAddr(C.TROJAN.String(), connID, cPacket.rAddr) // for tunnel's handleUDPConn

			tunnel.HandleUDPPacket(inbound.NewPacket(target, cPacket, C.TROJAN, additions...))
		}
	case trojan.CommandMux:
		if inMux {
			//log.Warnln("invalid command: %d", command)
			return
		}
		smuxConfig := smux.DefaultConfig()
		smuxConfig.KeepAliveDisabled = true
		session, err := smux.Server(conn, smuxConfig)
		if err != nil {
			//log.Warnln("smux server error: %s", err.Error())
			return
		}
		defer session.Close()
		for {
			stream, err := session.AcceptStream()
			if err != nil {
				return
			}
			go l.handleConn(true, stream, tunnel, additions...)
		}
	}
}
