package tls

import (
	"context"
	"errors"
	"net"

	"github.com/metacubex/mihomo/component/ca"
	"github.com/metacubex/mihomo/component/ech"
	tlsC "github.com/metacubex/mihomo/component/tls"
	"github.com/metacubex/tls"
)

type Config struct {
	Host                       string
	SkipCertVerify             bool
	FingerPrint                string
	Certificate                string
	PrivateKey                 string
	ClientFingerprint          string
	PreferWebsocketFingerprint bool // 新增字段：由调用者明确要求 WS 指纹
	NextProtos                 []string
	ECH                        *ech.Config
	Reality                    *tlsC.RealityConfig
}

func StreamTLSConn(ctx context.Context, conn net.Conn, cfg *Config) (net.Conn, error) {
	tlsConfig, err := ca.GetTLSConfig(ca.Option{
		TLSConfig: &tls.Config{
			ServerName:         cfg.Host,
			InsecureSkipVerify: cfg.SkipCertVerify,
			NextProtos:         cfg.NextProtos,
		},
		Fingerprint: cfg.FingerPrint,
		Certificate: cfg.Certificate,
		PrivateKey:  cfg.PrivateKey,
	})
	if err != nil {
		return nil, err
	}

	if clientFingerprint, ok := tlsC.GetFingerprint(cfg.ClientFingerprint); ok {
		if cfg.Reality != nil {
			return tlsC.GetRealityConn(ctx, conn, clientFingerprint, tlsConfig.ServerName, cfg.Reality)
		}

		tConfig := tlsC.UConfig(tlsConfig)
		if cfg.ECH != nil {
			err = cfg.ECH.ClientHandleUTLS(ctx, tConfig)
			if err != nil {
				return nil, err
			}
		}

		tlsConn := tlsC.UClient(conn, tConfig, clientFingerprint)

		if cfg.PreferWebsocketFingerprint {
			if err := tlsC.BuildWebsocketHandshakeState(tlsConn); err != nil {
				return nil, err
			}
		}

		err = tlsConn.HandshakeContext(ctx)
		if err != nil {
			return nil, err
		}
		return tlsConn, nil
	}

	if cfg.Reality != nil {
		return nil, errors.New("REALITY is based on uTLS, please set a client-fingerprint")
	}

	if cfg.ECH != nil {
		err = cfg.ECH.ClientHandle(ctx, tlsConfig)
		if err != nil {
			return nil, err
		}
	}

	tlsConn := tls.Client(conn, tlsConfig)
	err = tlsConn.HandshakeContext(ctx)
	return tlsConn, err
}
