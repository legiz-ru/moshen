package splithttp

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/url"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/metacubex/http"
	"github.com/metacubex/mihomo/common/buf"
	"github.com/metacubex/mihomo/common/pool"
	"github.com/metacubex/mihomo/common/utils"
	"github.com/metacubex/mihomo/component/ech"
	tlsC "github.com/metacubex/mihomo/component/tls"
	shareTLS "github.com/metacubex/mihomo/component/transport/tls"
	"github.com/metacubex/mihomo/log"
	"github.com/metacubex/quic-go"
	"github.com/metacubex/quic-go/http3"
	"github.com/metacubex/tls"
)

type uploadBuffer struct {
	sync.Mutex
	condFull, condEmpty *sync.Cond
	buf                 *bytes.Buffer
	closed              bool
	limit               int
}

func newUploadBuffer(limit int) *uploadBuffer {
	u := &uploadBuffer{buf: pool.GetBuffer(), limit: limit}
	u.condFull, u.condEmpty = sync.NewCond(&u.Mutex), sync.NewCond(&u.Mutex)
	return u
}

func (u *uploadBuffer) Write(b []byte) (int, error) {
	u.Lock()
	defer u.Unlock()
	for u.buf.Len() > u.limit && !u.closed {
		u.condFull.Wait()
	}
	if u.closed {
		return 0, io.ErrClosedPipe
	}
	n, err := u.buf.Write(b)
	u.condEmpty.Signal()
	return n, err
}

func (u *uploadBuffer) ReadBatch(max int) (*buf.Buffer, error) {
	u.Lock()
	defer u.Unlock()
	for u.buf.Len() == 0 && !u.closed {
		u.condEmpty.Wait()
	}
	if u.buf.Len() == 0 && u.closed {
		return nil, io.EOF
	}
	l := u.buf.Len()
	if l > max {
		l = max
	}
	b := buf.NewSize(l)
	_, _ = io.CopyN(b, u.buf, int64(l))
	u.condFull.Signal()
	return b, nil
}

func (u *uploadBuffer) Close() error {
	u.Lock()
	defer u.Unlock()
	u.closed = true
	u.condEmpty.Broadcast()
	u.condFull.Broadcast()
	return nil
}

type TransportWrap struct {
	ctx            context.Context
	cancel         context.CancelFunc
	config         *Config
	tlsConfig      *tls.Config
	realityConfig  *tlsC.RealityConfig
	dialFn         func(context.Context, string, string) (net.Conn, error)
	listenPacketFn func(context.Context) (net.PacketConn, net.Addr, error)
	xmuxManager    *XmuxManager
	httpVersion    string
}

// ✨ 修改点：增加 authCert, authKey 参数，总计 9 个参数，修复编译错误并支持 mTLS
func NewTransport(dialFn func(context.Context, string, string) (net.Conn, error), lpFn func(context.Context) (net.PacketConn, net.Addr, error), tlsCfg *tls.Config, cfg *Config, fp, authCert, authKey string, echCfg *ech.Config, realityCfg *tlsC.RealityConfig) *TransportWrap {
	ctx, cancel := context.WithCancel(context.Background())
	httpVersion := "2"
	if tlsCfg != nil && len(tlsCfg.NextProtos) > 0 && tlsCfg.NextProtos[0] == "h3" {
		httpVersion = "3"
	}
	tw := &TransportWrap{ctx: ctx, cancel: cancel, config: cfg, tlsConfig: tlsCfg, realityConfig: realityCfg, listenPacketFn: lpFn, httpVersion: httpVersion}
	tw.dialFn = func(ctxI context.Context, network, addr string) (net.Conn, error) {
		pconn, err := dialFn(ctxI, network, addr)
		if err != nil {
			return nil, err
		}
		if tlsCfg == nil {
			return pconn, nil
		}
		// ✨ 关键修复：在这里传入 authCert 和 authKey
		return shareTLS.StreamTLSConn(ctxI, pconn, &shareTLS.Config{
			Host:              tlsCfg.ServerName,
			SkipCertVerify:    tlsCfg.InsecureSkipVerify,
			NextProtos:        tlsCfg.NextProtos,
			ClientFingerprint: fp,
			Certificate:       authCert,
			PrivateKey:        authKey,
			ECH:               echCfg,
			Reality:           realityCfg,
		})
	}
	var xConf XmuxConfig
	if cfg.Xmux != nil {
		xConf = *cfg.Xmux
	}
	tw.xmuxManager = NewXmuxManager(xConf, func() XmuxConn { return tw.createHTTPClient() })
	return tw
}

func (tw *TransportWrap) HTTPVersion() string { return tw.httpVersion }
func (tw *TransportWrap) Close() error        { tw.cancel(); return nil }

func (tw *TransportWrap) createHTTPClient() DialerClient {
	var transport http.RoundTripper
	if tw.httpVersion == "3" {
		transport = &http3.Transport{QUICConfig: &quic.Config{MaxIdleTimeout: 90 * time.Second, KeepAlivePeriod: 15 * time.Second}, TLSClientConfig: tw.tlsConfig, Dial: func(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
			pconn, rAddr, err := tw.listenPacketFn(ctx)
			if err != nil {
				return nil, err
			}
			return quic.DialEarly(ctx, pconn, rAddr, tlsCfg, cfg)
		}}
	} else {
		transport = &http.Http2Transport{DialTLSContext: func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
			return tw.dialFn(ctx, network, addr)
		}, AllowHTTP: true}
	}
	return &DefaultDialerClient{transportConfig: tw.config, client: &http.Client{Transport: transport}}
}

func (tw *TransportWrap) DialContext(ctx context.Context) (net.Conn, error) {
	requestURL := url.URL{Scheme: "http", Path: tw.config.GetNormalizedPath(), RawQuery: tw.config.GetNormalizedQuery()}
	if tw.tlsConfig != nil {
		requestURL.Scheme = "https"
	}
	requestURL.Host = tw.config.Host
	if requestURL.Host == "" && tw.tlsConfig != nil {
		requestURL.Host = tw.tlsConfig.ServerName
	}

	xmuxClient := tw.xmuxManager.GetXmuxClient(ctx)
	httpClient := xmuxClient.XmuxConn.(DialerClient)
	mode := tw.config.Mode
	if mode == "" || mode == "auto" {
		mode = "packet-up"
		if tw.realityConfig != nil {
			mode = "stream-one"
		}
	}
	sessionId := ""
	if mode != "stream-one" {
		sessionId = utils.NewUUIDV4().String()
	}

	log.Debugln("[SplitHTTP] dialing to %s, mode: %s, HTTP version: %s", requestURL.Host, mode, tw.httpVersion)

	xmuxClient.OpenUsage.Add(1)
	var closed atomic.Int32
	conn := &splitConn{onClose: func() {
		if closed.Add(1) == 1 {
			xmuxClient.OpenUsage.Add(-1)
		}
	}}

	if mode == "stream-one" || mode == "stream-up" {
		pr, pw := io.Pipe()
		conn.writer = pw
		xmuxClient.LeftRequests.Add(-1)
		rc, waitHS, rAddr, lAddr, err := httpClient.OpenStream(ctx, requestURL.String(), sessionId, pr, mode == "stream-up")
		if err != nil {
			return nil, err
		}
		conn.reader, conn.waitHandshake, conn.remoteAddr, conn.localAddr = rc, waitHS, rAddr, lAddr
		return conn, nil
	}

	scMaxEach := tw.config.GetNormalizedScMaxEachPostBytes().rand()
	upBuf := newUploadBuffer(int(scMaxEach) * 30)
	conn.writer = upBuf

	// 限制并发信号量以防止高并发测试下的 TLS 握手堆积
	const maxConcurrency = 16
	semaphore := make(chan struct{}, maxConcurrency)
	for i := 0; i < maxConcurrency; i++ {
		semaphore <- struct{}{}
	}
	xmuxClient.LeftRequests.Add(-1)
	rc, waitHS, rAddr, lAddr, err := httpClient.OpenStream(ctx, requestURL.String(), sessionId, nil, false)
	if err != nil {
		return nil, err
	}
	conn.reader, conn.waitHandshake, conn.remoteAddr, conn.localAddr = rc, waitHS, rAddr, lAddr

	go func() {
		defer func() {
			upBuf.Lock()
			pool.PutBuffer(upBuf.buf)
			upBuf.Unlock()
		}()
		var seq int64
		for {
			select {
			case <-semaphore:
			case <-tw.ctx.Done():
				return
			}
			payload, err := upBuf.ReadBatch(int(scMaxEach))
			if payload != nil {
				seqStr := strconv.FormatInt(seq, 10)
				seq++
				if xmuxClient.LeftRequests.Add(-1) <= 0 {
					xmuxClient = tw.xmuxManager.GetXmuxClient(ctx)
					httpClient = xmuxClient.XmuxConn.(DialerClient)
				}
				go func(s string, p *buf.Buffer) {
					defer func() { semaphore <- struct{}{} }()
					defer p.Release()
					_ = httpClient.PostPacket(tw.ctx, requestURL.String(), sessionId, s, p.Bytes())
				}(seqStr, payload)
			} else {
				semaphore <- struct{}{}
			}
			if err != nil {
				break
			}
		}
	}()
	return conn, nil
}
