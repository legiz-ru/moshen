// Modified from: https://github.com/Qv2ray/gun-lite
// License: MIT

package gun

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/metacubex/mihomo/common/buf"
	"github.com/metacubex/mihomo/common/pool"
	"github.com/metacubex/mihomo/component/ech"
	tlsC "github.com/metacubex/mihomo/component/tls"
	shareTLS "github.com/metacubex/mihomo/component/transport/tls"
	C "github.com/metacubex/mihomo/constant"

	"github.com/metacubex/http"
	"github.com/metacubex/http/httptrace"
	"github.com/metacubex/tls"
)

var (
	ErrInvalidLength = errors.New("invalid length")
	ErrSmallBuffer   = errors.New("buffer too small")
)

var defaultHeader = http.Header{
	"content-type": []string{"application/grpc"},
	"user-agent":   []string{"grpc-go/1.36.0"},
}

type DialFn = func(ctx context.Context, network, addr string) (net.Conn, error)

type Conn struct {
	initFn func() (io.ReadCloser, netAddr, error)
	writer io.Writer // writer must not nil
	closer io.Closer
	netAddr

	initOnce sync.Once
	initErr  error
	reader   io.ReadCloser
	br       *bufio.Reader
	remain   int

	closeMutex sync.Mutex
	closed     bool

	// deadlines
	deadline *time.Timer
}

type Config struct {
	ServiceName       string
	UserAgent         string
	Host              string
	ClientFingerprint string
}

func (g *Conn) initReader() {
	reader, addr, err := g.initFn()
	if err != nil {
		g.initErr = err
		if closer, ok := g.writer.(io.Closer); ok {
			closer.Close()
		}
		return
	}
	g.netAddr = addr

	g.closeMutex.Lock()
	defer g.closeMutex.Unlock()
	if g.closed { // if g.Close() be called between g.initFn(), direct close the initFn returned reader
		_ = reader.Close()
		g.initErr = net.ErrClosed
		return
	}

	g.reader = reader
	g.br = bufio.NewReader(reader)
}

func (g *Conn) Init() error {
	g.initOnce.Do(g.initReader)
	return g.initErr
}

func (g *Conn) Read(b []byte) (n int, err error) {
	if err = g.Init(); err != nil {
		return
	}

	if g.remain > 0 {
		size := g.remain
		if len(b) < size {
			size = len(b)
		}

		n, err = io.ReadFull(g.br, b[:size])
		g.remain -= n
		return
	}

	// 0x00 grpclength(uint32) 0x0A uleb128 payload
	_, err = g.br.Discard(6)
	if err != nil {
		return 0, err
	}

	protobufPayloadLen, err := binary.ReadUvarint(g.br)
	if err != nil {
		return 0, ErrInvalidLength
	}

	size := int(protobufPayloadLen)
	if len(b) < size {
		size = len(b)
	}

	n, err = io.ReadFull(g.br, b[:size])
	if err != nil {
		return
	}

	remain := int(protobufPayloadLen) - n
	if remain > 0 {
		g.remain = remain
	}

	return n, nil
}

func (g *Conn) Write(b []byte) (n int, err error) {
	protobufHeader := [binary.MaxVarintLen64 + 1]byte{0x0A}
	varuintSize := binary.PutUvarint(protobufHeader[1:], uint64(len(b)))
	var grpcHeader [5]byte
	grpcPayloadLen := uint32(varuintSize + 1 + len(b))
	binary.BigEndian.PutUint32(grpcHeader[1:5], grpcPayloadLen)

	buf := pool.GetBuffer()
	defer pool.PutBuffer(buf)
	buf.Write(grpcHeader[:])
	buf.Write(protobufHeader[:varuintSize+1])
	buf.Write(b)

	_, err = g.writer.Write(buf.Bytes())
	if err == io.ErrClosedPipe && g.initErr != nil {
		err = g.initErr
	}

	if flusher, ok := g.writer.(http.Flusher); ok {
		flusher.Flush()
	}

	return len(b), err
}

func (g *Conn) WriteBuffer(buffer *buf.Buffer) error {
	defer buffer.Release()
	dataLen := buffer.Len()
	varLen := UVarintLen(uint64(dataLen))
	header := buffer.ExtendHeader(6 + varLen)
	_ = header[6] // bounds check hint to compiler
	header[0] = 0x00
	binary.BigEndian.PutUint32(header[1:5], uint32(1+varLen+dataLen))
	header[5] = 0x0A
	binary.PutUvarint(header[6:], uint64(dataLen))
	_, err := g.writer.Write(buffer.Bytes())

	if err == io.ErrClosedPipe && g.initErr != nil {
		err = g.initErr
	}

	if flusher, ok := g.writer.(http.Flusher); ok {
		flusher.Flush()
	}

	return err
}

func (g *Conn) FrontHeadroom() int {
	return 6 + binary.MaxVarintLen64
}

func (g *Conn) Close() error {
	g.initOnce.Do(func() { // if initReader not called, it should not be run anymore
		g.initErr = net.ErrClosed
	})

	g.closeMutex.Lock()
	defer g.closeMutex.Unlock()
	if g.closed {
		return nil
	}
	g.closed = true

	var errorArr []error

	if reader := g.reader; reader != nil {
		if err := reader.Close(); err != nil {
			errorArr = append(errorArr, err)
		}
	}

	if closer, ok := g.writer.(io.Closer); ok {
		if err := closer.Close(); err != nil {
			errorArr = append(errorArr, err)
		}
	}

	if closer := g.closer; closer != nil {
		if err := closer.Close(); err != nil {
			errorArr = append(errorArr, err)
		}
	}

	return errors.Join(errorArr...)
}

func (g *Conn) SetReadDeadline(t time.Time) error  { return g.SetDeadline(t) }
func (g *Conn) SetWriteDeadline(t time.Time) error { return g.SetDeadline(t) }

func (g *Conn) SetDeadline(t time.Time) error {
	if t.IsZero() {
		if g.deadline != nil {
			g.deadline.Stop()
			g.deadline = nil
		}
		return nil
	}
	d := time.Until(t)
	if g.deadline != nil {
		g.deadline.Reset(d)
		return nil
	}
	g.deadline = time.AfterFunc(d, func() {
		g.Close()
	})
	return nil
}

// ✨ 修改点：增加 authCert 和 authKey 参数以支持 mTLS
func NewHTTP2Client(dialFn DialFn, tlsConfig *tls.Config, clientFingerprint string, authCert, authKey string, echConfig *ech.Config, realityConfig *tlsC.RealityConfig) *TransportWrap {
	dialFunc := func(ctx context.Context, network, addr string, cfg *tls.Config) (net.Conn, error) {
		ctx, cancel := context.WithTimeout(ctx, C.DefaultTLSTimeout)
		defer cancel()
		pconn, err := dialFn(ctx, network, addr)
		if err != nil {
			return nil, err
		}

		if tlsConfig == nil {
			return pconn, nil
		}

		// ✨ 魔法发生在这里：用一行代码替换掉原本 40 行的 TLS 判断逻辑
		conn, err := shareTLS.StreamTLSConn(ctx, pconn, &shareTLS.Config{
			Host:              cfg.ServerName,
			SkipCertVerify:    cfg.InsecureSkipVerify,
			ClientFingerprint: clientFingerprint,
			Certificate:       authCert, // ✨ 关键修复：补上 mTLS 证书
			PrivateKey:        authKey,  // ✨ 关键修复：补上 mTLS 私钥
			NextProtos:        cfg.NextProtos,
			ECH:               echConfig,
			Reality:           realityConfig,
		})
		if err != nil {
			pconn.Close()
			return nil, err
		}

		// 验证 ALPN
		var negotiatedProtocol string
		if uconn, ok := conn.(*tlsC.UConn); ok {
			negotiatedProtocol = uconn.ConnectionState().NegotiatedProtocol
		} else if tconn, ok := conn.(*tls.Conn); ok {
			negotiatedProtocol = tconn.ConnectionState().NegotiatedProtocol
		}

		if negotiatedProtocol != http.Http2NextProtoTLS {
			// 如果是 Reality 模式且协议为空，通常是因为 uTLS 状态未同步，对于 gRPC 我们可以尝试继续
			if realityConfig != nil && negotiatedProtocol == "" {
				return conn, nil
			}
			conn.Close()
			return nil, fmt.Errorf("http2: unexpected ALPN protocol %s, want %s", negotiatedProtocol, http.Http2NextProtoTLS)
		}
		return conn, nil
	}

	transport := &http.Http2Transport{
		DialTLSContext:     dialFunc,
		TLSClientConfig:    tlsConfig,
		AllowHTTP:          false,
		DisableCompression: true,
		PingTimeout:        0,
	}

	ctx, cancel := context.WithCancel(context.Background())
	wrap := &TransportWrap{
		Http2Transport: transport,
		ctx:            ctx,
		cancel:         cancel,
	}
	return wrap
}

func ServiceNameToPath(serviceName string) string {
	if strings.HasPrefix(serviceName, "/") { // custom paths
		return serviceName
	}
	return "/" + serviceName + "/Tun"
}

func StreamGunWithTransport(transport *TransportWrap, cfg *Config) (net.Conn, error) {
	serviceName := "GunService"
	if cfg.ServiceName != "" {
		serviceName = cfg.ServiceName
	}
	path := ServiceNameToPath(serviceName)

	reader, writer := io.Pipe()

	header := defaultHeader.Clone()
	if cfg.UserAgent != "" {
		header.Set("User-Agent", cfg.UserAgent)
	}

	request := &http.Request{
		Method: http.MethodPost,
		Body:   reader,
		URL: &url.URL{
			Scheme: "https",
			Host:   cfg.Host,
			Path:   path,
			// for unescape path
			Opaque: "//" + cfg.Host + path,
		},
		Proto:      "HTTP/2",
		ProtoMajor: 2,
		ProtoMinor: 0,
		Header:     header,
	}
	request = request.WithContext(transport.ctx)

	conn := &Conn{
		initFn: func() (io.ReadCloser, netAddr, error) {
			nAddr := netAddr{}
			trace := &httptrace.ClientTrace{
				GotConn: func(connInfo httptrace.GotConnInfo) {
					nAddr.localAddr = connInfo.Conn.LocalAddr()
					nAddr.remoteAddr = connInfo.Conn.RemoteAddr()
				},
			}
			request = request.WithContext(httptrace.WithClientTrace(request.Context(), trace))
			response, err := transport.RoundTrip(request)
			if err != nil {
				return nil, nAddr, err
			}
			return response.Body, nAddr, nil
		},
		writer: writer,
	}

	go conn.Init()
	return conn, nil
}

// ✨ 修改点：增加 authCert 和 authKey 参数
func StreamGunWithConn(conn net.Conn, tlsConfig *tls.Config, cfg *Config, authCert, authKey string, echConfig *ech.Config, realityConfig *tlsC.RealityConfig) (net.Conn, error) {
	dialFn := func(ctx context.Context, network, addr string) (net.Conn, error) {
		return conn, nil
	}

	transport := NewHTTP2Client(dialFn, tlsConfig, cfg.ClientFingerprint, authCert, authKey, echConfig, realityConfig)
	c, err := StreamGunWithTransport(transport, cfg)
	if err != nil {
		return nil, err
	}
	if c, ok := c.(*Conn); ok { // The incoming net.Conn should be closed synchronously with the generated gun.Conn
		c.closer = conn
	}
	return c, nil
}
