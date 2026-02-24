package websocket

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/metacubex/mihomo/common/buf"
	N "github.com/metacubex/mihomo/common/net"
	"github.com/metacubex/mihomo/component/ech"
	shareTLS "github.com/metacubex/mihomo/component/transport/tls"
	"github.com/metacubex/mihomo/log"

	"github.com/gobwas/ws"
	"github.com/gobwas/ws/wsutil"
	"github.com/metacubex/http"
	"github.com/metacubex/randv2"
	"github.com/metacubex/tls"
)

type websocketConn struct {
	net.Conn
	state          ws.State
	reader         *wsutil.Reader
	controlHandler wsutil.FrameHandlerFunc

	rawWriter N.ExtendedWriter
}

type websocketWithEarlyDataConn struct {
	wConn    net.Conn // ✨ 修改点：取消匿名嵌入，改为具名成员，防止递归死循环
	wsWriter N.ExtendedWriter
	underlay net.Conn
	dialed   chan bool
	cancel   context.CancelFunc
	ctx      context.Context
	config   *Config
}

type Config struct {
	Host                     string
	Port                     string
	Path                     string
	Headers                  http.Header
	TLS                      bool
	TLSConfig                *tls.Config
	ECHConfig                *ech.Config
	MaxEarlyData             int
	EarlyDataHeaderName      string
	ClientFingerprint        string
	V2rayHttpUpgrade         bool
	V2rayHttpUpgradeFastOpen bool
	Certificate              string
	PrivateKey               string
}

// Read implements net.Conn.Read()
// modify from gobwas/ws/wsutil.readData
func (wsc *websocketConn) Read(b []byte) (n int, err error) {
	defer func() { // avoid gobwas/ws pbytes.GetLen panic
		if value := recover(); value != nil {
			err = fmt.Errorf("websocket error: %s", value)
		}
	}()
	var header ws.Header
	for {
		n, err = wsc.reader.Read(b)
		// in gobwas/ws: "The error is io.EOF only if all of message bytes were read."
		// but maybe next frame still have data, so drop it
		if errors.Is(err, io.EOF) {
			err = nil
		}
		if !errors.Is(err, wsutil.ErrNoFrameAdvance) {
			return
		}
		header, err = wsc.reader.NextFrame()
		if err != nil {
			return
		}
		if header.OpCode.IsControl() {
			err = wsc.controlHandler(header, wsc.reader)
			if err != nil {
				return
			}
			continue
		}
		if header.OpCode&(ws.OpBinary|ws.OpText) == 0 {
			err = wsc.reader.Discard()
			if err != nil {
				return
			}
			continue
		}
	}
}

// Write implements io.Writer.
func (wsc *websocketConn) Write(b []byte) (n int, err error) {
	err = wsutil.WriteMessage(wsc.Conn, wsc.state, ws.OpBinary, b)
	if err != nil {
		return
	}
	n = len(b)
	return
}

func (wsc *websocketConn) WriteBuffer(buffer *buf.Buffer) error {
	var payloadBitLength int
	dataLen := buffer.Len()
	data := buffer.Bytes()
	if dataLen < 126 {
		payloadBitLength = 1
	} else if dataLen < 65536 {
		payloadBitLength = 3
	} else {
		payloadBitLength = 9
	}

	var headerLen int
	headerLen += 1 // FIN / RSV / OPCODE
	headerLen += payloadBitLength
	if wsc.state.ClientSide() {
		headerLen += 4 // MASK KEY
	}

	header := buffer.ExtendHeader(headerLen)
	header[0] = byte(ws.OpBinary) | 0x80
	if wsc.state.ClientSide() {
		header[1] = 1 << 7
	} else {
		header[1] = 0
	}

	if dataLen < 126 {
		header[1] |= byte(dataLen)
	} else if dataLen < 65536 {
		header[1] |= 126
		binary.BigEndian.PutUint16(header[2:], uint16(dataLen))
	} else {
		header[1] |= 127
		binary.BigEndian.PutUint64(header[2:], uint64(dataLen))
	}

	if wsc.state.ClientSide() {
		maskKey := randv2.Uint32()
		binary.LittleEndian.PutUint32(header[1+payloadBitLength:], maskKey)
		N.MaskWebSocket(maskKey, data)
	}

	return wsc.rawWriter.WriteBuffer(buffer)
}

func (wsc *websocketConn) FrontHeadroom() int {
	return 14
}

func (wsc *websocketConn) Upstream() any {
	return wsc.Conn
}

func (wsc *websocketConn) Close() error {
	_ = wsc.Conn.SetWriteDeadline(time.Now().Add(time.Second * 5))
	_ = wsutil.WriteMessage(wsc.Conn, wsc.state, ws.OpClose, ws.NewCloseFrameBody(ws.StatusNormalClosure, ""))
	_ = wsc.Conn.Close()
	return nil
}

func (wsedc *websocketWithEarlyDataConn) Dial(earlyData []byte) error {
	base64DataBuf := &bytes.Buffer{}
	base64EarlyDataEncoder := base64.NewEncoder(base64.RawURLEncoding, base64DataBuf)

	earlyDataBuf := bytes.NewBuffer(earlyData)
	if _, err := base64EarlyDataEncoder.Write(earlyDataBuf.Next(wsedc.config.MaxEarlyData)); err != nil {
		return fmt.Errorf("failed to encode early data: %w", err)
	}

	if errc := base64EarlyDataEncoder.Close(); errc != nil {
		return fmt.Errorf("failed to encode early data tail: %w", errc)
	}

	var err error
	// ✨ 修复：赋值给具名成员 wConn
	if wsedc.wConn, err = streamWebsocketConn(wsedc.ctx, wsedc.underlay, wsedc.config, base64DataBuf); err != nil {
		wsedc.Close()
		return fmt.Errorf("failed to dial WebSocket: %w", err)
	}

	wsedc.dialed <- true
	wsedc.wsWriter = N.NewExtendedWriter(wsedc.wConn)
	if earlyDataBuf.Len() != 0 {
		_, err = wsedc.wConn.Write(earlyDataBuf.Bytes())
	}

	return err
}

func (wsedc *websocketWithEarlyDataConn) Write(b []byte) (int, error) {
	if wsedc.ctx.Err() != nil {
		return 0, io.ErrClosedPipe
	}
	if wsedc.wConn == nil {
		if err := wsedc.Dial(b); err != nil {
			return 0, err
		}
		return len(b), nil
	}

	return wsedc.wConn.Write(b)
}

func (wsedc *websocketWithEarlyDataConn) WriteBuffer(buffer *buf.Buffer) error {
	if wsedc.ctx.Err() != nil {
		return io.ErrClosedPipe
	}
	if wsedc.wConn == nil {
		if err := wsedc.Dial(buffer.Bytes()); err != nil {
			return err
		}
		return nil
	}

	return wsedc.wsWriter.WriteBuffer(buffer)
}

func (wsedc *websocketWithEarlyDataConn) Read(b []byte) (int, error) {
	if wsedc.ctx.Err() != nil {
		return 0, io.ErrClosedPipe
	}
	if wsedc.wConn == nil {
		select {
		case <-wsedc.ctx.Done():
			return 0, io.ErrUnexpectedEOF
		case <-wsedc.dialed:
		}
	}
	return wsedc.wConn.Read(b)
}

func (wsedc *websocketWithEarlyDataConn) Close() error {
	wsedc.cancel()
	if wsedc.wConn == nil {
		return wsedc.underlay.Close()
	}
	return wsedc.wConn.Close()
}

func (wsedc *websocketWithEarlyDataConn) LocalAddr() net.Addr {
	if wsedc.wConn == nil {
		return wsedc.underlay.LocalAddr()
	}
	return wsedc.wConn.LocalAddr()
}

func (wsedc *websocketWithEarlyDataConn) RemoteAddr() net.Addr {
	if wsedc.wConn == nil {
		return wsedc.underlay.RemoteAddr()
	}
	return wsedc.wConn.RemoteAddr()
}

func (wsedc *websocketWithEarlyDataConn) SetDeadline(t time.Time) error {
	if err := wsedc.SetReadDeadline(t); err != nil {
		return err
	}
	return wsedc.SetWriteDeadline(t)
}

func (wsedc *websocketWithEarlyDataConn) SetReadDeadline(t time.Time) error {
	if wsedc.wConn == nil {
		return nil
	}
	return wsedc.wConn.SetReadDeadline(t)
}

func (wsedc *websocketWithEarlyDataConn) SetWriteDeadline(t time.Time) error {
	if wsedc.wConn == nil {
		return nil
	}
	// ✨ 修复：显式调用 wConn 的方法，彻底消除递归栈溢出风险
	return wsedc.wConn.SetWriteDeadline(t)
}

func (wsedc *websocketWithEarlyDataConn) FrontHeadroom() int {
	return 14
}

func (wsedc *websocketWithEarlyDataConn) Upstream() any {
	return wsedc.underlay
}

func (wsedc *websocketWithEarlyDataConn) NeedHandshake() bool {
	return wsedc.wConn == nil
}

func streamWebsocketWithEarlyDataConn(conn net.Conn, c *Config) (net.Conn, error) {
	ctx, cancel := context.WithCancel(context.Background())
	wsedc := &websocketWithEarlyDataConn{
		dialed:   make(chan bool, 1),
		cancel:   cancel,
		ctx:      ctx,
		underlay: conn,
		config:   c,
	}
	// websocketWithEarlyDataConn can't correct handle Deadline
	// it will not apply the already set Deadline after Dial()
	// so call N.NewDeadlineConn to add a safe wrapper
	return N.NewDeadlineConn(wsedc), nil
}

func streamWebsocketConn(ctx context.Context, conn net.Conn, c *Config, earlyData *bytes.Buffer) (_ net.Conn, err error) {
	u, err := url.Parse(c.Path)
	if err != nil {
		return nil, fmt.Errorf("parse url %s error: %w", c.Path, err)
	}

	uri := url.URL{
		Scheme:   "ws",
		Host:     net.JoinHostPort(c.Host, c.Port),
		Path:     u.Path,
		RawQuery: u.RawQuery,
	}

	if !strings.HasPrefix(uri.Path, "/") {
		uri.Path = "/" + uri.Path
	}

	if c.TLS {
		uri.Scheme = "wss"
		// 直接调用统一的 TLS 握手组件
		tlsCfg := &shareTLS.Config{
			Host:                       c.Host,
			SkipCertVerify:             false,
			ClientFingerprint:          c.ClientFingerprint,
			ECH:                        c.ECHConfig,
			Certificate:                c.Certificate,
			PrivateKey:                 c.PrivateKey,
			NextProtos:                 []string{"http/1.1"},
			PreferWebsocketFingerprint: true, // ✨ 显式开启
		}
		if c.TLSConfig != nil {
			tlsCfg.SkipCertVerify = c.TLSConfig.InsecureSkipVerify
			tlsCfg.Host = c.TLSConfig.ServerName
			if tlsCfg.Host == "" {
				tlsCfg.Host = c.Host
			}
		}

		var err error
		conn, err = shareTLS.StreamTLSConn(ctx, conn, tlsCfg)
		if err != nil {
			return nil, err
		}
	}

	request := &http.Request{
		Method: http.MethodGet,
		URL:    &uri,
		Header: c.Headers.Clone(),
		Host:   c.Host,
	}

	request.Header.Set("Connection", "Upgrade")
	request.Header.Set("Upgrade", "websocket")

	if host := request.Header.Get("Host"); host != "" {
		// For client requests, Host optionally overrides the Host
		// header to send. If empty, the Request.Write method uses
		// the value of URL.Host. Host may contain an international
		// domain name.
		request.Host = host
	}
	request.Header.Del("Host")

	var secKey string
	if !c.V2rayHttpUpgrade {
		// NOTE: bts does not escape.
		bts := make([]byte, 16)
		if _, err = rand.Read(bts); err != nil {
			return nil, fmt.Errorf("rand read error: %w", err)
		}
		secKey = base64.StdEncoding.EncodeToString(bts)
		request.Header.Set("Sec-WebSocket-Version", "13")
		request.Header.Set("Sec-WebSocket-Key", secKey)
	}

	if earlyData != nil {
		earlyDataString := earlyData.String()
		if c.EarlyDataHeaderName == "" {
			uri.Path += earlyDataString
		} else {
			request.Header.Set(c.EarlyDataHeaderName, earlyDataString)
		}
	}

	if ctx.Done() != nil {
		done := N.SetupContextForConn(ctx, conn)
		defer done(&err)
	}

	err = request.Write(conn)
	if err != nil {
		return nil, err
	}
	bufferedConn := N.NewBufferedConn(conn)

	if c.V2rayHttpUpgrade && c.V2rayHttpUpgradeFastOpen {
		return N.NewEarlyConn(bufferedConn, func() error {
			response, err := http.ReadResponse(bufferedConn.Reader(), request)
			if err != nil {
				return err
			}
			if response.StatusCode != http.StatusSwitchingProtocols ||
				!strings.EqualFold(response.Header.Get("Connection"), "upgrade") ||
				!strings.EqualFold(response.Header.Get("Upgrade"), "websocket") {
				return fmt.Errorf("unexpected status: %s", response.Status)
			}
			return nil
		}), nil
	}

	response, err := http.ReadResponse(bufferedConn.Reader(), request)
	if err != nil {
		return nil, err
	}
	if response.StatusCode != http.StatusSwitchingProtocols ||
		!strings.EqualFold(response.Header.Get("Connection"), "upgrade") ||
		!strings.EqualFold(response.Header.Get("Upgrade"), "websocket") {
		return nil, fmt.Errorf("unexpected status: %s", response.Status)
	}

	if c.V2rayHttpUpgrade {
		return bufferedConn, nil
	}

	if log.Level() == log.DEBUG { // we might not check this for performance
		secAccept := response.Header.Get("Sec-Websocket-Accept")
		if N.GetWebSocketSecAccept(secKey) != secAccept {
			return nil, errors.New("unexpected Sec-Websocket-Accept")
		}
	}

	conn = newWebsocketConn(bufferedConn, ws.StateClientSide)
	// websocketConn can't correct handle ReadDeadline
	// so call N.NewDeadlineConn to add a safe wrapper
	return N.NewDeadlineConn(conn), nil
}

func StreamConn(ctx context.Context, conn net.Conn, c *Config) (net.Conn, error) {
	if u, err := url.Parse(c.Path); err == nil {
		if q := u.Query(); q.Get("ed") != "" {
			if ed, err := strconv.Atoi(q.Get("ed")); err == nil {
				c.MaxEarlyData = ed
				c.EarlyDataHeaderName = "Sec-WebSocket-Protocol"
				q.Del("ed")
				u.RawQuery = q.Encode()
				c.Path = u.String()
			}
		}
	}

	if c.MaxEarlyData > 0 {
		return streamWebsocketWithEarlyDataConn(conn, c)
	}

	return streamWebsocketConn(ctx, conn, c, nil)
}

func newWebsocketConn(conn net.Conn, state ws.State) *websocketConn {
	controlHandler := wsutil.ControlFrameHandler(conn, state)
	return &websocketConn{
		Conn:  conn,
		state: state,
		reader: &wsutil.Reader{
			Source:          conn,
			State:           state,
			SkipHeaderCheck: true,
			CheckUTF8:       false,
			OnIntermediate:  controlHandler,
		},
		controlHandler: controlHandler,
		rawWriter:      N.NewExtendedWriter(conn),
	}
}

func IsWebSocketUpgrade(r *http.Request) bool {
	return r.Header.Get("Upgrade") == "websocket"
}

func IsV2rayHttpUpdate(r *http.Request) bool {
	return IsWebSocketUpgrade(r) && r.Header.Get("Sec-WebSocket-Key") == ""
}

func StreamUpgradedWebsocketConn(w http.ResponseWriter, r *http.Request) (net.Conn, error) {
	isRaw := IsV2rayHttpUpdate(r)
	w.Header().Set("Connection", "upgrade")
	w.Header().Set("Upgrade", "websocket")
	if !isRaw {
		w.Header().Set("Sec-Websocket-Accept", N.GetWebSocketSecAccept(r.Header.Get("Sec-WebSocket-Key")))
	}
	w.WriteHeader(http.StatusSwitchingProtocols)

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		return nil, errors.New("hijack not supported")
	}
	conn, rw, err := hijacker.Hijack()
	if err != nil {
		return nil, err
	}

	// rw.Writer was flushed, so we only need warp rw.Reader
	conn = N.WarpConnWithBioReader(conn, rw.Reader)

	if !isRaw {
		conn = newWebsocketConn(conn, ws.StateServerSide)
		// websocketConn can't correct handle ReadDeadline
		// so call N.NewDeadlineConn to add a safe wrapper
		conn = N.NewDeadlineConn(conn)
	}

	if secProtocol := r.Header.Get("Sec-WebSocket-Protocol"); len(secProtocol) > 0 {
		if edBuf, err := base64.RawURLEncoding.DecodeString(strings.NewReplacer("+", "-", "/", "_", "=", "").Replace(secProtocol)); err == nil {
			conn = N.NewCachedConn(conn, edBuf)
		}
	}

	return conn, nil
}
