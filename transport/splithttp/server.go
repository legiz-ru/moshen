package splithttp

import (
	"bytes"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/metacubex/http"
	"github.com/metacubex/mihomo/common/buf"
	N "github.com/metacubex/mihomo/common/net"
	"github.com/metacubex/mihomo/common/pool"
)

type httpSession struct {
	uploadQueue      *uploadQueue
	isFullyConnected chan struct{}
}

type remoteConn struct {
	net.Conn
	remote net.Addr
}

func (c *remoteConn) RemoteAddr() net.Addr { return c.remote }

type ServerHandler struct {
	config    *Config
	path      string
	sessionMu sync.Mutex
	sessions  sync.Map
	handleFn  func(net.Conn)
}

func NewServerHandler(cfg *Config, handleFn func(net.Conn)) *ServerHandler {
	return &ServerHandler{config: cfg, path: cfg.GetNormalizedPath(), handleFn: handleFn}
}

func (h *ServerHandler) upsertSession(sessionId string) *httpSession {
	if val, ok := h.sessions.Load(sessionId); ok {
		return val.(*httpSession)
	}
	h.sessionMu.Lock()
	defer h.sessionMu.Unlock()
	if val, ok := h.sessions.Load(sessionId); ok {
		return val.(*httpSession)
	}

	maxBuffered := h.config.GetNormalizedScMaxBufferedPosts()
	s := &httpSession{uploadQueue: NewUploadQueue(maxBuffered), isFullyConnected: make(chan struct{})}
	h.sessions.Store(sessionId, s)
	go func() {
		timer := time.NewTimer(30 * time.Second)
		defer timer.Stop()
		select {
		case <-timer.C:
			h.sessions.Delete(sessionId)
			s.uploadQueue.Close()
		case <-s.isFullyConnected:
		}
	}()
	return s
}

func (h *ServerHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if h.config.Host != "" && !strings.EqualFold(r.Host, h.config.Host) {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	if !strings.HasPrefix(r.URL.Path, h.path) {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	rc := http.NewResponseController(w)
	rc.EnableFullDuplex()
	h.config.WriteResponseHeader(w)
	h.applyPadding(w)

	validRange := h.config.GetNormalizedXPaddingBytes()
	paddingValue, _ := h.config.ExtractXPaddingFromRequest(r, h.config.XPaddingObfsMode)
	if !h.config.IsPaddingValid(paddingValue, validRange.From, validRange.To, PaddingMethod(h.config.XPaddingMethod)) {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	sessionId, seqStr := h.config.ExtractMetaFromRequest(r, h.path)
	isUplink := h.checkIsUplink(r)

	remoteAddrStr := r.RemoteAddr
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		ips := strings.Split(xff, ",")
		remoteAddrStr = strings.TrimSpace(ips[0]) + ":0"
	}
	rIP, rPort, _ := net.SplitHostPort(remoteAddrStr)
	remoteAddr := N.NewCustomAddr("tcp", remoteAddrStr, &net.TCPAddr{IP: net.ParseIP(rIP), Port: int(commonToUint16(rPort))})

	if sessionId == "" {
		if isUplink {
			h.handleStreamOne(w, r, rc, remoteAddr)
		} else {
			w.WriteHeader(http.StatusBadRequest)
		}
		return
	}
	currentSession := h.upsertSession(sessionId)
	if isUplink {
		h.handleUplink(w, r, rc, currentSession, seqStr)
	} else {
		h.handleDownlink(w, r, rc, currentSession, sessionId, remoteAddr)
	}
}

func commonToUint16(s string) uint16 {
	u, _ := strconv.ParseUint(s, 10, 16)
	return uint16(u)
}

type httpWriterWithFlush struct {
	w  http.ResponseWriter
	rc *http.ResponseController
}

func (hw httpWriterWithFlush) Write(p []byte) (n int, err error) {
	n, err = hw.w.Write(p)
	if err == nil {
		_ = hw.rc.Flush()
	}
	return
}

func (h *ServerHandler) handleStreamOne(w http.ResponseWriter, r *http.Request, rc *http.ResponseController, addr net.Addr) {
	w.Header().Set("X-Accel-Buffering", "no")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_ = rc.Flush()

	c1, c2 := N.Pipe()
	go h.handleFn(&remoteConn{Conn: N.NewDeadlineConn(c2), remote: addr})

	go func() { defer c1.Close(); _, _ = io.Copy(c1, r.Body) }()
	bufRelay := pool.Get(pool.RelayBufferSize)
	defer pool.Put(bufRelay)
	_, _ = io.CopyBuffer(httpWriterWithFlush{w, rc}, c1, bufRelay)
	_ = c1.Close()
}

func (h *ServerHandler) handleUplink(w http.ResponseWriter, r *http.Request, rc *http.ResponseController, session *httpSession, seqStr string) {
	if seqStr == "" {
		if err := session.uploadQueue.Push(Packet{Reader: r.Body}); err != nil {
			w.WriteHeader(http.StatusConflict)
			return
		}
		w.Header().Set("X-Accel-Buffering", "no")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusOK)
		_ = rc.Flush()

		scStreamUpServerSecs := h.config.GetNormalizedScStreamUpServerSecs()
		if r.Header.Get("Referer") != "" && scStreamUpServerSecs.To > 0 {
			go func() {
				for {
					padding := bytes.Repeat([]byte{'X'}, int(h.config.GetNormalizedXPaddingBytes().rand()))
					if _, err := w.Write(padding); err != nil {
						break
					}
					_ = rc.Flush()
					time.Sleep(time.Duration(scStreamUpServerSecs.rand()) * time.Second)
				}
			}()
		}
		<-r.Context().Done()
		return
	}

	size := int(r.ContentLength)
	if size <= 0 || size > 10485760 {
		size = 10485760
	}

	payloadRaw, err := io.ReadAll(io.LimitReader(r.Body, int64(size)))
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	payloadBuf := buf.As(payloadRaw)

	seq, _ := strconv.ParseUint(seqStr, 10, 64)
	if err := session.uploadQueue.Push(Packet{Buffer: payloadBuf, Seq: seq}); err != nil {
		if payloadBuf != nil {
			payloadBuf.Release()
		}
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (h *ServerHandler) handleDownlink(w http.ResponseWriter, r *http.Request, rc *http.ResponseController, session *httpSession, sessionId string, addr net.Addr) {
	close(session.isFullyConnected)
	defer h.sessions.Delete(sessionId)
	w.Header().Set("X-Accel-Buffering", "no")
	w.Header().Set("Cache-Control", "no-store")
	if !h.config.NoSSEHeader {
		w.Header().Set("Content-Type", "text/event-stream")
	}
	w.WriteHeader(http.StatusOK)
	_ = rc.Flush()

	c1, c2 := N.Pipe()
	go h.handleFn(&remoteConn{Conn: N.NewDeadlineConn(c2), remote: addr})

	go func() {
		defer c1.Close()
		bufRelay := pool.Get(pool.RelayBufferSize)
		defer pool.Put(bufRelay)
		_, _ = io.CopyBuffer(httpWriterWithFlush{w, rc}, c1, bufRelay)
	}()
	_, _ = io.Copy(c1, session.uploadQueue)
}

func (h *ServerHandler) applyPadding(w http.ResponseWriter) {
	length := int(h.config.GetNormalizedXPaddingBytes().rand())
	config := XPaddingConfig{Length: length}
	if h.config.XPaddingObfsMode {
		config.Placement = XPaddingPlacement{
			Placement: h.config.XPaddingPlacement,
			Key:       h.config.XPaddingKey,
			Header:    h.config.XPaddingHeader,
		}
		config.Method = PaddingMethod(h.config.XPaddingMethod)
	} else {
		config.Placement = XPaddingPlacement{
			Placement: PlacementHeader,
			Header:    "X-Padding",
		}
	}
	h.config.ApplyXPaddingToHeader(w.Header(), config)
}

func (h *ServerHandler) checkIsUplink(r *http.Request) bool {
	if r.Method == h.config.GetNormalizedUplinkHTTPMethod() {
		return true
	}
	key := h.config.UplinkDataKey
	if r.Header.Get(key+"-Upstream") == "1" {
		return true
	}
	if c, _ := r.Cookie(key + "_upstream"); c != nil && c.Value == "1" {
		return true
	}
	return false
}
