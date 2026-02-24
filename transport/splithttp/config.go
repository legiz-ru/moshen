package splithttp

import (
	"strings"

	"github.com/metacubex/http"
	"github.com/metacubex/randv2"
)

const (
	PlacementQueryInHeader = "queryInHeader"
	PlacementCookie        = "cookie"
	PlacementHeader        = "header"
	PlacementQuery         = "query"
	PlacementPath          = "path"
	PlacementBody          = "body"
)

type RangeConfig struct {
	From int32 `proxy:"from,omitempty"`
	To   int32 `proxy:"to,omitempty"`
}

func (c RangeConfig) rand() int32 {
	if c.From >= c.To {
		return c.From
	}
	return c.From + randv2.Int32N(c.To-c.From+1)
}

type XmuxConfig struct {
	MaxConcurrency   *RangeConfig `proxy:"max-concurrency,omitempty"`
	MaxConnections   *RangeConfig `proxy:"max-connections,omitempty"`
	CMaxReuseTimes   *RangeConfig `proxy:"c-max-reuse-times,omitempty"`
	HMaxRequestTimes *RangeConfig `proxy:"h-max-request-times,omitempty"`
	HMaxReusableSecs *RangeConfig `proxy:"h-max-reusable-secs,omitempty"`
	HKeepAlivePeriod int64        `proxy:"h-keep-alive-period,omitempty"`
}

type Config struct {
	Host, Path, Mode                                                                       string
	Headers                                                                                map[string]string
	XPaddingBytes                                                                          *RangeConfig
	XPaddingObfsMode                                                                       bool
	XPaddingKey, XPaddingHeader, XPaddingPlacement, XPaddingMethod, UplinkHTTPMethod       string
	NoGRPCHeader, NoSSEHeader                                                              bool
	SessionPlacement, SessionKey, SeqPlacement, SeqKey, UplinkDataPlacement, UplinkDataKey string
	UplinkChunkSize                                                                        uint32
	ScMaxEachPostBytes                                                                     *RangeConfig
	ScMinPostsIntervalMs                                                                   *RangeConfig
	ScMaxBufferedPosts                                                                     int32
	ScStreamUpServerSecs                                                                   *RangeConfig
	Xmux                                                                                   *XmuxConfig
}

func (c *Config) GetNormalizedPath() string {
	path := strings.Split(c.Path, "?")[0]
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	if !strings.HasSuffix(path, "/") {
		path += "/"
	}
	return path
}

func (c *Config) GetNormalizedQuery() string {
	parts := strings.Split(c.Path, "?")
	if len(parts) > 1 {
		return parts[1]
	}
	return ""
}

func (c *Config) GetRequestHeader() http.Header {
	h := http.Header{}
	for k, v := range c.Headers {
		h.Add(k, v)
	}
	if h.Get("User-Agent") == "" {
		h.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
	}
	return h
}

func (c *Config) WriteResponseHeader(w http.ResponseWriter) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "*")
	w.Header().Set("Access-Control-Allow-Headers", "*")
}

func (c *Config) GetNormalizedScMaxEachPostBytes() RangeConfig {
	if c.ScMaxEachPostBytes == nil || c.ScMaxEachPostBytes.To == 0 {
		return RangeConfig{From: 1000000, To: 1000000}
	}
	return *c.ScMaxEachPostBytes
}

func (c *Config) GetNormalizedXPaddingBytes() RangeConfig {
	if c.XPaddingBytes == nil || (c.XPaddingBytes.From == 0 && c.XPaddingBytes.To == 0) {
		return RangeConfig{From: 100, To: 1000}
	}
	return *c.XPaddingBytes
}

func (c *Config) GetNormalizedScMinPostsIntervalMs() RangeConfig {
	if c.ScMinPostsIntervalMs == nil || (c.ScMinPostsIntervalMs.From == 0 && c.ScMinPostsIntervalMs.To == 0) {
		return RangeConfig{From: 30, To: 30}
	}
	return *c.ScMinPostsIntervalMs
}

func (c *Config) GetNormalizedScMaxBufferedPosts() int {
	if c.ScMaxBufferedPosts <= 0 {
		return 30
	}
	return int(c.ScMaxBufferedPosts)
}

func (c *Config) GetNormalizedUplinkHTTPMethod() string {
	if c.UplinkHTTPMethod == "" {
		return "POST"
	}
	return c.UplinkHTTPMethod
}

func (c *Config) GetNormalizedSessionPlacement() string {
	if c.SessionPlacement == "" {
		return PlacementPath
	}
	return c.SessionPlacement
}

func (c *Config) GetNormalizedSeqPlacement() string {
	if c.SeqPlacement == "" {
		return PlacementPath
	}
	return c.SeqPlacement
}

func (c *Config) GetNormalizedSessionKey() string {
	if c.SessionKey != "" {
		return c.SessionKey
	}
	if c.GetNormalizedSessionPlacement() == PlacementHeader {
		return "X-Session"
	}
	return "x_session"
}

func (c *Config) GetNormalizedSeqKey() string {
	if c.SeqKey != "" {
		return c.SeqKey
	}
	if c.GetNormalizedSeqPlacement() == PlacementHeader {
		return "X-Seq"
	}
	return "x_seq"
}

func (c *Config) GetNormalizedUplinkDataPlacement() string {
	if c.UplinkDataPlacement == "" {
		return PlacementBody
	}
	return c.UplinkDataPlacement
}

func (c *Config) GetNormalizedScStreamUpServerSecs() RangeConfig {
	if c.ScStreamUpServerSecs == nil || c.ScStreamUpServerSecs.To == 0 {
		return RangeConfig{From: 20, To: 80}
	}
	return *c.ScStreamUpServerSecs
}

func (c *Config) ApplyMetaToRequest(req *http.Request, sessionId string, seqStr string) {
	sP, qP := c.GetNormalizedSessionPlacement(), c.GetNormalizedSeqPlacement()
	sK, qK := c.GetNormalizedSessionKey(), c.GetNormalizedSeqKey()
	if sessionId != "" {
		switch sP {
		case PlacementPath:
			req.URL.Path = appendToPath(req.URL.Path, sessionId)
		case PlacementQuery:
			q := req.URL.Query()
			q.Set(sK, sessionId)
			req.URL.RawQuery = q.Encode()
		case PlacementHeader:
			req.Header.Set(sK, sessionId)
		case PlacementCookie:
			req.AddCookie(&http.Cookie{Name: sK, Value: sessionId})
		}
	}
	if seqStr != "" {
		switch qP {
		case PlacementPath:
			req.URL.Path = appendToPath(req.URL.Path, seqStr)
		case PlacementQuery:
			q := req.URL.Query()
			q.Set(qK, seqStr)
			req.URL.RawQuery = q.Encode()
		case PlacementHeader:
			req.Header.Set(qK, seqStr)
		case PlacementCookie:
			req.AddCookie(&http.Cookie{Name: qK, Value: seqStr})
		}
	}
}

func (c *Config) ExtractMetaFromRequest(req *http.Request, path string) (sessionId string, seqStr string) {
	sP, qP := c.GetNormalizedSessionPlacement(), c.GetNormalizedSeqPlacement()
	sK, qK := c.GetNormalizedSessionKey(), c.GetNormalizedSeqKey()

	if sP == PlacementPath && qP == PlacementPath {
		uPath := req.URL.Path
		if len(uPath) > len(path) {
			subpath := strings.Split(strings.TrimPrefix(uPath[len(path):], "/"), "/")
			if len(subpath) > 0 {
				sessionId = subpath[0]
			}
			if len(subpath) > 1 {
				seqStr = subpath[1]
			}
		}
		return sessionId, seqStr
	}

	switch sP {
	case PlacementPath:
		sessionId = c.extractFromPath(req.URL.Path, path, 0)
	case PlacementQuery:
		sessionId = req.URL.Query().Get(sK)
	case PlacementHeader:
		sessionId = req.Header.Get(sK)
	case PlacementCookie:
		if cookie, e := req.Cookie(sK); e == nil {
			sessionId = cookie.Value
		}
	}

	switch qP {
	case PlacementPath:
		idx := 0
		if sP == PlacementPath {
			idx = 1
		}
		seqStr = c.extractFromPath(req.URL.Path, path, idx)
	case PlacementQuery:
		seqStr = req.URL.Query().Get(qK)
	case PlacementHeader:
		seqStr = req.Header.Get(qK)
	case PlacementCookie:
		if cookie, e := req.Cookie(qK); e == nil {
			seqStr = cookie.Value
		}
	}

	return sessionId, seqStr
}

func (c *Config) extractFromPath(uPath, basePath string, index int) string {
	if !strings.HasPrefix(uPath, basePath) {
		return ""
	}
	sub := strings.Trim(uPath[len(basePath):], "/")
	if sub == "" {
		return ""
	}
	parts := strings.Split(sub, "/")
	if index < len(parts) {
		return parts[index]
	}
	return ""
}

func appendToPath(path, value string) string {
	if strings.HasSuffix(path, "/") {
		return path + value
	}
	return path + "/" + value
}

func (m *XmuxConfig) GetNormalizedMaxConcurrency() RangeConfig {
	if m == nil || m.MaxConcurrency == nil {
		return RangeConfig{From: 0, To: 0}
	}
	return *m.MaxConcurrency
}
func (m *XmuxConfig) GetNormalizedMaxConnections() RangeConfig {
	if m == nil || m.MaxConnections == nil {
		// ✨ 修正：默认维持在 64，显著提升高并发下的稳定性
		return RangeConfig{From: 64, To: 64}
	}
	return *m.MaxConnections
}
func (m *XmuxConfig) GetNormalizedCMaxReuseTimes() RangeConfig {
	if m == nil || m.CMaxReuseTimes == nil {
		return RangeConfig{From: 0, To: 0}
	}
	return *m.CMaxReuseTimes
}
func (m *XmuxConfig) GetNormalizedHMaxRequestTimes() RangeConfig {
	if m == nil || m.HMaxRequestTimes == nil {
		return RangeConfig{From: 0, To: 0}
	}
	return *m.HMaxRequestTimes
}
func (m *XmuxConfig) GetNormalizedHMaxReusableSecs() RangeConfig {
	if m == nil || m.HMaxReusableSecs == nil {
		return RangeConfig{From: 0, To: 0}
	}
	return *m.HMaxReusableSecs
}
