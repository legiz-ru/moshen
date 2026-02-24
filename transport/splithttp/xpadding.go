package splithttp

import (
	"math"
	"net/url"
	"strings"

	"github.com/metacubex/http"
	"github.com/metacubex/randv2"
	"golang.org/x/net/http2/hpack"
)

type PaddingMethod string

const (
	PaddingMethodRepeatX  PaddingMethod = "repeat-x"
	PaddingMethodTokenish PaddingMethod = "tokenish"
)

const charsetBase62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
const avgHuffmanBytesPerCharBase62 = 0.8
const validationTolerance = 2

type XPaddingPlacement struct {
	Placement, Key, Header, RawURL string
}

type XPaddingConfig struct {
	Length    int
	Placement XPaddingPlacement
	Method    PaddingMethod
}

func GenerateTokenishPaddingBase62(target int) string {
	n := int(math.Ceil(float64(target) / avgHuffmanBytesPerCharBase62))
	if n < 1 {
		n = 1
	}
	res := make([]byte, n)
	for i := range res {
		res[i] = charsetBase62[randv2.Uint32N(uint32(len(charsetBase62)))]
	}
	s := string(res)
	for i := 0; i < 150; i++ {
		cur := int(hpack.HuffmanEncodeLength(s))
		diff := cur - target
		if diff >= -validationTolerance && diff <= validationTolerance {
			return s
		}
		if diff < 0 {
			s += "X"
		} else {
			s = s[:len(s)-1]
		}
	}
	return s
}

func GeneratePadding(method PaddingMethod, length int) string {
	if length <= 0 {
		return ""
	}
	if method == PaddingMethodTokenish {
		p := GenerateTokenishPaddingBase62(length)
		if p != "" {
			return p
		}
	}
	return strings.Repeat("X", length)
}

func (c *Config) ApplyXPaddingToHeader(h http.Header, cfg XPaddingConfig) {
	if h == nil {
		return
	}
	val := GeneratePadding(cfg.Method, cfg.Length)
	switch cfg.Placement.Placement {
	case PlacementHeader:
		h.Set(cfg.Placement.Header, val)
	case PlacementQueryInHeader:
		u, _ := url.Parse(cfg.Placement.RawURL)
		if u != nil {
			q := u.Query()
			q.Set(cfg.Placement.Key, val)
			u.RawQuery = q.Encode()
			h.Set(cfg.Placement.Header, u.String())
		}
	}
}

func (c *Config) ApplyXPaddingToRequest(req *http.Request, cfg XPaddingConfig) {
	if req == nil {
		return
	}
	if cfg.Placement.Placement == PlacementHeader || cfg.Placement.Placement == PlacementQueryInHeader {
		c.ApplyXPaddingToHeader(req.Header, cfg)
		return
	}
	val := GeneratePadding(cfg.Method, cfg.Length)
	if cfg.Placement.Placement == PlacementCookie {
		req.AddCookie(&http.Cookie{Name: cfg.Placement.Key, Value: val, Path: "/"})
	} else {
		q := req.URL.Query()
		q.Set(cfg.Placement.Key, val)
		req.URL.RawQuery = q.Encode()
	}
}

func (c *Config) ExtractXPaddingFromRequest(r *http.Request, obfs bool) (string, string) {
	if !obfs {
		if ref := r.Header.Get("Referer"); ref != "" {
			if u, _ := url.Parse(ref); u != nil {
				return u.Query().Get("x_padding"), "queryInHeader"
			}
		}
		return r.URL.Query().Get("x_padding"), "query"
	}
	if ck, _ := r.Cookie(c.XPaddingKey); ck != nil {
		return ck.Value, "cookie"
	}
	if hv := r.Header.Get(c.XPaddingHeader); hv != "" {
		if c.XPaddingPlacement == PlacementHeader {
			return hv, "header"
		}
		if u, _ := url.Parse(hv); u != nil {
			return u.Query().Get(c.XPaddingKey), "queryInHeader"
		}
	}
	return r.URL.Query().Get(c.XPaddingKey), "query"
}

func (c *Config) IsPaddingValid(val string, from, to int32, method PaddingMethod) bool {
	if val == "" {
		return false
	}
	if to <= 0 {
		r := c.GetNormalizedXPaddingBytes()
		from, to = r.From, r.To
	}
	if method == PaddingMethodTokenish {
		n := int32(hpack.HuffmanEncodeLength(val))
		return n >= from-int32(validationTolerance) && n <= to+int32(validationTolerance)
	}
	n := int32(len(val))
	return n >= from && n <= to
}
