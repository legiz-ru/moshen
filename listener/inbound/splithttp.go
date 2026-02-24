package inbound

import (
	LC "github.com/metacubex/mihomo/listener/config"
	"github.com/metacubex/mihomo/transport/splithttp"
)

type SplitHTTPOptions struct {
	Path                 string                 `inbound:"path,omitempty"`
	Mode                 string                 `inbound:"mode,omitempty"`
	Headers              map[string]string      `inbound:"headers,omitempty"`
	XPaddingBytes        *splithttp.RangeConfig `inbound:"x-padding-bytes,omitempty"`
	XPaddingObfsMode     bool                   `inbound:"x-padding-obfs-mode,omitempty"`
	XPaddingKey          string                 `inbound:"x-padding-key,omitempty"`
	XPaddingHeader       string                 `inbound:"x-padding-header,omitempty"`
	XPaddingPlacement    string                 `inbound:"x-padding-placement,omitempty"`
	XPaddingMethod       string                 `inbound:"x-padding-method,omitempty"`
	UplinkHTTPMethod     string                 `inbound:"uplink-http-method,omitempty"`
	NoGRPCHeader         bool                   `inbound:"no-grpc-header,omitempty"`
	NoSSEHeader          bool                   `inbound:"no-sse-header,omitempty"`
	SessionPlacement     string                 `inbound:"session-placement,omitempty"`
	SessionKey           string                 `inbound:"session-key,omitempty"`
	SeqPlacement         string                 `inbound:"seq-placement,omitempty"`
	SeqKey               string                 `inbound:"seq-key,omitempty"`
	UplinkDataPlacement  string                 `inbound:"uplink-data-placement,omitempty"`
	UplinkDataKey        string                 `inbound:"uplink-data-key,omitempty"`
	UplinkChunkSize      uint32                 `inbound:"uplink-chunk-size,omitempty"`
	ScMaxEachPostBytes   *splithttp.RangeConfig `inbound:"max-each-post-bytes,omitempty"`
	ScMinPostsIntervalMs *splithttp.RangeConfig `inbound:"min-posts-interval,omitempty"`
	ScMaxBufferedPosts   int                    `inbound:"max-buffered-posts,omitempty"`
	ScStreamUpServerSecs *splithttp.RangeConfig `inbound:"stream-up-server-secs,omitempty"`
}

func (o SplitHTTPOptions) Build() LC.SplitHTTPOptions {
	return LC.SplitHTTPOptions{
		Path:                 o.Path,
		Mode:                 o.Mode,
		Headers:              o.Headers,
		XPaddingBytes:        o.XPaddingBytes,
		XPaddingObfsMode:     o.XPaddingObfsMode,
		XPaddingKey:          o.XPaddingKey,
		XPaddingHeader:       o.XPaddingHeader,
		XPaddingPlacement:    o.XPaddingPlacement,
		XPaddingMethod:       o.XPaddingMethod,
		UplinkHTTPMethod:     o.UplinkHTTPMethod,
		NoGRPCHeader:         o.NoGRPCHeader,
		NoSSEHeader:          o.NoSSEHeader,
		SessionPlacement:     o.SessionPlacement,
		SessionKey:           o.SessionKey,
		SeqPlacement:         o.SeqPlacement,
		SeqKey:               o.SeqKey,
		UplinkDataPlacement:  o.UplinkDataPlacement,
		UplinkDataKey:        o.UplinkDataKey,
		UplinkChunkSize:      o.UplinkChunkSize,
		ScMaxEachPostBytes:   o.ScMaxEachPostBytes,
		ScMinPostsIntervalMs: o.ScMinPostsIntervalMs,
		ScMaxBufferedPosts:   o.ScMaxBufferedPosts,
		ScStreamUpServerSecs: o.ScStreamUpServerSecs,
	}
}
