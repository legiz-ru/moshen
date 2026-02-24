package config

import "github.com/metacubex/mihomo/transport/splithttp"

type SplitHTTPOptions struct {
	Path                 string                 `yaml:"path,omitempty" json:"path,omitempty"`
	Mode                 string                 `yaml:"mode,omitempty" json:"mode,omitempty"`
	Headers              map[string]string      `yaml:"headers,omitempty" json:"headers,omitempty"`
	XPaddingBytes        *splithttp.RangeConfig `yaml:"x-padding-bytes,omitempty" json:"x-padding-bytes,omitempty"`
	XPaddingObfsMode     bool                   `yaml:"x-padding-obfs-mode,omitempty" json:"x-padding-obfs-mode,omitempty"`
	XPaddingKey          string                 `yaml:"x-padding-key,omitempty" json:"x-padding-key,omitempty"`
	XPaddingHeader       string                 `yaml:"x-padding-header,omitempty" json:"x-padding-header,omitempty"`
	XPaddingPlacement    string                 `yaml:"x-padding-placement,omitempty" json:"x-padding-placement,omitempty"`
	XPaddingMethod       string                 `yaml:"x-padding-method,omitempty" json:"x-padding-method,omitempty"`
	UplinkHTTPMethod     string                 `yaml:"uplink-http-method,omitempty" json:"uplink-http-method,omitempty"`
	NoGRPCHeader         bool                   `yaml:"no-grpc-header,omitempty" json:"no-grpc-header,omitempty"`
	NoSSEHeader          bool                   `yaml:"no-sse-header,omitempty" json:"no-sse-header,omitempty"`
	SessionPlacement     string                 `yaml:"session-placement,omitempty" json:"session-placement,omitempty"`
	SessionKey           string                 `yaml:"session-key,omitempty" json:"session-key,omitempty"`
	SeqPlacement         string                 `yaml:"seq-placement,omitempty" json:"seq-placement,omitempty"`
	SeqKey               string                 `yaml:"seq-key,omitempty" json:"seq-key,omitempty"`
	UplinkDataPlacement  string                 `yaml:"uplink-data-placement,omitempty" json:"uplink-data-placement,omitempty"`
	UplinkDataKey        string                 `yaml:"uplink-data-key,omitempty" json:"uplink-data-key,omitempty"`
	UplinkChunkSize      uint32                 `yaml:"uplink-chunk-size,omitempty" json:"uplink-chunk-size,omitempty"`
	ScMaxEachPostBytes   *splithttp.RangeConfig `yaml:"max-each-post-bytes,omitempty" json:"max-each-post-bytes,omitempty"`
	ScMinPostsIntervalMs *splithttp.RangeConfig `yaml:"min-posts-interval,omitempty" json:"min-posts-interval,omitempty"`
	ScMaxBufferedPosts   int                    `yaml:"max-buffered-posts,omitempty" json:"max-buffered-posts,omitempty"`
	ScStreamUpServerSecs *splithttp.RangeConfig `yaml:"stream-up-server-secs,omitempty" json:"stream-up-server-secs,omitempty"`
}
