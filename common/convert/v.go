package convert

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

func handleVShareLink(names map[string]int, url *url.URL, scheme string, proxy map[string]any) error {
	// Xray VMessAEAD / VLESS share link standard
	// https://github.com/XTLS/Xray-core/discussions/716
	query := url.Query()
	proxy["name"] = uniqueName(names, url.Fragment)
	if url.Hostname() == "" {
		return errors.New("url.Hostname() is empty")
	}
	if url.Port() == "" {
		proxy["port"] = "80"
	} else {
		proxy["port"] = url.Port()
	}
	proxy["type"] = scheme
	proxy["server"] = url.Hostname()
	proxy["uuid"] = url.User.Username()
	proxy["udp"] = true
	proxy["skip-cert-verify"] = true
	tls := strings.ToLower(query.Get("security"))
	if strings.HasSuffix(tls, "tls") || tls == "reality" {
		proxy["tls"] = true
		if fingerprint := query.Get("fp"); fingerprint == "" {
			proxy["client-fingerprint"] = "chrome"
		} else {
			proxy["client-fingerprint"] = fingerprint
		}
		if alpn := query.Get("alpn"); alpn != "" {
			proxy["alpn"] = strings.Split(alpn, ",")
		}
		if pcs := query.Get("pcs"); pcs != "" {
			proxy["fingerprint"] = pcs
		}
	}
	if sni := query.Get("sni"); sni != "" {
		proxy["servername"] = sni
	}
	if realityPublicKey := query.Get("pbk"); realityPublicKey != "" {
		proxy["reality-opts"] = map[string]any{
			"public-key": realityPublicKey,
			"short-id":   query.Get("sid"),
		}
	}

	switch query.Get("packetEncoding") {
	case "none":
	case "packet":
		proxy["packet-addr"] = true
	default:
		proxy["xudp"] = true
	}

	network := strings.ToLower(query.Get("type"))
	if network == "" {
		network = "tcp"
	}
	fakeType := strings.ToLower(query.Get("headerType"))
	if fakeType == "http" {
		network = "http"
	}
	proxy["network"] = network
	switch network {
	case "tcp":
		if fakeType != "none" {
			headers := make(map[string]any)
			httpOpts := make(map[string]any)
			httpOpts["path"] = []string{"/"}

			if host := query.Get("host"); host != "" {
				headers["Host"] = []string{host}
			}

			if method := query.Get("method"); method != "" {
				httpOpts["method"] = method
			}

			if path := query.Get("path"); path != "" {
				httpOpts["path"] = []string{path}
			}
			httpOpts["headers"] = headers
			proxy["http-opts"] = httpOpts
		}

	case "http":
		headers := make(map[string]any)
		h2Opts := make(map[string]any)
		h2Opts["path"] = "/"
		if path := query.Get("path"); path != "" {
			h2Opts["path"] = path
		}
		if host := query.Get("host"); host != "" {
			h2Opts["host"] = []string{host}
		}
		h2Opts["headers"] = headers
		proxy["h2-opts"] = h2Opts

	case "ws", "httpupgrade":

		wsOpts := make(map[string]any)
		if path := query.Get("path"); path != "" {
			wsOpts["path"] = path
		}

		if host := query.Get("host"); host != "" {
			headers := make(map[string]any)
			headers["User-Agent"] = RandUserAgent()
			headers["Host"] = host
			wsOpts["headers"] = headers
		}

		if earlyData := query.Get("ed"); earlyData != "" {
			med, err := strconv.Atoi(earlyData)
			if err != nil {
				return fmt.Errorf("bad WebSocket max early data size: %v", err)
			}
			wsOpts["max-early-data"] = med
			wsOpts["early-data-header-name"] = "Sec-WebSocket-Protocol"
		}
		if earlyDataHeader := query.Get("eh"); earlyDataHeader != "" {
			wsOpts["early-data-header-name"] = earlyDataHeader
		}

		if network == "httpupgrade" {
			wsOpts["v2ray-http-upgrade"] = true
			wsOpts["v2ray-http-upgrade-fast-open"] = true
		}

		proxy["network"] = "ws"
		proxy["ws-opts"] = wsOpts

	case "grpc":
		grpcOpts := make(map[string]any)
		grpcOpts["grpc-service-name"] = query.Get("serviceName")
		proxy["grpc-opts"] = grpcOpts

	case "xhttp", "splithttp":
		proxy["network"] = "xhttp"
		splithttpOpts := make(map[string]any)
		if path := query.Get("path"); path != "" {
			splithttpOpts["path"] = path
		}
		if host := query.Get("host"); host != "" {
			splithttpOpts["host"] = host
		}
		if mode := query.Get("mode"); mode != "" {
			splithttpOpts["mode"] = mode
		}
		if extra := query.Get("extra"); extra != "" {
			var extraMap map[string]any
			if err := json.Unmarshal([]byte(extra), &extraMap); err == nil {
				parseSplitHTTPExtra(extraMap, splithttpOpts)
			}
		}
		proxy["splithttp-opts"] = splithttpOpts
	}
	return nil
}

// parseRangeConfig converts an xray-core extra JSON value to a mihomo RangeConfig map.
// The value may be a number (e.g. 1000000), a "min-max" string (e.g. "16-32"),
// or a plain number string (e.g. "30").
func parseRangeConfig(v any) map[string]any {
	switch val := v.(type) {
	case float64:
		n := int32(val)
		return map[string]any{"from": n, "to": n}
	case string:
		if parts := strings.SplitN(val, "-", 2); len(parts) == 2 {
			from, err1 := strconv.ParseInt(parts[0], 10, 32)
			to, err2 := strconv.ParseInt(parts[1], 10, 32)
			if err1 == nil && err2 == nil {
				return map[string]any{"from": int32(from), "to": int32(to)}
			}
		}
		if n, err := strconv.ParseInt(val, 10, 32); err == nil {
			return map[string]any{"from": int32(n), "to": int32(n)}
		}
	}
	return nil
}

// parseSplitHTTPExtra maps xray-core camelCase extra fields to mihomo splithttp-opts fields.
func parseSplitHTTPExtra(extra map[string]any, opts map[string]any) {
	if v, ok := extra["noGRPCHeader"].(bool); ok && v {
		opts["no-grpc-header"] = true
	}
	if v, ok := extra["xPaddingBytes"]; ok {
		if rc := parseRangeConfig(v); rc != nil {
			opts["x-padding-bytes"] = rc
		}
	}
	if v, ok := extra["scMaxEachPostBytes"]; ok {
		if rc := parseRangeConfig(v); rc != nil {
			opts["max-each-post-bytes"] = rc
		}
	}
	if v, ok := extra["scMinPostsIntervalMs"]; ok {
		if rc := parseRangeConfig(v); rc != nil {
			opts["min-posts-interval"] = rc
		}
	}
	if v, ok := extra["scStreamUpServerSecs"]; ok {
		if rc := parseRangeConfig(v); rc != nil {
			opts["stream-up-server-secs"] = rc
		}
	}
	if xmuxAny, ok := extra["xmux"].(map[string]any); ok {
		xmuxOpts := make(map[string]any)
		if v, ok := xmuxAny["maxConcurrency"]; ok {
			if rc := parseRangeConfig(v); rc != nil {
				xmuxOpts["max-concurrency"] = rc
			}
		}
		if v, ok := xmuxAny["maxConnections"]; ok {
			if rc := parseRangeConfig(v); rc != nil {
				xmuxOpts["max-connections"] = rc
			}
		}
		if v, ok := xmuxAny["cMaxReuseTimes"]; ok {
			if rc := parseRangeConfig(v); rc != nil {
				xmuxOpts["c-max-reuse-times"] = rc
			}
		}
		if v, ok := xmuxAny["hMaxRequestTimes"]; ok {
			if rc := parseRangeConfig(v); rc != nil {
				xmuxOpts["h-max-request-times"] = rc
			}
		}
		if v, ok := xmuxAny["hMaxReusableSecs"]; ok {
			if rc := parseRangeConfig(v); rc != nil {
				xmuxOpts["h-max-reusable-secs"] = rc
			}
		}
		if v, ok := xmuxAny["hKeepAlivePeriod"].(float64); ok && v != 0 {
			xmuxOpts["h-keep-alive-period"] = int64(v)
		}
		if len(xmuxOpts) > 0 {
			opts["xmux"] = xmuxOpts
		}
	}
}
