package convert

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// https://v2.hysteria.network/zh/docs/developers/URI-Scheme/
func TestConvertsV2Ray_normal(t *testing.T) {
	hy2test := "hysteria2://letmein@example.com:8443/?insecure=1&obfs=salamander&obfs-password=gawrgura&pinSHA256=deadbeef&sni=real.example.com&up=114&down=514&alpn=h3,h4#hy2test"

	expected := []map[string]interface{}{
		{
			"name":             "hy2test",
			"type":             "hysteria2",
			"server":           "example.com",
			"port":             "8443",
			"sni":              "real.example.com",
			"obfs":             "salamander",
			"obfs-password":    "gawrgura",
			"alpn":             []string{"h3", "h4"},
			"password":         "letmein",
			"up":               "114",
			"down":             "514",
			"skip-cert-verify": true,
			"fingerprint":      "deadbeef",
		},
	}

	proxies, err := ConvertsV2Ray([]byte(hy2test))

	assert.Nil(t, err)
	assert.Equal(t, expected, proxies)
}

func TestConvertsV2Ray_vless_xhttp(t *testing.T) {
	link := "vless://68b36cfd-6c53-4863-8879-25a4288c4d90@73.240283.xyz:443?security=tls&type=xhttp&headerType=&path=%2Fxhttp_re9ty7ri6%2F&host=73.240283.xyz&flow=&mode=packet-up&extra=%7B%22xmux%22%3A%7B%22cMaxReuseTimes%22%3A0%2C%22maxConcurrency%22%3A%2216-32%22%2C%22maxConnections%22%3A0%2C%22hKeepAlivePeriod%22%3A0%2C%22hMaxRequestTimes%22%3A%22600-900%22%2C%22hMaxReusableSecs%22%3A%221800-3000%22%7D%2C%22headers%22%3A%7B%7D%2C%22noGRPCHeader%22%3Afalse%2C%22xPaddingBytes%22%3A%22100-1000%22%2C%22scMaxEachPostBytes%22%3A1000000%2C%22scMinPostsIntervalMs%22%3A30%2C%22scStreamUpServerSecs%22%3A%2220-80%22%7D&sni=73.240283.xyz&fp=chrome&alpn=h2%2Chttp%2F1.1#%F0%9F%87%B8%F0%9F%87%AA%20Sweden%20XHTTP"

	proxies, err := ConvertsV2Ray([]byte(link))
	assert.Nil(t, err)
	assert.Len(t, proxies, 1)

	p := proxies[0]
	assert.Equal(t, "vless", p["type"])
	assert.Equal(t, "73.240283.xyz", p["server"])
	assert.Equal(t, "443", p["port"])
	assert.Equal(t, "68b36cfd-6c53-4863-8879-25a4288c4d90", p["uuid"])
	assert.Equal(t, "xhttp", p["network"])
	assert.Equal(t, true, p["tls"])
	assert.Equal(t, "chrome", p["client-fingerprint"])
	assert.Equal(t, []string{"h2", "http/1.1"}, p["alpn"])
	assert.Equal(t, "73.240283.xyz", p["servername"])

	opts, ok := p["splithttp-opts"]
	assert.True(t, ok, "splithttp-opts must be present")
	optsMap := opts.(map[string]any)
	assert.Equal(t, "/xhttp_re9ty7ri6/", optsMap["path"])
	assert.Equal(t, "73.240283.xyz", optsMap["host"])
	assert.Equal(t, "packet-up", optsMap["mode"])
	assert.Equal(t, map[string]any{"from": int32(100), "to": int32(1000)}, optsMap["x-padding-bytes"])
	assert.Equal(t, map[string]any{"from": int32(1000000), "to": int32(1000000)}, optsMap["max-each-post-bytes"])
	assert.Equal(t, map[string]any{"from": int32(30), "to": int32(30)}, optsMap["min-posts-interval"])
	assert.Equal(t, map[string]any{"from": int32(20), "to": int32(80)}, optsMap["stream-up-server-secs"])

	xmux, ok := optsMap["xmux"]
	assert.True(t, ok, "xmux must be present")
	xmuxMap := xmux.(map[string]any)
	assert.Equal(t, map[string]any{"from": int32(16), "to": int32(32)}, xmuxMap["max-concurrency"])
	assert.Equal(t, map[string]any{"from": int32(600), "to": int32(900)}, xmuxMap["h-max-request-times"])
	assert.Equal(t, map[string]any{"from": int32(1800), "to": int32(3000)}, xmuxMap["h-max-reusable-secs"])
}
