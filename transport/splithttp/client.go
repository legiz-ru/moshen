package splithttp

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"sync"

	"github.com/metacubex/http"
	"github.com/metacubex/http/httptrace"
)

type DialerClient interface {
	IsClosed() bool
	OpenStream(context.Context, string, string, io.Reader, bool) (io.ReadCloser, func() error, net.Addr, net.Addr, error)
	PostPacket(context.Context, string, string, string, []byte) error
}

type DefaultDialerClient struct {
	transportConfig *Config
	client          *http.Client
	closed          bool
}

func (c *DefaultDialerClient) IsClosed() bool { return c.closed }

func (c *DefaultDialerClient) applyXrayPadding(req *http.Request, urlStr string) {
	length := int(c.transportConfig.GetNormalizedXPaddingBytes().rand())
	config := XPaddingConfig{Length: length}
	if c.transportConfig.XPaddingObfsMode {
		config.Placement = XPaddingPlacement{
			Placement: c.transportConfig.XPaddingPlacement,
			Key:       c.transportConfig.XPaddingKey,
			Header:    c.transportConfig.XPaddingHeader,
			RawURL:    urlStr,
		}
		config.Method = PaddingMethod(c.transportConfig.XPaddingMethod)
	} else {
		config.Placement = XPaddingPlacement{
			Placement: PlacementQueryInHeader,
			Key:       "x_padding",
			Header:    "Referer",
			RawURL:    urlStr,
		}
	}
	c.transportConfig.ApplyXPaddingToRequest(req, config)
}

func (c *DefaultDialerClient) OpenStream(ctx context.Context, url string, sessionId string, body io.Reader, uploadOnly bool) (io.ReadCloser, func() error, net.Addr, net.Addr, error) {
	gotConn := make(chan struct{})
	var gotConnOnce sync.Once
	var remoteAddr, localAddr net.Addr

	reqCtx := context.WithoutCancel(ctx)
	reqCtx = httptrace.WithClientTrace(reqCtx, &httptrace.ClientTrace{
		GotConn: func(connInfo httptrace.GotConnInfo) {
			remoteAddr = connInfo.Conn.RemoteAddr()
			localAddr = connInfo.Conn.LocalAddr()
			gotConnOnce.Do(func() { close(gotConn) })
		},
	})

	method := "GET"
	if body != nil {
		method = c.transportConfig.GetNormalizedUplinkHTTPMethod()
	}

	req, _ := http.NewRequestWithContext(reqCtx, method, url, body)
	req.Header = c.transportConfig.GetRequestHeader()

	c.applyXrayPadding(req, url)
	c.transportConfig.ApplyMetaToRequest(req, sessionId, "")

	if method == c.transportConfig.GetNormalizedUplinkHTTPMethod() && !c.transportConfig.NoGRPCHeader {
		req.Header.Set("Content-Type", "application/grpc")
	}

	pr, pw := io.Pipe()
	errCh := make(chan error, 1)

	go func() {
		resp, err := c.client.Do(req)
		if err != nil {
			if !uploadOnly {
				c.closed = true
			}
			pw.CloseWithError(err)
			errCh <- err
			gotConnOnce.Do(func() { close(gotConn) })
			return
		}

		if resp.StatusCode != 200 {
			resp.Body.Close()
			err := fmt.Errorf("unexpected status %d", resp.StatusCode)
			pw.CloseWithError(err)
			errCh <- err
			return
		}

		errCh <- nil
		if uploadOnly {
			io.Copy(io.Discard, resp.Body)
		} else {
			io.Copy(pw, resp.Body)
		}
		resp.Body.Close()
		pw.Close()
	}()

	waitHandshake := func() error { return <-errCh }
	<-gotConn
	return pr, waitHandshake, remoteAddr, localAddr, nil
}

func (c *DefaultDialerClient) PostPacket(ctx context.Context, url string, sessionId string, seqStr string, payload []byte) error {
	var body io.Reader
	dataPlacement := c.transportConfig.GetNormalizedUplinkDataPlacement()
	var encodedData string

	if dataPlacement != PlacementBody {
		encodedData = base64.RawURLEncoding.EncodeToString(payload)
		body = nil
	} else {
		body = bytes.NewReader(payload)
	}

	req, err := http.NewRequestWithContext(context.WithoutCancel(ctx), c.transportConfig.GetNormalizedUplinkHTTPMethod(), url, body)
	if err != nil {
		return err
	}
	req.Header = c.transportConfig.GetRequestHeader()

	if !c.transportConfig.NoGRPCHeader {
		req.Header.Set("Content-Type", "application/grpc")
	}

	if dataPlacement != PlacementBody {
		key := c.transportConfig.UplinkDataKey
		cSize := int(c.transportConfig.UplinkChunkSize)
		if cSize == 0 {
			cSize = len(encodedData)
		}

		switch dataPlacement {
		case PlacementHeader:
			for i := 0; i < len(encodedData); i += cSize {
				end := i + cSize
				if end > len(encodedData) {
					end = len(encodedData)
				}
				req.Header.Set(fmt.Sprintf("%s-%d", key, i/cSize), encodedData[i:end])
			}
			req.Header.Set(key+"-Length", fmt.Sprintf("%d", len(encodedData)))
			req.Header.Set(key+"-Upstream", "1")
		case PlacementCookie:
			for i := 0; i < len(encodedData); i += cSize {
				end := i + cSize
				if end > len(encodedData) {
					end = len(encodedData)
				}
				req.AddCookie(&http.Cookie{Name: fmt.Sprintf("%s_%d", key, i/cSize), Value: encodedData[i:end]})
			}
			req.AddCookie(&http.Cookie{Name: key + "_upstream", Value: "1"})
		}
	}

	c.applyXrayPadding(req, url)
	c.transportConfig.ApplyMetaToRequest(req, sessionId, seqStr)

	resp, err := c.client.Do(req)
	if err != nil {
		c.closed = true
		return err
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	if resp.StatusCode != 200 {
		return fmt.Errorf("bad status code: %s", resp.Status)
	}
	return nil
}
