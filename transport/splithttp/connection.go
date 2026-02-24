package splithttp

import (
	"io"
	"net"
	"os"
	"sync"
	"time"

	"github.com/metacubex/mihomo/common/buf"
	"github.com/metacubex/sing/common/bufio"
	N "github.com/metacubex/sing/common/network"
)

type splitConn struct {
	writer     io.WriteCloser
	reader     io.ReadCloser
	remoteAddr net.Addr
	localAddr  net.Addr
	onClose    func()

	// ✨ 缓存包装后的接口，避免高频调用产生 GC 压力
	exReader N.ExtendedReader
	exWriter N.ExtendedWriter

	waitHandshake func() error
	handshakeOnce sync.Once
	handshakeErr  error

	closeOnce  sync.Once
	readMu     sync.Mutex
	writeMu    sync.Mutex
	readTimer  *time.Timer
	writeTimer *time.Timer
}

// ensureEx 确保握手完成并初始化缓存的扩展接口
func (c *splitConn) ensureEx() error {
	c.handshakeOnce.Do(func() {
		if c.waitHandshake != nil {
			c.handshakeErr = c.waitHandshake()
		}
		if c.handshakeErr == nil {
			// 在握手成功后，只包装一次
			if c.reader != nil {
				c.exReader = bufio.NewExtendedReader(c.reader)
			}
			if c.writer != nil {
				c.exWriter = bufio.NewExtendedWriter(c.writer)
			}
		}
	})
	return c.handshakeErr
}

func (c *splitConn) Write(b []byte) (int, error) {
	if err := c.ensureEx(); err != nil {
		return 0, err
	}
	return c.writer.Write(b)
}

// WriteBuffer 实现 N.ExtendedConn 接口
func (c *splitConn) WriteBuffer(buffer *buf.Buffer) error {
	if err := c.ensureEx(); err != nil {
		return err
	}
	if c.exWriter == nil {
		return io.ErrClosedPipe
	}
	// ✨ 使用缓存的包装器执行写入
	return c.exWriter.WriteBuffer(buffer)
}

func (c *splitConn) Read(b []byte) (int, error) {
	if err := c.ensureEx(); err != nil {
		return 0, err
	}
	if c.reader == nil {
		return 0, io.EOF
	}
	return c.reader.Read(b)
}

// ReadBuffer 实现 N.ExtendedConn 接口，适配主线 deadline.go
func (c *splitConn) ReadBuffer(buffer *buf.Buffer) error {
	if err := c.ensureEx(); err != nil {
		return err
	}
	if c.exReader == nil {
		return io.EOF
	}
	// ✨ 使用缓存的包装器执行高效读取
	return c.exReader.ReadBuffer(buffer)
}

// Upstream 适配
func (c *splitConn) Upstream() any {
	// ✨ 保持返回 nil。
	// 强制屏蔽主线 deadline.go 的异步预读协程，
	// 这是解决 curl 报 unexpected eof 的核心逻辑。
	return nil
}

func (c *splitConn) Close() error {
	var err1, err2 error
	c.closeOnce.Do(func() {
		if c.onClose != nil {
			c.onClose()
		}
		c.stopTimer(true)
		c.stopTimer(false)
		err1 = c.writer.Close()
		if c.reader != nil {
			err2 = c.reader.Close()
		}
	})
	if err1 != nil {
		return err1
	}
	return err2
}

func (c *splitConn) stopTimer(isRead bool) {
	if isRead {
		c.readMu.Lock()
		if c.readTimer != nil {
			c.readTimer.Stop()
			c.readTimer = nil
		}
		c.readMu.Unlock()
	} else {
		c.writeMu.Lock()
		if c.writeTimer != nil {
			c.writeTimer.Stop()
			c.writeTimer = nil
		}
		c.writeMu.Unlock()
	}
}

func (c *splitConn) LocalAddr() net.Addr  { return c.localAddr }
func (c *splitConn) RemoteAddr() net.Addr { return c.remoteAddr }

func (c *splitConn) SetDeadline(t time.Time) error {
	_ = c.SetReadDeadline(t)
	_ = c.SetWriteDeadline(t)
	return nil
}

func (c *splitConn) SetReadDeadline(t time.Time) error {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	if c.readTimer != nil {
		c.readTimer.Stop()
	}
	if t.IsZero() {
		c.readTimer = nil
		return nil
	}
	c.readTimer = time.AfterFunc(time.Until(t), func() {
		if pr, ok := c.reader.(interface{ CloseWithError(error) error }); ok {
			_ = pr.CloseWithError(os.ErrDeadlineExceeded)
		}
	})
	return nil
}

func (c *splitConn) SetWriteDeadline(t time.Time) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if c.writeTimer != nil {
		c.writeTimer.Stop()
	}
	if t.IsZero() {
		c.writeTimer = nil
		return nil
	}
	c.writeTimer = time.AfterFunc(time.Until(t), func() {
		if pw, ok := c.writer.(interface{ CloseWithError(error) error }); ok {
			_ = pw.CloseWithError(os.ErrDeadlineExceeded)
		}
	})
	return nil
}

// 确保完全实现了接口
var _ N.ExtendedConn = (*splitConn)(nil)
