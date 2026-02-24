package splithttp

import (
	"context"
	"math"
	"sync"
	"sync/atomic"
	"time"

	"github.com/metacubex/randv2"
)

type XmuxConn interface{ IsClosed() bool }

type XmuxClient struct {
	XmuxConn     XmuxConn
	OpenUsage    atomic.Int32
	leftUsage    int32
	LeftRequests atomic.Int32
	UnreusableAt time.Time
}

type XmuxManager struct {
	sync.Mutex
	xmuxConfig  XmuxConfig
	concurrency int32
	connections int32
	newConnFunc func() XmuxConn
	xmuxClients []*XmuxClient
}

func NewXmuxManager(xmuxConfig XmuxConfig, newConnFunc func() XmuxConn) *XmuxManager {
	return &XmuxManager{
		xmuxConfig:  xmuxConfig,
		concurrency: xmuxConfig.GetNormalizedMaxConcurrency().rand(),
		connections: xmuxConfig.GetNormalizedMaxConnections().rand(),
		newConnFunc: newConnFunc,
		xmuxClients: make([]*XmuxClient, 0),
	}
}

func (m *XmuxManager) newXmuxClient() *XmuxClient {
	xmuxClient := &XmuxClient{XmuxConn: m.newConnFunc(), leftUsage: -1}
	if x := m.xmuxConfig.GetNormalizedCMaxReuseTimes().rand(); x > 0 {
		xmuxClient.leftUsage = x - 1
	}
	xmuxClient.LeftRequests.Store(math.MaxInt32)
	if x := m.xmuxConfig.GetNormalizedHMaxRequestTimes().rand(); x > 0 {
		xmuxClient.LeftRequests.Store(x)
	}
	if x := m.xmuxConfig.GetNormalizedHMaxReusableSecs().rand(); x > 0 {
		xmuxClient.UnreusableAt = time.Now().Add(time.Duration(x) * time.Second)
	}
	m.xmuxClients = append(m.xmuxClients, xmuxClient)
	return xmuxClient
}

func (m *XmuxManager) GetXmuxClient(ctx context.Context) *XmuxClient {
	m.Lock()
	defer m.Unlock()
	for i := 0; i < len(m.xmuxClients); {
		xc := m.xmuxClients[i]
		if xc.XmuxConn.IsClosed() || xc.leftUsage == 0 || xc.LeftRequests.Load() <= 0 ||
			(xc.UnreusableAt != time.Time{} && time.Now().After(xc.UnreusableAt)) {
			m.xmuxClients = append(m.xmuxClients[:i], m.xmuxClients[i+1:]...)
		} else {
			i++
		}
	}
	if len(m.xmuxClients) == 0 {
		return m.newXmuxClient()
	}
	if m.connections > 0 && len(m.xmuxClients) < int(m.connections) {
		return m.newXmuxClient()
	}

	validClients := make([]*XmuxClient, 0)
	if m.concurrency > 0 {
		for _, xc := range m.xmuxClients {
			if xc.OpenUsage.Load() < m.concurrency {
				validClients = append(validClients, xc)
			}
		}
	} else {
		validClients = m.xmuxClients
	}

	if len(validClients) == 0 {
		return m.newXmuxClient()
	}
	idx := randv2.IntN(len(validClients))
	xc := validClients[idx]
	if xc.leftUsage > 0 {
		xc.leftUsage -= 1
	}
	return xc
}
