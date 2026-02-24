package splithttp

import (
	"errors"
	"io"
	"sync"

	"github.com/metacubex/mihomo/common/buf"
)

type Packet struct {
	Reader io.ReadCloser
	Buffer *buf.Buffer
	Seq    uint64
}

type uploadQueue struct {
	mu         sync.Mutex
	cond       *sync.Cond
	heap       uploadHeap
	nextSeq    uint64
	closed     bool
	reader     io.ReadCloser
	maxPackets int
}

func NewUploadQueue(maxPackets int) *uploadQueue {
	// ✨ 现代化大幅增强：针对现代硬件大内存进行优化
	// 将保底深度从 128 提升到 512
	// 理由：在万兆抖动网络下，更大的队列可以极大地减少因乱序导致的连接断开
	if maxPackets < 512 {
		maxPackets = 512
	}
	q := &uploadQueue{maxPackets: maxPackets}
	q.cond = sync.NewCond(&q.mu)
	return q
}

func (q *uploadQueue) Push(p Packet) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.closed {
		if p.Buffer != nil {
			p.Buffer.Release()
		}
		return io.ErrClosedPipe
	}
	if p.Reader != nil {
		if q.reader != nil {
			return errors.New("reader already exists")
		}
		q.reader = p.Reader
		q.cond.Signal()
		return nil
	}
	if len(q.heap) > q.maxPackets {
		if p.Buffer != nil {
			p.Buffer.Release()
		}
		return errors.New("reassembly queue overflow")
	}
	heapPush(&q.heap, p)
	q.cond.Signal()
	return nil
}

func (q *uploadQueue) Read(b []byte) (int, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	for {
		if q.reader != nil {
			r := q.reader
			q.mu.Unlock()
			n, err := r.Read(b)
			q.mu.Lock()
			return n, err
		}
		if len(q.heap) > 0 && q.heap[0].Seq == q.nextSeq {
			packet := heapPop(&q.heap)
			n := copy(b, packet.Buffer.Bytes())
			packet.Buffer.Advance(n)
			if packet.Buffer.IsEmpty() {
				packet.Buffer.Release()
				q.nextSeq++
			} else {
				heapPush(&q.heap, packet)
			}
			return n, nil
		}
		if q.closed {
			return 0, io.EOF
		}
		q.cond.Wait()
	}
}

func (q *uploadQueue) Close() error {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.closed = true
	q.cond.Broadcast()
	for len(q.heap) > 0 {
		p := heapPop(&q.heap)
		if p.Buffer != nil {
			p.Buffer.Release()
		}
	}
	if q.reader != nil {
		return q.reader.Close()
	}
	return nil
}

type uploadHeap []Packet

func (h uploadHeap) Len() int           { return len(h) }
func (h uploadHeap) Less(i, j int) bool { return h[i].Seq < h[j].Seq }
func (h uploadHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }
func heapPush(h *uploadHeap, x Packet)  { *h = append(*h, x); up(*h, len(*h)-1) }
func heapPop(h *uploadHeap) Packet {
	n := len(*h) - 1
	(*h)[0], (*h)[n] = (*h)[n], (*h)[0]
	down(*h, 0, n)
	x := (*h)[n]
	*h = (*h)[0:n]
	return x
}
func up(h uploadHeap, j int) {
	for {
		i := (j - 1) / 2
		if i == j || !h.Less(j, i) {
			break
		}
		h.Swap(i, j)
		j = i
	}
}
func down(h uploadHeap, i0, n int) bool {
	i := i0
	for {
		j1 := 2*i + 1
		if j1 >= n || j1 < 0 {
			break
		}
		j := j1
		if j2 := j1 + 1; j2 < n && h.Less(j2, j1) {
			j = j2
		}
		if !h.Less(j, i) {
			break
		}
		h.Swap(i, j)
		i = j
	}
	return i > i0
}
