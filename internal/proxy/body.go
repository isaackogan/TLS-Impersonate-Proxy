package proxy

import (
	"io"
	"sync"
	"sync/atomic"
)

type countingBody struct {
	io.ReadCloser
	n *atomic.Int64
}

func (b *countingBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	b.n.Add(int64(n))
	return n, err
}

type closeHook struct {
	io.ReadCloser
	once sync.Once
	fn   func()
}

func (b *closeHook) Close() error {
	err := b.ReadCloser.Close()
	b.once.Do(b.fn)
	return err
}

type readWriteBody struct {
	io.ReadCloser
	io.Writer
}

func countReads(body io.ReadCloser, n *atomic.Int64) io.ReadCloser {
	return preserveWriter(body, &countingBody{ReadCloser: body, n: n})
}

func onClose(body io.ReadCloser, fn func()) io.ReadCloser {
	return preserveWriter(body, &closeHook{ReadCloser: body, fn: fn})
}

func preserveWriter(original, wrapped io.ReadCloser) io.ReadCloser {
	if w, ok := original.(io.Writer); ok {
		return &readWriteBody{ReadCloser: wrapped, Writer: w}
	}
	return wrapped
}
