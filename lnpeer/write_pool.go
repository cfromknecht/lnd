package lnpeer

import (
	"bytes"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/lightningnetwork/lnd/lnwire"
)

var ErrWritePoolExiting = errors.New("write pool shutting down")

type writeRequest struct {
	conn         net.Conn
	msg          lnwire.Message
	writeTimeout time.Duration
	byteCount    *uint64
	errChan      chan error

	// TODO(conner): add version when we move to something other than 0
}

type WritePool struct {
	stopped uint32 // to be used atomically

	pool *WriteBufferPool

	work      chan *writeRequest
	workerSem chan struct{}

	wg   sync.WaitGroup
	quit chan struct{}
}

func NewWritePool(numWorkers int, bufferPool *WriteBufferPool) *WritePool {
	return &WritePool{
		pool:      bufferPool,
		work:      make(chan *writeRequest),
		workerSem: make(chan struct{}, numWorkers),
	}
}

func (w *WritePool) Stop() {
	if !atomic.CompareAndSwapUint32(&w.stopped, 0, 1) {
		return
	}

	close(w.quit)
	w.wg.Wait()
}

func (w *WritePool) Write(conn net.Conn, msg lnwire.Message,
	timeout time.Duration, byteCount *uint64) error {

	req := &writeRequest{
		conn:         conn,
		msg:          msg,
		writeTimeout: timeout,
		byteCount:    byteCount,
		errChan:      make(chan error),
	}

	select {
	case w.workerSem <- struct{}{}:
		w.wg.Add(1)
		go w.spawnWorker(req)
	case w.work <- req:
	case <-w.quit:
		return ErrWritePoolExiting
	}

	return <-req.errChan
}

func (w *WritePool) spawnWorker(req *writeRequest) {
	defer w.wg.Done()
	defer func() { <-w.workerSem }()

	writeBuf := w.pool.Take()
	defer w.pool.Return(writeBuf)

	buf := bytes.NewBuffer(writeBuf[:])

	sendMessage := func(req *writeRequest) {
		n, err := lnwire.WriteMessage(buf, req.msg, 0)
		if err != nil {
			req.errChan <- err
			return
		}

		writeDeadline := time.Now().Add(req.writeTimeout)
		err = req.conn.SetWriteDeadline(writeDeadline)
		if err != nil {
			req.errChan <- err
			return
		}

		atomic.AddUint64(req.byteCount, uint64(n))

		_, err = req.conn.Write(buf.Bytes())
		req.errChan <- err
	}

	sendMessage(req)
	for {
		buf.Reset()

		select {
		case req := <-w.work:
			sendMessage(req)
			continue
		case <-w.quit:
			return
		default:
		}

		select {
		case req := <-w.work:
			sendMessage(req)
		case <-time.After(5 * time.Second):
			return
		case <-w.quit:
			return
		}
	}
}
