package session

import (
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

const (
	// dataQueueCap is the per-stream buffered channel capacity (frame count).
	dataQueueCap = 64

	// dataQueueMaxBytes is the per-stream byte limit for queued data.
	// Rejects enqueue when exceeded.  Typical proxy frames are ~1.5 KB so
	// effective usage is ~96 KB; worst-case (all 64 KB frames) ≈ 4 MB.
	dataQueueMaxBytes int64 = 4 << 20
)

// Stream implements net.Conn over a multiplexed session.
type Stream struct {
	id   uint32
	sess *Session

	pr *io.PipeReader
	pw *io.PipeWriter

	dataCh  chan []byte   // buffered; recvLoop → writeLoop (frame-count bound)
	done    chan struct{} // closed on force / overflow shutdown
	synDone chan error    // cap 1; SYNACK result (nil = success)

	closed      atomic.Bool
	queuedBytes atomic.Int64 // tracks total bytes buffered in dataCh
	dieOnce     sync.Once
	CloseFunc   func() error // overridable close hook (set by Client)

	// dataMu serialises close(dataCh) with the non-blocking send in enqueue,
	// preventing a send-on-closed-channel panic and the corresponding data
	// race that the race detector flags.
	dataMu sync.Mutex

	readTimerMu sync.Mutex
	readTimer   *time.Timer
}

func newStream(id uint32, sess *Session) *Stream {
	pr, pw := io.Pipe()
	s := &Stream{
		id:      id,
		sess:    sess,
		pr:      pr,
		pw:      pw,
		dataCh:  make(chan []byte, dataQueueCap),
		done:    make(chan struct{}),
		synDone: make(chan error, 1),
	}
	go s.writeLoop()
	return s
}

// writeLoop is the single goroutine that drains dataCh into pw, preserving
// frame order.  Exits on:
//   - dataCh closed (graceful): remaining buffered items are drained first,
//     then pw.Close → reader sees io.EOF.
//   - done closed (force / session death / overflow): exits immediately,
//     remaining queue is discarded.
func (s *Stream) writeLoop() {
	defer s.pw.Close()
	for {
		select {
		case data, ok := <-s.dataCh:
			if !ok {
				return
			}
			s.queuedBytes.Add(-int64(len(data)))
			if _, err := s.pw.Write(data); err != nil {
				return
			}
		case <-s.done:
			return
		}
	}
}

// enqueue is called by recvLoop (single goroutine — no concurrent callers).
// Returns false if either the channel is full (frame-count limit) or the
// byte budget is exceeded; the caller should close the stream.
//
// dataMu is held across the closed check and the channel send to prevent
// a race with close(dataCh) in the various close methods.  The send is
// non-blocking (select with default) so the mutex is never held long.
func (s *Stream) enqueue(data []byte) bool {
	n := int64(len(data))
	if s.queuedBytes.Load()+n > dataQueueMaxBytes {
		return false
	}
	s.dataMu.Lock()
	defer s.dataMu.Unlock()
	if s.closed.Load() {
		return false
	}
	select {
	case s.dataCh <- data:
		s.queuedBytes.Add(n)
		return true
	default:
		return false
	}
}

// closeDataCh marks the stream closed and closes dataCh under dataMu,
// preventing a race with the non-blocking send in enqueue.
func (s *Stream) closeDataCh() {
	s.dataMu.Lock()
	s.closed.Store(true)
	close(s.dataCh)
	s.dataMu.Unlock()
}

func (s *Stream) Read(b []byte) (int, error) {
	return s.pr.Read(b)
}

func (s *Stream) Write(b []byte) (int, error) {
	if s.closed.Load() {
		return 0, io.ErrClosedPipe
	}
	return s.sess.writeDataFrame(s.id, b)
}

func (s *Stream) Close() error {
	if s.CloseFunc != nil {
		return s.CloseFunc()
	}
	return s.CloseRemote()
}

// CloseRemote closes the stream and notifies the remote peer with cmdFIN.
func (s *Stream) CloseRemote() error {
	var once bool
	s.dieOnce.Do(func() {
		s.closeDataCh() // writeLoop drains remaining, then pw.Close → EOF
		once = true
	})
	// Unblock writeLoop if it is stuck in pw.Write (reader stopped reading).
	// pw.Close is idempotent and concurrent-safe; the reader sees io.EOF.
	s.pw.Close()
	if once {
		return s.sess.streamClosed(s.id)
	}
	return io.ErrClosedPipe
}

// closeLocally is a graceful close: the remote already sent cmdFIN.
// Remaining buffered data is drained to the reader before io.EOF.
func (s *Stream) closeLocally() {
	s.dieOnce.Do(func() {
		s.closeDataCh()
	})
}

// overflowClose is used when the stream's data queue is full (backpressure).
// It stops writeLoop immediately (discards queued data) but the reader
// receives io.EOF — NOT io.ErrClosedPipe — so the forwarder health
// counter is not penalised.
//
// Mechanism: close(done) makes writeLoop exit via select; defer pw.Close()
// in writeLoop signals io.EOF to the reader.  We call pw.Close() here as
// well to handle the case where writeLoop is blocked inside pw.Write
// (slow reader).  io.PipeWriter.Close is concurrency-safe and idempotent;
// the stored error is always io.EOF regardless of call count.
func (s *Stream) overflowClose() {
	s.dieOnce.Do(func() {
		close(s.done)
		s.closeDataCh()
	})
	s.pw.Close() // unblock stuck pw.Write; reader sees io.EOF
}

// forceClose is an immediate close used during session shutdown.
// It stops writeLoop and unblocks the reader.  The reader sees
// io.ErrClosedPipe, which is appropriate: session death IS a real error.
func (s *Stream) forceClose() {
	s.dieOnce.Do(func() {
		close(s.done)
		s.closeDataCh()
	})
	s.pr.Close() // unblock stuck pw.Write AND make Read return ErrClosedPipe
}

// closePipe cleans up a stream that was never fully registered (e.g.
// OpenStream raced with session close).
func (s *Stream) closePipe() {
	s.dieOnce.Do(func() {
		close(s.done)
		s.closeDataCh()
	})
}

func (s *Stream) LocalAddr() net.Addr {
	if ts, ok := s.sess.conn.(interface{ LocalAddr() net.Addr }); ok {
		return ts.LocalAddr()
	}
	return nil
}

func (s *Stream) RemoteAddr() net.Addr {
	if ts, ok := s.sess.conn.(interface{ RemoteAddr() net.Addr }); ok {
		return ts.RemoteAddr()
	}
	return nil
}

func (s *Stream) SetDeadline(t time.Time) error {
	s.SetWriteDeadline(t)
	return s.SetReadDeadline(t)
}

// SetReadDeadline implements net.Conn.  When the deadline expires, pw is
// closed with os.ErrDeadlineExceeded so that pr.Read returns a proper
// timeout error.  proxy.Relay explicitly checks errors.Is(err,
// os.ErrDeadlineExceeded) and treats it as normal cleanup, so this will
// not be recorded as a forwarder failure.
//
// Limitation: once the deadline fires the stream is permanently done;
// calling SetReadDeadline(time.Time{}) afterwards cannot undo it.
func (s *Stream) SetReadDeadline(t time.Time) error {
	s.readTimerMu.Lock()
	defer s.readTimerMu.Unlock()

	if s.readTimer != nil {
		s.readTimer.Stop()
		s.readTimer = nil
	}

	if t.IsZero() {
		return nil
	}

	d := time.Until(t)
	if d <= 0 {
		s.pw.CloseWithError(os.ErrDeadlineExceeded)
		return nil
	}

	s.readTimer = time.AfterFunc(d, func() {
		s.pw.CloseWithError(os.ErrDeadlineExceeded)
	})
	return nil
}

func (s *Stream) SetWriteDeadline(t time.Time) error { return nil }
