package session

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nadoo/glider/pkg/log"
)

const protocolVersion = "2"
const clientName = "anytls/0.0.11"
const synackTimeout = 3 * time.Second

// Session multiplexes streams over a single connection.
type Session struct {
	conn     net.Conn
	connLock sync.Mutex

	streams    map[uint32]*Stream
	streamID   atomic.Uint32
	streamLock sync.RWMutex

	dieOnce sync.Once
	die     chan struct{}
	DieHook func()

	// pool fields
	Seq       uint64
	IdleSince time.Time
	InIdle    atomic.Bool // true while session is in the idle pool

	peerVersion atomic.Uint32

	// buffering: buffer initial frames until first stream opens.
	// Protected by connLock (read in writeConn, written in flushBuffering).
	buffering bool
	buffer    []byte
}

// NewClientSession creates a new client-side session.
func NewClientSession(conn net.Conn) *Session {
	s := &Session{
		conn:      conn,
		buffering: true,
		die:       make(chan struct{}),
		streams:   make(map[uint32]*Stream),
	}
	return s
}

// Run starts the session. For clients, it sends settings then starts the recv loop.
func (s *Session) Run() {
	settings := fmt.Sprintf("v=%s\nclient=%s\n", protocolVersion, clientName)
	f := newFrame(cmdSettings, 0)
	f.data = []byte(settings)
	s.writeControlFrame(f)

	go s.recvLoop()
}

// IsClosed returns true if the session is closed.
func (s *Session) IsClosed() bool {
	select {
	case <-s.die:
		return true
	default:
		return false
	}
}

// Close closes the session and all its streams.
func (s *Session) Close() error {
	var once bool
	s.dieOnce.Do(func() {
		close(s.die)
		once = true
	})
	if once {
		if s.DieHook != nil {
			s.DieHook()
			s.DieHook = nil
		}
		s.streamLock.Lock()
		for _, stream := range s.streams {
			stream.forceClose()
		}
		s.streams = make(map[uint32]*Stream)
		s.streamLock.Unlock()
		return s.conn.Close()
	}
	return io.ErrClosedPipe
}

// OpenStream opens a new stream on the session.
func (s *Session) OpenStream() (*Stream, error) {
	if s.IsClosed() {
		return nil, io.ErrClosedPipe
	}

	sid := s.streamID.Add(1)
	stream := newStream(sid, s)

	if _, err := s.writeControlFrame(newFrame(cmdSYN, sid)); err != nil {
		stream.closePipe()
		return nil, err
	}

	// Disable buffering under connLock so writeConn sees a consistent value.
	s.flushBuffering()

	// Register the stream.
	s.streamLock.Lock()
	select {
	case <-s.die:
		s.streamLock.Unlock()
		stream.closePipe()
		return nil, io.ErrClosedPipe
	default:
		s.streams[sid] = stream
	}
	s.streamLock.Unlock()

	// For protocol v2 (not the first stream), wait for SYNACK.
	// First stream (sid==1): peerVersion is still 0 because cmdServerSettings
	// hasn't arrived yet — we skip the wait, matching the reference impl.
	if sid >= 2 && s.peerVersion.Load() >= 2 {
		select {
		case err := <-stream.synDone:
			if err != nil {
				s.streamLock.Lock()
				delete(s.streams, sid)
				s.streamLock.Unlock()
				stream.forceClose()
				return nil, err
			}
		case <-time.After(synackTimeout):
			s.streamLock.Lock()
			delete(s.streams, sid)
			s.streamLock.Unlock()
			stream.forceClose()
			return nil, errors.New("[anytls] stream open timeout: no SYNACK received")
		case <-s.die:
			// Session died while waiting; stream already force-closed by Session.Close.
			return nil, io.ErrClosedPipe
		}
	}

	return stream, nil
}

// flushBuffering disables the buffering flag under connLock.
// The next writeConn call will flush any accumulated buffer.
func (s *Session) flushBuffering() {
	s.connLock.Lock()
	s.buffering = false
	s.connLock.Unlock()
}

func (s *Session) recvLoop() {
	defer s.Close()

	var hdr rawHeader
	for {
		if s.IsClosed() {
			return
		}

		if _, err := io.ReadFull(s.conn, hdr[:]); err != nil {
			return
		}

		sid := hdr.StreamID()
		dataLen := int(hdr.Length())

		switch hdr.Cmd() {
		case cmdPSH:
			if dataLen > 0 {
				data := make([]byte, dataLen)
				if _, err := io.ReadFull(s.conn, data); err != nil {
					return
				}
				s.streamLock.RLock()
				stream, ok := s.streams[sid]
				s.streamLock.RUnlock()
				if !ok {
					break
				}
				if !stream.enqueue(data) {
					// Backpressure: reader not consuming, queue full.
					// Close stream with io.EOF (not ErrClosedPipe) so the
					// forwarder health counter is not penalised.
					s.streamLock.Lock()
					delete(s.streams, sid)
					s.streamLock.Unlock()
					stream.overflowClose()
					s.writeControlFrame(newFrame(cmdFIN, sid))
				}
			}

		case cmdFIN:
			s.streamLock.Lock()
			stream, ok := s.streams[sid]
			delete(s.streams, sid)
			s.streamLock.Unlock()
			if ok {
				stream.closeLocally()
			}

		case cmdSYNACK:
			// Always consume body bytes to keep framing in sync.
			var data []byte
			if dataLen > 0 {
				data = make([]byte, dataLen)
				if _, err := io.ReadFull(s.conn, data); err != nil {
					return
				}
			}
			s.streamLock.RLock()
			stream, ok := s.streams[sid]
			s.streamLock.RUnlock()
			if !ok {
				break // stream already gone (e.g. timed out)
			}
			if len(data) > 0 {
				// Non-empty SYNACK = handshake failure.
				synErr := fmt.Errorf("remote: %s", string(data))
				select {
				case stream.synDone <- synErr:
					// OpenStream is waiting — it will clean up.
				default:
					// Nobody waiting (first stream / v1 peer).
					stream.closed.Store(true)
					stream.pw.CloseWithError(synErr)
				}
			} else {
				// Empty SYNACK = success.
				select {
				case stream.synDone <- nil:
				default:
				}
			}

		case cmdWaste:
			if dataLen > 0 {
				if _, err := io.ReadFull(s.conn, make([]byte, dataLen)); err != nil {
					return
				}
			}

		case cmdAlert:
			if dataLen > 0 {
				data := make([]byte, dataLen)
				if _, err := io.ReadFull(s.conn, data); err != nil {
					return
				}
				log.F("[anytls] alert from server: %s", string(data))
				return
			}

		case cmdServerSettings:
			if dataLen > 0 {
				data := make([]byte, dataLen)
				if _, err := io.ReadFull(s.conn, data); err != nil {
					return
				}
				m := parseStringMap(string(data))
				if v, err := strconv.Atoi(m["v"]); err == nil {
					s.peerVersion.Store(uint32(v))
				}
			}

		case cmdUpdatePaddingScheme:
			if dataLen > 0 {
				if _, err := io.ReadFull(s.conn, make([]byte, dataLen)); err != nil {
					return
				}
			}

		case cmdHeartRequest:
			s.writeControlFrame(newFrame(cmdHeartResponse, sid))

		case cmdHeartResponse:
			// no-op

		default:
			if dataLen > 0 {
				if _, err := io.ReadFull(s.conn, make([]byte, dataLen)); err != nil {
					return
				}
			}
		}
	}
}

func (s *Session) streamClosed(sid uint32) error {
	if s.IsClosed() {
		return io.ErrClosedPipe
	}
	_, err := s.writeControlFrame(newFrame(cmdFIN, sid))
	s.streamLock.Lock()
	delete(s.streams, sid)
	s.streamLock.Unlock()
	return err
}

func (s *Session) writeDataFrame(sid uint32, data []byte) (int, error) {
	dataLen := len(data)
	buf := make([]byte, headerSize+dataLen)
	buf[0] = cmdPSH
	binary.BigEndian.PutUint32(buf[1:5], sid)
	binary.BigEndian.PutUint16(buf[5:7], uint16(dataLen))
	copy(buf[headerSize:], data)

	_, err := s.writeConn(buf)
	if err != nil {
		return 0, err
	}
	return dataLen, nil
}

func (s *Session) writeControlFrame(f frame) (int, error) {
	dataLen := len(f.data)
	buf := make([]byte, headerSize+dataLen)
	buf[0] = f.cmd
	binary.BigEndian.PutUint32(buf[1:5], f.sid)
	binary.BigEndian.PutUint16(buf[5:7], uint16(dataLen))
	copy(buf[headerSize:], f.data)

	s.conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	_, err := s.writeConn(buf)
	if err != nil {
		s.Close()
		return 0, err
	}
	s.conn.SetWriteDeadline(time.Time{})
	return dataLen, nil
}

// writeConn writes to the underlying connection.  While buffering is true,
// bytes are accumulated in memory; once buffering is set to false (by
// flushBuffering under connLock), the accumulated buffer is flushed with
// the first real write.
func (s *Session) writeConn(b []byte) (int, error) {
	s.connLock.Lock()
	defer s.connLock.Unlock()

	if s.buffering {
		s.buffer = append(s.buffer, b...)
		return len(b), nil
	}

	if len(s.buffer) > 0 {
		b = append(s.buffer, b...)
		s.buffer = nil
	}

	return s.conn.Write(b)
}

// NumStreams returns the number of active streams.
func (s *Session) NumStreams() int {
	s.streamLock.RLock()
	defer s.streamLock.RUnlock()
	return len(s.streams)
}

// parseStringMap parses newline-separated key=value pairs.
func parseStringMap(s string) map[string]string {
	m := make(map[string]string)
	for _, line := range strings.Split(s, "\n") {
		if k, v, ok := strings.Cut(line, "="); ok {
			m[strings.TrimSpace(k)] = strings.TrimSpace(v)
		}
	}
	return m
}
