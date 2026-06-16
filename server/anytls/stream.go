package anytls

import (
	"io"
	"net"
	"sync"
	"time"
)

type Stream struct {
	id   uint32
	sess *Session

	mu            sync.Mutex
	pending       []byte
	readDeadline  time.Time
	writeDeadline time.Time

	readCh    chan []byte
	closed    chan struct{}
	closeOnce sync.Once
}

func newStream(id uint32, sess *Session) *Stream {
	return &Stream{
		id:     id,
		sess:   sess,
		readCh: make(chan []byte, 32),
		closed: make(chan struct{}),
	}
}

func (s *Stream) Read(b []byte) (int, error) {
	for {
		s.mu.Lock()
		if len(s.pending) > 0 {
			n := copy(b, s.pending)
			s.pending = s.pending[n:]
			s.mu.Unlock()
			return n, nil
		}
		deadline := s.readDeadline
		s.mu.Unlock()

		if deadlineExceeded(deadline) {
			return 0, osDeadlineExceeded()
		}

		var timer <-chan time.Time
		if !deadline.IsZero() {
			timer = time.After(time.Until(deadline))
		}

		select {
		case data := <-s.readCh:
			s.mu.Lock()
			s.pending = data
			s.mu.Unlock()
		case <-s.closed:
			return 0, io.EOF
		case <-timer:
			return 0, osDeadlineExceeded()
		}
	}
}

func (s *Stream) Write(b []byte) (int, error) {
	s.mu.Lock()
	deadline := s.writeDeadline
	s.mu.Unlock()
	if deadlineExceeded(deadline) {
		return 0, osDeadlineExceeded()
	}

	written := 0
	for written < len(b) {
		end := written + maxFrameData
		if end > len(b) {
			end = len(b)
		}
		if err := s.sess.writeFrame(frame{
			cmd:      cmdPSH,
			streamID: s.id,
			data:     b[written:end],
		}); err != nil {
			return written, err
		}
		written = end
	}
	return written, nil
}

func (s *Stream) Close() error {
	var shouldSendFIN bool
	s.closeOnce.Do(func() {
		shouldSendFIN = true
		close(s.closed)
	})
	if !shouldSendFIN {
		return nil
	}
	return s.sess.closeStream(s.id, true)
}

func (s *Stream) closeRemote() {
	s.closeOnce.Do(func() {
		close(s.closed)
	})
}

func (s *Stream) receive(data []byte) error {
	cp := append([]byte(nil), data...)
	select {
	case s.readCh <- cp:
		return nil
	case <-s.closed:
		return io.ErrClosedPipe
	case <-s.sess.closed:
		return io.ErrClosedPipe
	}
}

func (s *Stream) SetReadDeadline(t time.Time) error {
	s.mu.Lock()
	s.readDeadline = t
	s.mu.Unlock()
	return nil
}

func (s *Stream) SetWriteDeadline(t time.Time) error {
	s.mu.Lock()
	s.writeDeadline = t
	s.mu.Unlock()
	return nil
}

func (s *Stream) SetDeadline(t time.Time) error {
	_ = s.SetReadDeadline(t)
	return s.SetWriteDeadline(t)
}

func (s *Stream) LocalAddr() net.Addr {
	return s.sess.conn.LocalAddr()
}

func (s *Stream) RemoteAddr() net.Addr {
	return s.sess.conn.RemoteAddr()
}
