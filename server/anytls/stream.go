package anytls

import (
	"context"
	"errors"
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
	readDeadlineC chan struct{}

	readCh     chan []byte
	closed     chan struct{}
	closeOnce  sync.Once
	synackCh   chan error
	synackOnce sync.Once
}

func newStream(id uint32, sess *Session) *Stream {
	return &Stream{
		id:            id,
		sess:          sess,
		readDeadlineC: make(chan struct{}),
		readCh:        make(chan []byte, 32),
		closed:        make(chan struct{}),
		synackCh:      make(chan error, 1),
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
		readDeadlineC := s.readDeadlineC
		s.mu.Unlock()

		if deadlineExceeded(deadline) {
			return 0, osDeadlineExceeded()
		}

		var timer *time.Timer
		var timerC <-chan time.Time
		if !deadline.IsZero() {
			timer = time.NewTimer(time.Until(deadline))
			timerC = timer.C
		}

		select {
		case data := <-s.readCh:
			stopTimer(timer)
			s.mu.Lock()
			s.pending = data
			s.mu.Unlock()
		case <-s.closed:
			stopTimer(timer)
			return 0, io.EOF
		case <-readDeadlineC:
			stopTimer(timer)
		case <-timerC:
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
	close(s.readDeadlineC)
	s.readDeadlineC = make(chan struct{})
	s.mu.Unlock()
	return nil
}

func (s *Stream) SetWriteDeadline(t time.Time) error {
	s.mu.Lock()
	s.writeDeadline = t
	s.mu.Unlock()
	if s.sess == nil || s.sess.conn == nil {
		return nil
	}
	return s.sess.conn.SetWriteDeadline(t)
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

func (s *Stream) receiveSYNACK(data []byte) {
	var err error
	if len(data) > 0 {
		err = errors.New(string(data))
		s.closeRemote()
	}
	s.synackOnce.Do(func() {
		s.synackCh <- err
		close(s.synackCh)
	})
}

func (s *Stream) waitSYNACK(ctx context.Context) error {
	select {
	case err := <-s.synackCh:
		return err
	case <-s.closed:
		return io.ErrClosedPipe
	case <-s.sess.closed:
		return io.ErrClosedPipe
	case <-ctx.Done():
		_ = s.Close()
		return ctx.Err()
	}
}

func stopTimer(timer *time.Timer) {
	if timer == nil {
		return
	}
	if !timer.Stop() {
		select {
		case <-timer.C:
		default:
		}
	}
}
