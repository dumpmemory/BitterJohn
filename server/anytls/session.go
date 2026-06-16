package anytls

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Session struct {
	conn net.Conn

	isClient bool
	onStream func(*Stream)

	writeMu      sync.Mutex
	writeStateMu sync.Mutex
	activeWrite  *Stream

	mu       sync.RWMutex
	nextID   uint32
	streams  map[uint32]*Stream
	closed   chan struct{}
	closeOne sync.Once

	peerVersion            byte
	serverSettingsDone     bool
	serverSettingsTimedOut bool
	serverSettingsCh       chan struct{}
	serverSettingsOnce     sync.Once
}

func newClientSession(conn net.Conn) *Session {
	return &Session{
		conn:             conn,
		isClient:         true,
		streams:          make(map[uint32]*Stream),
		closed:           make(chan struct{}),
		serverSettingsCh: make(chan struct{}),
	}
}

func newServerSession(conn net.Conn, onStream func(*Stream)) *Session {
	return &Session{
		conn:     conn,
		onStream: onStream,
		streams:  make(map[uint32]*Stream),
		closed:   make(chan struct{}),
	}
}

func (s *Session) runClient() error {
	if err := s.writeFrame(frame{
		cmd:  cmdSettings,
		data: []byte("v=2\nclient=BitterJohn\npadding-md5="),
	}); err != nil {
		return err
	}
	go s.recvLoop()
	return nil
}

func (s *Session) runServer() error {
	return s.recvLoop()
}

func (s *Session) IsClosed() bool {
	select {
	case <-s.closed:
		return true
	default:
		return false
	}
}

func (s *Session) Close() error {
	var first bool
	s.closeOne.Do(func() {
		first = true
		close(s.closed)
		if s.isClient {
			s.closeServerSettings()
		}
	})
	if !first {
		return nil
	}
	_ = s.conn.Close()
	s.mu.Lock()
	for _, stream := range s.streams {
		stream.closeRemote()
	}
	s.streams = make(map[uint32]*Stream)
	s.mu.Unlock()
	return nil
}

func (s *Session) OpenStream() (*Stream, error) {
	if s.IsClosed() {
		return nil, io.ErrClosedPipe
	}

	s.mu.Lock()
	s.nextID++
	id := s.nextID
	stream := newStream(id, s)
	s.streams[id] = stream
	s.mu.Unlock()

	if err := s.writeFrame(frame{cmd: cmdSYN, streamID: id}); err != nil {
		_ = s.closeStream(id, false)
		return nil, err
	}
	return stream, nil
}

func (s *Session) writeFrame(f frame) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	return writeFrame(s.conn, f)
}

func (s *Session) writeFrameForStream(stream *Stream, f frame) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	deadline := stream.getWriteDeadline()
	if deadlineExceeded(deadline) {
		return osDeadlineExceeded()
	}
	if err := s.beginStreamWrite(stream, deadline); err != nil {
		s.endStreamWrite(stream)
		return err
	}
	defer s.endStreamWrite(stream)
	return writeFrame(s.conn, f)
}

func (s *Session) beginStreamWrite(stream *Stream, deadline time.Time) error {
	s.writeStateMu.Lock()
	defer s.writeStateMu.Unlock()
	s.activeWrite = stream
	if s.conn == nil {
		return nil
	}
	return s.conn.SetWriteDeadline(deadline)
}

func (s *Session) endStreamWrite(stream *Stream) {
	s.writeStateMu.Lock()
	defer s.writeStateMu.Unlock()
	if s.activeWrite != stream {
		return
	}
	s.activeWrite = nil
	if s.conn != nil {
		_ = s.conn.SetWriteDeadline(time.Time{})
	}
}

func (s *Session) updateActiveWriteDeadline(stream *Stream, deadline time.Time) error {
	s.writeStateMu.Lock()
	defer s.writeStateMu.Unlock()
	if s.activeWrite != stream || s.conn == nil {
		return nil
	}
	return s.conn.SetWriteDeadline(deadline)
}

func (s *Session) closeStream(id uint32, notify bool) error {
	s.mu.Lock()
	delete(s.streams, id)
	s.mu.Unlock()
	if !notify || s.IsClosed() {
		return nil
	}
	return s.writeFrame(frame{cmd: cmdFIN, streamID: id})
}

func (s *Session) recvLoop() error {
	defer s.Close()

	var receivedSettings bool
	for {
		f, err := readFrame(s.conn)
		if err != nil {
			return err
		}
		switch f.cmd {
		case cmdWaste:
			continue
		case cmdPSH:
			stream := s.getStream(f.streamID)
			if stream != nil {
				_ = stream.receive(f.data)
			}
		case cmdSYN:
			if !s.isClient && !receivedSettings {
				_ = s.writeFrame(frame{cmd: cmdAlert, data: []byte("client did not send its settings")})
				return fmt.Errorf("client opened stream before settings")
			}
			if s.isClient {
				continue
			}
			stream := s.getOrCreateStream(f.streamID)
			if s.peerVersion >= 2 {
				_ = s.writeFrame(frame{cmd: cmdSYNACK, streamID: f.streamID})
			}
			if s.onStream != nil {
				go s.onStream(stream)
			}
		case cmdSYNACK:
			if stream := s.getStream(f.streamID); stream != nil {
				stream.receiveSYNACK(f.data)
				if len(f.data) > 0 {
					_ = s.closeStream(f.streamID, false)
				}
			}
		case cmdFIN:
			if stream := s.getStream(f.streamID); stream != nil {
				_ = s.closeStream(f.streamID, false)
				stream.closeRemote()
			}
		case cmdSettings:
			if !s.isClient {
				receivedSettings = true
				if v, err := strconv.Atoi(parseSettings(f.data)["v"]); err == nil && v >= 2 {
					s.setPeerVersion(byte(v))
					_ = s.writeFrame(frame{cmd: cmdServerSettings, data: []byte("v=2")})
				}
			}
		case cmdServerSettings:
			if s.isClient {
				if v, err := strconv.Atoi(parseSettings(f.data)["v"]); err == nil {
					s.completePeerVersion(byte(v))
				} else {
					s.completePeerVersion(1)
				}
			}
		case cmdAlert:
			return fmt.Errorf("remote alert: %s", string(f.data))
		case cmdUpdatePaddingScheme:
			continue
		case cmdHeartRequest:
			_ = s.writeFrame(frame{cmd: cmdHeartResponse, streamID: f.streamID})
		case cmdHeartResponse:
			continue
		default:
			return fmt.Errorf("unknown anytls command: %d", f.cmd)
		}
	}
}

func (s *Session) setPeerVersion(version byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.peerVersion = version
}

func (s *Session) getPeerVersion() byte {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.peerVersion
}

func (s *Session) waitServerSettings(timeout time.Duration) byte {
	if !s.isClient || s.serverSettingsCh == nil {
		return s.getPeerVersion()
	}
	if version, shouldWait := s.serverSettingsState(); !shouldWait {
		return version
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-s.serverSettingsCh:
	case <-timer.C:
		s.markServerSettingsTimedOut()
	case <-s.closed:
	}
	version := s.getPeerVersion()
	if version == 0 {
		return 1
	}
	return version
}

func (s *Session) completePeerVersion(version byte) {
	s.mu.Lock()
	if s.peerVersion == 0 || s.serverSettingsTimedOut {
		s.peerVersion = version
	}
	s.serverSettingsDone = true
	s.serverSettingsTimedOut = false
	s.mu.Unlock()
	s.closeServerSettings()
}

func (s *Session) serverSettingsState() (version byte, shouldWait bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.serverSettingsDone || s.peerVersion != 0 {
		if s.peerVersion == 0 {
			return 1, false
		}
		return s.peerVersion, false
	}
	if s.serverSettingsTimedOut {
		return 1, false
	}
	return 0, true
}

func (s *Session) markServerSettingsTimedOut() {
	s.mu.Lock()
	if s.peerVersion == 0 && !s.serverSettingsDone {
		s.serverSettingsTimedOut = true
	}
	s.mu.Unlock()
}

func (s *Session) closeServerSettings() {
	s.serverSettingsOnce.Do(func() {
		close(s.serverSettingsCh)
	})
}

func (s *Session) getStream(id uint32) *Stream {
	s.mu.RLock()
	stream := s.streams[id]
	s.mu.RUnlock()
	return stream
}

func (s *Session) getOrCreateStream(id uint32) *Stream {
	s.mu.Lock()
	defer s.mu.Unlock()
	stream := s.streams[id]
	if stream == nil {
		stream = newStream(id, s)
		s.streams[id] = stream
	}
	return stream
}

func parseSettings(data []byte) map[string]string {
	settings := make(map[string]string)
	for _, line := range bytes.Split(data, []byte{'\n'}) {
		key, value, ok := bytes.Cut(line, []byte{'='})
		if !ok {
			continue
		}
		settings[strings.TrimSpace(string(key))] = strings.TrimSpace(string(value))
	}
	return settings
}

func osDeadlineExceeded() error {
	return os.ErrDeadlineExceeded
}
