package anytls

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/daeuniverse/softwind/netproxy"
	"github.com/daeuniverse/softwind/protocol"
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/BitterJohn/api"
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/BitterJohn/common"
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/BitterJohn/config"
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/BitterJohn/pkg/log"
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/BitterJohn/server"
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/SweetLisa/model"
	jsoniter "github.com/json-iterator/go"
	gonanoid "github.com/matoous/go-nanoid"
)

func init() {
	server.Register(string(server.ProtocolAnyTLS), NewJohn)
}

type Server struct {
	dialer    netproxy.Dialer
	tlsConfig *tls.Config

	sweetLisa config.Lisa
	arg       server.Argument

	mutex    sync.Mutex
	passages []Passage
	users    map[[sha256.Size]byte]*Passage

	passageContentionCache *server.ContentionCache
	lastAlive              time.Time

	ctx      context.Context
	cancel   context.CancelFunc
	listener net.Listener
}

type Passage struct {
	server.Passage
	passwordHash [sha256.Size]byte
}

func New(valueCtx context.Context, dialer netproxy.Dialer) (server.Server, error) {
	tlsConfig, err := newSelfSignedTLSConfig()
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &Server{
		dialer:    dialer,
		tlsConfig: tlsConfig,
		users:     make(map[[sha256.Size]byte]*Passage),
		ctx:       ctx,
		cancel:    cancel,
	}, nil
}

func NewJohn(valueCtx context.Context, dialer netproxy.Dialer, sweetLisa config.Lisa, arg server.Argument) (server.Server, error) {
	srv, err := New(valueCtx, dialer)
	if err != nil {
		return nil, err
	}
	john := srv.(*Server)
	john.sweetLisa = sweetLisa
	john.arg = arg
	john.passageContentionCache = server.NewContentionCache()
	if err := srv.AddPassages([]server.Passage{{Manager: true}}); err != nil {
		return nil, err
	}
	if err := john.register(); err != nil {
		return nil, err
	}
	go john.registerBackground()
	return john, nil
}

func (s *Server) Listen(addr string) error {
	lt, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	return s.serveListener(lt)
}

func (s *Server) serveListener(lt net.Listener) error {
	s.listener = lt
	for {
		conn, err := lt.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		go func() {
			if err := s.handleConn(conn); err != nil {
				if errors.Is(err, server.ErrPassageAbuse) ||
					errors.Is(err, protocol.ErrFailAuth) {
					log.Warn("anytls handleConn: %v", err)
				} else {
					log.Info("anytls handleConn: %v", err)
				}
			}
		}()
	}
}

func (s *Server) Close() error {
	s.cancel()
	if s.listener != nil {
		return s.listener.Close()
	}
	return nil
}

func (s *Server) AddPassages(passages []server.Passage) error {
	local, _ := LocalizePassages(passages)
	s.mutex.Lock()
	defer s.mutex.Unlock()
	for _, passage := range local {
		if passage.Manager {
			s.removePassagesFuncLocked(func(p *Passage) bool { return p.Manager })
		}
		s.passages = append(s.passages, passage)
	}
	s.rebuildUsersLocked()
	return nil
}

func (s *Server) RemovePassages(passages []server.Passage, alsoManager bool) error {
	local, _ := LocalizePassages(passages)
	keySet := make(map[string]struct{}, len(local))
	for _, passage := range local {
		if passage.Manager && !alsoManager {
			continue
		}
		keySet[passage.In.Argument.Hash()] = struct{}{}
	}

	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.removePassagesFuncLocked(func(p *Passage) bool {
		_, ok := keySet[p.In.Argument.Hash()]
		return ok
	})
	s.rebuildUsersLocked()
	return nil
}

func (s *Server) SyncPassages(passages []server.Passage) error {
	return server.SyncPassages(s, passages)
}

func (s *Server) Passages() (passages []server.Passage) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	for _, passage := range s.passages {
		passages = append(passages, passage.Passage)
	}
	return passages
}

func LocalizePassages(passages []server.Passage) ([]Passage, *Passage) {
	local := make([]Passage, len(passages))
	var manager *Passage
	for i, passage := range passages {
		if passage.Manager {
			passage.In.Password, _ = gonanoid.Generate(common.Alphabet, 23)
			if manager == nil {
				manager = &local[i]
			} else {
				passage.Manager = false
				log.Warn("found more than one manager")
			}
		}
		local[i].Passage = passage
		local[i].passwordHash = sha256.Sum256([]byte(passage.In.Password))
	}
	return local, manager
}

func (s *Server) removePassagesFuncLocked(f func(*Passage) bool) {
	for i := len(s.passages) - 1; i >= 0; i-- {
		if f(&s.passages[i]) {
			s.passages = append(s.passages[:i], s.passages[i+1:]...)
		}
	}
}

func (s *Server) rebuildUsersLocked() {
	s.users = make(map[[sha256.Size]byte]*Passage, len(s.passages))
	for i := range s.passages {
		s.users[s.passages[i].passwordHash] = &s.passages[i]
	}
}

func (s *Server) handleConn(conn net.Conn) error {
	defer conn.Close()
	tlsConn := tls.Server(conn, s.tlsConfig)
	if err := tlsConn.Handshake(); err != nil {
		return err
	}
	passage, err := s.auth(tlsConn)
	if err != nil {
		return err
	}
	if tcpAddr, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
		if err := s.ContentionCheck(tcpAddr.IP, passage); err != nil {
			return err
		}
	}

	session := newServerSession(tlsConn, func(stream *Stream) {
		if err := s.handleStream(stream, passage); err != nil {
			log.Warn("anytls handleStream: %v", err)
		}
	})
	return session.runServer()
}

func (s *Server) auth(conn net.Conn) (*Passage, error) {
	var key [sha256.Size]byte
	if _, err := io.ReadFull(conn, key[:]); err != nil {
		return nil, err
	}
	var lenBuf [2]byte
	if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
		return nil, err
	}
	if paddingLen := binary.BigEndian.Uint16(lenBuf[:]); paddingLen > 0 {
		if _, err := io.CopyN(io.Discard, conn, int64(paddingLen)); err != nil {
			return nil, err
		}
	}

	s.mutex.Lock()
	passage := s.users[key]
	s.mutex.Unlock()
	if passage == nil {
		return nil, protocol.ErrFailAuth
	}
	return passage, nil
}

func (s *Server) handleStream(stream *Stream, passage *Passage) error {
	defer stream.Close()

	destination, err := readSocksAddr(stream)
	if err != nil {
		return err
	}
	if destination.Host == managerHost && destination.Port == managerPort {
		return s.handleMsg(stream, passage)
	}
	if passage.Manager {
		return fmt.Errorf("%w: manager key is abused for a non-cmd connection", server.ErrPassageAbuse)
	}
	if destination.Host == uotMagicAddress {
		return s.handleUOT(stream, passage)
	}

	dialer := s.dialer
	if passage.Out != nil {
		header, err := server.GetHeader(*passage.Out, &s.sweetLisa)
		if err != nil {
			return err
		}
		dialer, err = server.NewDialer(string(passage.Out.Protocol), dialer, header)
		if err != nil {
			return err
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), server.DialTimeout)
	defer cancel()
	rConn, err := (&netproxy.ContextDialerConverter{Dialer: dialer}).DialContext(ctx, "tcp", destination.String())
	if err != nil {
		var netErr net.Error
		if errors.As(err, &netErr) && netErr.Timeout() {
			log.Debug("%v", err)
			return nil
		}
		return err
	}
	defer rConn.Close()
	if err = server.RelayTCP(stream, rConn); err != nil {
		var netErr net.Error
		if errors.Is(err, io.EOF) || (errors.As(err, &netErr) && netErr.Timeout()) {
			return nil
		}
		return fmt.Errorf("relay tcp error: %w", err)
	}
	return nil
}

func (s *Server) handleMsg(conn netproxy.Conn, passage *Passage) error {
	if !passage.Manager {
		return fmt.Errorf("handleMsg: illegal message received from a non-manager passage")
	}
	var cmd [1]byte
	if _, err := io.ReadFull(conn, cmd[:]); err != nil {
		return err
	}
	reqBody, err := readManagerBody(conn)
	if err != nil {
		return err
	}

	var resp []byte
	switch protocol.MetadataCmd(cmd[0]) {
	case protocol.MetadataCmdPing:
		if !bytes.Equal(reqBody, []byte("ping")) {
			log.Warn("the body of received ping message is %v instead of %v", strconv.Quote(string(reqBody)), strconv.Quote("ping"))
		}
		s.lastAlive = time.Now()
		bandwidthLimit, err := server.GenerateBandwidthLimit()
		if err != nil {
			return err
		}
		resp, err = jsoniter.Marshal(model.PingResp{BandwidthLimit: bandwidthLimit})
		if err != nil {
			return err
		}
	case protocol.MetadataCmdSyncPassages:
		var passages []model.Passage
		if err := jsoniter.Unmarshal(reqBody, &passages); err != nil {
			return err
		}
		serverPassages := make([]server.Passage, 0, len(passages))
		for _, passage := range passages {
			serverPassages = append(serverPassages, server.Passage{Passage: passage})
		}
		if err := s.SyncPassages(serverPassages); err != nil {
			return err
		}
		resp = []byte("OK")
	default:
		return fmt.Errorf("%w: unexpected metadata cmd type: %v", protocol.ErrFailAuth, cmd[0])
	}
	return writeManagerBody(conn, resp)
}

func readManagerBody(r io.Reader) ([]byte, error) {
	var lenBuf [4]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return nil, err
	}
	body := make([]byte, int(binary.BigEndian.Uint32(lenBuf[:])))
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, err
	}
	return body, nil
}

func writeManagerBody(w io.Writer, body []byte) error {
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(body)))
	if _, err := w.Write(lenBuf[:]); err != nil {
		return err
	}
	_, err := w.Write(body)
	return err
}

func (s *Server) ContentionCheck(thisIP net.IP, passage *Passage) error {
	if s.passageContentionCache == nil {
		return nil
	}
	contentionDuration := server.ProtectTime[passage.Use()]
	if contentionDuration > 0 {
		passageKey := passage.In.Argument.Hash()
		accept, conflictIP := s.passageContentionCache.Check(passageKey, contentionDuration, thisIP)
		if !accept {
			return fmt.Errorf("%w: from %v and %v: contention detected", server.ErrPassageAbuse, thisIP.String(), conflictIP.String())
		}
	}
	return nil
}

func (s *Server) registerBackground() {
	interval := 2 * time.Second
	ticker := time.NewTicker(interval)
	for {
		select {
		case <-s.ctx.Done():
			ticker.Stop()
			return
		case <-ticker.C:
			if time.Since(s.lastAlive) < server.LostThreshold {
				continue
			}
			if err := s.register(); err != nil {
				interval *= 2
				if interval > 600*time.Second {
					interval = 600 * time.Second
				}
				log.Warn("anytls registerBackground: %v. retry in %v", err, interval.String())
			} else {
				interval = 2 * time.Second
			}
			ticker.Reset(interval)
		}
	}
}

func (s *Server) register() error {
	var manager server.Passage
	for _, passage := range s.Passages() {
		if passage.Manager {
			manager = passage
			break
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	t, _ := net.LookupTXT("cdn-validate." + s.sweetLisa.Host)
	var validateToken string
	if len(t) > 0 {
		validateToken = t[0]
	}
	bandwidthLimit, err := server.GenerateBandwidthLimit()
	if err != nil {
		return err
	}
	cdnNames, users, err := api.Register(ctx, s.sweetLisa.Host, validateToken, model.Server{
		Ticket: s.arg.Ticket,
		Name:   s.arg.ServerName,
		Hosts:  s.arg.Hostnames,
		Port:   s.arg.Port,
		Argument: model.Argument{
			Protocol: server.ProtocolAnyTLS,
			Password: manager.In.Password,
		},
		BandwidthLimit: bandwidthLimit,
		NoRelay:        s.arg.NoRelay,
	})
	if err != nil {
		return err
	}
	log.Alert("Succeed to register at %v (%v)", strconv.Quote(s.sweetLisa.Host), cdnNames)
	s.lastAlive = time.Now()
	return s.SyncPassages(users)
}
