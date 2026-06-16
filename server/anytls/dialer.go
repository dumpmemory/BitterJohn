package anytls

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/protocol"
	bjserver "github.com/e14914c0-6759-480d-be89-66b7b7676451/BitterJohn/server"
)

const (
	managerHost                      = "bitterjohn.anytls.manager.arpa"
	managerPort                      = uint16(0)
	serverSettingsNegotiationTimeout = 200 * time.Millisecond
)

func init() {
	protocol.Register(string(serverProtocol()), NewDialer)
}

type Dialer struct {
	proxyAddress string
	nextDialer   netproxy.Dialer
	tlsConfig    *tls.Config
	passwordHash [sha256.Size]byte

	mu      sync.Mutex
	session *Session
}

func NewDialer(nextDialer netproxy.Dialer, header protocol.Header) (netproxy.Dialer, error) {
	if nextDialer == nil {
		return nil, fmt.Errorf("nil next dialer")
	}
	tlsConfig := header.TlsConfig
	if tlsConfig == nil {
		tlsConfig = &tls.Config{
			MinVersion:         tls.VersionTLS12,
			ServerName:         header.SNI,
			InsecureSkipVerify: true,
		}
	} else {
		tlsConfig = tlsConfig.Clone()
	}
	if tlsConfig.ServerName == "" && header.SNI != "" {
		tlsConfig.ServerName = header.SNI
	}
	return &Dialer{
		proxyAddress: header.ProxyAddress,
		nextDialer:   nextDialer,
		tlsConfig:    tlsConfig,
		passwordHash: sha256.Sum256([]byte(header.Password)),
	}, nil
}

func (d *Dialer) Dial(network string, addr string) (netproxy.Conn, error) {
	return d.DialContext(context.Background(), network, addr)
}

func (d *Dialer) DialContext(ctx context.Context, network string, addr string) (netproxy.Conn, error) {
	magicNetwork, err := netproxy.ParseMagicNetwork(network)
	if err != nil {
		return nil, err
	}
	switch magicNetwork.Network {
	case "tcp":
		stream, session, err := d.openStream(ctx, addr)
		if err != nil {
			return nil, err
		}
		if err := waitStreamReady(ctx, session, stream); err != nil {
			_ = stream.Close()
			return nil, err
		}
		return stream, nil
	case "udp":
		stream, session, err := d.openStream(ctx, net.JoinHostPort(uotMagicAddress, "0"))
		if err != nil {
			return nil, err
		}
		destination, err := parseSocksAddr(addr)
		if err != nil {
			_ = stream.Close()
			return nil, err
		}
		if err := writeUOTRequest(stream, uotRequest{IsConnect: true, Destination: destination}); err != nil {
			_ = stream.Close()
			return nil, err
		}
		if err := waitStreamReady(ctx, session, stream); err != nil {
			_ = stream.Close()
			return nil, err
		}
		return newUDPPacketConn(stream, destination), nil
	default:
		return nil, fmt.Errorf("%w: %v", netproxy.UnsupportedTunnelTypeError, magicNetwork.Network)
	}
}

func (d *Dialer) DialCmdMsg(cmd protocol.MetadataCmd) (netproxy.Conn, error) {
	return d.DialCmdMsgContext(context.Background(), cmd)
}

func (d *Dialer) DialCmdMsgContext(ctx context.Context, cmd protocol.MetadataCmd) (netproxy.Conn, error) {
	stream, _, err := d.openStream(ctx, net.JoinHostPort(managerHost, "0"))
	if err != nil {
		return nil, err
	}
	if _, err := stream.Write([]byte{byte(cmd)}); err != nil {
		_ = stream.Close()
		return nil, err
	}
	return stream, nil
}

func (d *Dialer) Close() error {
	d.mu.Lock()
	session := d.session
	d.session = nil
	d.mu.Unlock()
	if session != nil {
		return session.Close()
	}
	return nil
}

func (d *Dialer) openStream(ctx context.Context, addr string) (*Stream, *Session, error) {
	session, err := d.getSession(ctx)
	if err != nil {
		return nil, nil, err
	}
	stream, err := session.OpenStream()
	if err != nil {
		_ = session.Close()
		return nil, nil, err
	}
	if err := writeSocksAddr(stream, addr); err != nil {
		_ = stream.Close()
		return nil, nil, err
	}
	return stream, session, nil
}

func waitStreamReady(ctx context.Context, session *Session, stream *Stream) error {
	if session.waitServerSettings(serverSettingsNegotiationTimeout) < 2 {
		return nil
	}
	synackCtx, cancel := context.WithTimeout(ctx, bjserver.DialTimeout)
	defer cancel()
	return stream.waitSYNACK(synackCtx)
}

func (d *Dialer) getSession(ctx context.Context) (*Session, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.session != nil && !d.session.IsClosed() {
		return d.session, nil
	}

	rawConn, err := d.nextDialer.DialContext(ctx, "tcp", d.proxyAddress)
	if err != nil {
		return nil, err
	}
	tlsConn := tls.Client(asNetConn(rawConn), d.tlsConfig)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		_ = tlsConn.Close()
		return nil, err
	}
	if err := writeClientAuth(tlsConn, d.passwordHash); err != nil {
		_ = tlsConn.Close()
		return nil, err
	}
	session := newClientSession(tlsConn)
	if err := session.runClient(); err != nil {
		_ = tlsConn.Close()
		return nil, err
	}
	d.session = session
	return session, nil
}

func writeClientAuth(w io.Writer, passwordHash [sha256.Size]byte) error {
	var header [sha256.Size + 2]byte
	copy(header[:sha256.Size], passwordHash[:])
	binary.BigEndian.PutUint16(header[sha256.Size:], 0)
	_, err := w.Write(header[:])
	return err
}

func serverProtocol() protocol.Protocol {
	return protocol.Protocol("anytls")
}
