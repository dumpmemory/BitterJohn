package server

import (
	"encoding/binary"
	"fmt"
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/BitterJohn/common"
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/BitterJohn/config"
	"github.com/mzz2017/softwind/netproxy"
	"github.com/mzz2017/softwind/pool"
	"golang.org/x/net/dns/dnsmessage"
	"io"
	"net"
	"net/netip"
	"strings"
	"syscall"
)

type ForceNetworkType int

const (
	Force4 ForceNetworkType = iota
	Force6
	KeepOrigin
)

var ErrDialPrivateAddress = fmt.Errorf("request to dial a private address")

var SymmetricPrivateLimitedDialer netproxy.Dialer
var FullconePrivateLimitedDialer netproxy.Dialer

func InitLimitedDialer() {
	forceNetwork := KeepOrigin
	if config.ParamsObj.John.Only4 {
		forceNetwork = Force4
	}
	SymmetricPrivateLimitedDialer = NewLimitedDialer(false, forceNetwork)
	FullconePrivateLimitedDialer = NewLimitedDialer(true, forceNetwork)
}

type PrivateLimitedDialer struct {
	netDialer    net.Dialer
	fullCone     bool
	forceNetwork ForceNetworkType
}

func NewLimitedDialer(fullCone bool, forceNetwork ForceNetworkType) *PrivateLimitedDialer {
	return &PrivateLimitedDialer{
		netDialer: net.Dialer{
			Control: func(network, address string, c syscall.RawConn) error {
				host, _, err := net.SplitHostPort(address)
				if err != nil {
					return err
				}
				ip, err := netip.ParseAddr(host)
				if err != nil {
					// not a valid IP address
					return err
				}
				if common.IsPrivate(ip.AsSlice()) {
					return fmt.Errorf("%w: %v", ErrDialPrivateAddress, ip.String())
				}
				return nil
			},
		},
		fullCone:     fullCone,
		forceNetwork: forceNetwork,
	}
}

func (d *PrivateLimitedDialer) DialTcp(addr string) (c netproxy.Conn, err error) {
	return d.Dial("tcp", addr)
}

func (d *PrivateLimitedDialer) DialUdp(addr string) (netproxy.PacketConn, error) {
	c, err := d.Dial("udp", addr)
	if err != nil {
		return nil, err
	}
	cc := c.(*PrivateLimitedUDPConn)
	return cc, nil
}

func (d *PrivateLimitedDialer) Dial(network, addr string) (c netproxy.Conn, err error) {
	switch {
	case strings.HasPrefix(network, "tcp"):
		switch d.forceNetwork {
		case Force4:
			network = "tcp4"
		case Force6:
			network = "tcp6"
		default:
		}
		return d.netDialer.Dial(network, addr)
	case strings.HasPrefix(network, "udp"):
		switch d.forceNetwork {
		case Force4:
			network = "udp4"
		case Force6:
			network = "udp6"
		default:
		}
		if d.fullCone {
			conn, err := net.ListenUDP(network, nil)
			if err != nil {
				return nil, err
			}
			return &PrivateLimitedUDPConn{UDPConn: conn, FullCone: true}, nil
		} else {
			conn, err := d.netDialer.Dial(network, addr)
			if err != nil {
				return nil, err
			}
			return &PrivateLimitedUDPConn{UDPConn: conn.(*net.UDPConn), FullCone: false}, nil
		}
	default:
		return nil, net.UnknownNetworkError(network)
	}
}

type PrivateLimitedUDPConn struct {
	*net.UDPConn
	FullCone bool
}

func (c *PrivateLimitedUDPConn) WriteTo(b []byte, addr string) (int, error) {
	if !c.FullCone {
		// FIXME: check the addr
		return c.Write(b)
	}
	a, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return 0, err
	}
	if common.IsPrivate(a.IP) {
		return 0, ErrDialPrivateAddress
	}
	return c.UDPConn.WriteTo(b, a)
}

func (c *PrivateLimitedUDPConn) WriteMsgUDP(b, oob []byte, addr *net.UDPAddr) (n, oobn int, err error) {
	if !c.FullCone {
		n, err = c.Write(b)
		return n, 0, err
	}
	if common.IsPrivate(addr.IP) {
		return 0, 0, ErrDialPrivateAddress
	}
	return c.UDPConn.WriteMsgUDP(b, oob, addr)
}

func (c *PrivateLimitedUDPConn) WriteToUDP(b []byte, addr *net.UDPAddr) (int, error) {
	if !c.FullCone {
		return c.Write(b)
	}
	if common.IsPrivate(addr.IP) {
		return 0, ErrDialPrivateAddress
	}
	return c.UDPConn.WriteToUDP(b, addr)
}

func (c *PrivateLimitedUDPConn) ReadFrom(p []byte) (n int, addr netip.AddrPort, err error) {
	return c.UDPConn.ReadFromUDPAddrPort(p)
}

// LimitedDNSConn adheres to RFC 7766 section 5, "Transport Protocol Selection".
type LimitedDNSConn struct {
	net.Conn
	buf   []byte
	start int
}

func (c *LimitedDNSConn) Write(b []byte) (int, error) {
	switch c.Conn.RemoteAddr().Network() {
	case "udp":
		return c.Conn.Write(b[2:])
	default:
		return c.Conn.Write(b)
	}
}

func (c *LimitedDNSConn) Read(b []byte) (int, error) {
	if c.buf == nil {
		var (
			buf []byte
			n   int
			err error
		)
		switch c.Conn.RemoteAddr().Network() {
		case "udp":
			buf = pool.Get(2 + 512) // see RFC 1035
			n, err = c.Conn.Read(buf[2:])
			if err != nil {
				pool.Put(buf)
				return 0, err
			}
		default:
			buf = pool.Get(2 + 1280) // 1280 is a reasonable initial size for IP over Ethernet, see RFC 4035
			if _, err = io.ReadFull(c.Conn, buf[:2]); err != nil {
				pool.Put(buf)
				return 0, err
			}
			if msgLength := binary.BigEndian.Uint16(buf[:2]); msgLength > 1280 {
				pool.Put(buf)
				buf = pool.Get(2 + int(msgLength))
			} else {
				buf = buf[:2+msgLength]
			}
			if n, err = io.ReadFull(c.Conn, buf[2:]); err != nil {
				pool.Put(buf)
				return 0, err
			}
		}
		var dmsg dnsmessage.Message
		if err := dmsg.Unpack(buf[2 : 2+n]); err != nil {
			pool.Put(buf)
			return 0, err
		}
		for _, ans := range dmsg.Answers {
			if ans.Header.Type != dnsmessage.TypeA && ans.Header.Type != dnsmessage.TypeAAAA {
				continue
			}
			var ip net.IP
			switch body := ans.Body.(type) {
			case *dnsmessage.AResource:
				ip = body.A[:]
			case *dnsmessage.AAAAResource:
				ip = body.AAAA[:]
			}
			if common.IsPrivate(ip) {
				pool.Put(buf)
				return 0, fmt.Errorf("%w: %v(%v)", ErrDialPrivateAddress, ip.String(), ans.Header.Name)
			}
		}
		binary.BigEndian.PutUint16(buf, uint16(n))
		n += 2
		copy(b[:], buf[:n])
		if n < len(b) {
			pool.Put(buf)
		} else {
			c.buf = buf
			c.start = len(b)
		}
		return n, nil
	}
	n := copy(b, c.buf[c.start:])
	c.start += n
	if c.start >= len(c.buf) {
		pool.Put(c.buf)
		c.buf = nil
	}
	return n, nil
}
