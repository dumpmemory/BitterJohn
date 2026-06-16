package anytls

import (
	"net"
	"time"

	"github.com/daeuniverse/softwind/netproxy"
)

type anyAddr string

func (a anyAddr) Network() string { return "anytls" }
func (a anyAddr) String() string  { return string(a) }

type netConnAdapter struct {
	netproxy.Conn
}

func asNetConn(conn netproxy.Conn) net.Conn {
	if c, ok := conn.(net.Conn); ok {
		return c
	}
	return netConnAdapter{Conn: conn}
}

func (c netConnAdapter) LocalAddr() net.Addr  { return anyAddr("local") }
func (c netConnAdapter) RemoteAddr() net.Addr { return anyAddr("remote") }

func deadlineExceeded(t time.Time) bool {
	return !t.IsZero() && !time.Now().Before(t)
}
