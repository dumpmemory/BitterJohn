package anytls

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
)

const (
	socksAddrIPv4   byte = 0x01
	socksAddrDomain byte = 0x03
	socksAddrIPv6   byte = 0x04
)

type socksAddr struct {
	Host string
	Port uint16
}

func (a socksAddr) String() string {
	return net.JoinHostPort(a.Host, strconv.Itoa(int(a.Port)))
}

func writeSocksAddr(w io.Writer, addr string) error {
	host, port, err := splitHostPort(addr)
	if err != nil {
		return err
	}

	var buf []byte
	if ip, err := netip.ParseAddr(host); err == nil {
		if ip.Is4() {
			buf = append(buf, socksAddrIPv4)
			buf = append(buf, ip.AsSlice()...)
		} else {
			buf = append(buf, socksAddrIPv6)
			buf = append(buf, ip.AsSlice()...)
		}
	} else {
		if len(host) > 255 {
			return fmt.Errorf("domain name too long: %v", host)
		}
		buf = append(buf, socksAddrDomain, byte(len(host)))
		buf = append(buf, host...)
	}

	buf = binary.BigEndian.AppendUint16(buf, port)
	_, err = w.Write(buf)
	return err
}

func readSocksAddr(r io.Reader) (socksAddr, error) {
	var typ [1]byte
	if _, err := io.ReadFull(r, typ[:]); err != nil {
		return socksAddr{}, err
	}

	var host string
	switch typ[0] {
	case socksAddrIPv4:
		var b [4]byte
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return socksAddr{}, err
		}
		host = netip.AddrFrom4(b).String()
	case socksAddrIPv6:
		var b [16]byte
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return socksAddr{}, err
		}
		host = netip.AddrFrom16(b).String()
	case socksAddrDomain:
		var l [1]byte
		if _, err := io.ReadFull(r, l[:]); err != nil {
			return socksAddr{}, err
		}
		b := make([]byte, int(l[0]))
		if _, err := io.ReadFull(r, b); err != nil {
			return socksAddr{}, err
		}
		host = string(b)
	default:
		return socksAddr{}, fmt.Errorf("unsupported socks addr type: %d", typ[0])
	}

	var port [2]byte
	if _, err := io.ReadFull(r, port[:]); err != nil {
		return socksAddr{}, err
	}
	return socksAddr{Host: host, Port: binary.BigEndian.Uint16(port[:])}, nil
}

func parseSocksAddr(addr string) (socksAddr, error) {
	host, port, err := splitHostPort(addr)
	if err != nil {
		return socksAddr{}, err
	}
	return socksAddr{Host: host, Port: port}, nil
}

func splitHostPort(addr string) (string, uint16, error) {
	host, strPort, err := net.SplitHostPort(addr)
	if err != nil {
		return "", 0, err
	}
	port, err := strconv.ParseUint(strPort, 10, 16)
	if err != nil {
		return "", 0, err
	}
	return host, uint16(port), nil
}
