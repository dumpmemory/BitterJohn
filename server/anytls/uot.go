package anytls

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/daeuniverse/outbound/netproxy"
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/BitterJohn/server"
)

const uotMagicAddress = "sp.v2.udp-over-tcp.arpa"

type uotRequest struct {
	IsConnect   bool
	Destination socksAddr
}

func writeUOTRequest(w io.Writer, req uotRequest) error {
	var isConnect byte
	if req.IsConnect {
		isConnect = 1
	}
	if _, err := w.Write([]byte{isConnect}); err != nil {
		return err
	}
	return writeSocksAddr(w, req.Destination.String())
}

func readUOTRequest(r io.Reader) (uotRequest, error) {
	var isConnect [1]byte
	if _, err := io.ReadFull(r, isConnect[:]); err != nil {
		return uotRequest{}, err
	}
	destination, err := readSocksAddr(r)
	if err != nil {
		return uotRequest{}, err
	}
	return uotRequest{
		IsConnect:   isConnect[0] != 0,
		Destination: destination,
	}, nil
}

func writeUOTPayload(w io.Writer, payload []byte) error {
	if len(payload) > maxFrameData {
		return fmt.Errorf("uot payload too large: %d", len(payload))
	}
	buf := make([]byte, 2+len(payload))
	binary.BigEndian.PutUint16(buf[:2], uint16(len(payload)))
	copy(buf[2:], payload)
	_, err := w.Write(buf)
	return err
}

func readUOTPayload(r io.Reader, buf []byte) (int, error) {
	var lenBuf [2]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return 0, err
	}
	length := int(binary.BigEndian.Uint16(lenBuf[:]))
	if length > len(buf) {
		return 0, io.ErrShortBuffer
	}
	return io.ReadFull(r, buf[:length])
}

type udpPacketConn struct {
	stream     *Stream
	target     socksAddr
	targetAddr netip.AddrPort
	writeMu    sync.Mutex
}

func newUDPPacketConn(stream *Stream, target socksAddr) *udpPacketConn {
	return &udpPacketConn{
		stream:     stream,
		target:     target,
		targetAddr: resolveTargetAddr(target),
	}
}

func (c *udpPacketConn) Read(b []byte) (int, error) {
	n, _, err := c.ReadFrom(b)
	return n, err
}

func (c *udpPacketConn) Write(b []byte) (int, error) {
	if err := c.writePayload(b); err != nil {
		return 0, err
	}
	return len(b), nil
}

func (c *udpPacketConn) ReadFrom(b []byte) (int, netip.AddrPort, error) {
	n, err := readUOTPayload(c.stream, b)
	return n, c.targetAddr, err
}

func (c *udpPacketConn) WriteTo(b []byte, addr string) (int, error) {
	if addr != "" && addr != c.target.String() {
		return 0, fmt.Errorf("anytls uot packet conn is connected to %v, got %v", c.target.String(), addr)
	}
	if err := c.writePayload(b); err != nil {
		return 0, err
	}
	return len(b), nil
}

func (c *udpPacketConn) writePayload(b []byte) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	return writeUOTPayload(c.stream, b)
}

func (c *udpPacketConn) Close() error {
	return c.stream.Close()
}

func (c *udpPacketConn) SetDeadline(t time.Time) error {
	return c.stream.SetDeadline(t)
}

func (c *udpPacketConn) SetReadDeadline(t time.Time) error {
	return c.stream.SetReadDeadline(t)
}

func (c *udpPacketConn) SetWriteDeadline(t time.Time) error {
	return c.stream.SetWriteDeadline(t)
}

func (s *Server) handleUOT(stream *Stream, passage *Passage) error {
	req, err := readUOTRequest(stream)
	if err != nil {
		return err
	}
	if !req.IsConnect {
		return fmt.Errorf("anytls uot packet mode is not supported")
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

	conn, err := dialWithTimeout(dialer, "udp", req.Destination.String())
	if err != nil {
		return err
	}
	packetConn, ok := conn.(netproxy.PacketConn)
	if !ok {
		_ = conn.Close()
		return fmt.Errorf("dialer returned %T for udp", conn)
	}
	defer packetConn.Close()

	errCh := make(chan error, 2)
	go func() {
		errCh <- relayUOTToPacketConn(packetConn, stream, req.Destination.String())
	}()
	go func() {
		errCh <- relayPacketConnToUOT(stream, packetConn)
	}()
	err = <-errCh
	if isIgnorableUOTError(err) {
		return nil
	}
	return err
}

func relayUOTToPacketConn(dst netproxy.PacketConn, src *Stream, target string) error {
	buf := make([]byte, maxFrameData)
	for {
		_ = src.SetReadDeadline(time.Now().Add(server.DefaultNatTimeout))
		n, err := readUOTPayload(src, buf)
		if err != nil {
			return err
		}
		_ = dst.SetWriteDeadline(time.Now().Add(server.DefaultNatTimeout))
		if _, err := dst.WriteTo(buf[:n], target); err != nil {
			return err
		}
	}
}

func relayPacketConnToUOT(dst *Stream, src netproxy.PacketConn) error {
	buf := make([]byte, maxFrameData)
	for {
		_ = src.SetReadDeadline(time.Now().Add(server.DefaultNatTimeout))
		n, _, err := src.ReadFrom(buf)
		if err != nil {
			return err
		}
		_ = dst.SetWriteDeadline(time.Now().Add(server.DefaultNatTimeout))
		if err := writeUOTPayload(dst, buf[:n]); err != nil {
			return err
		}
	}
}

func isIgnorableUOTError(err error) bool {
	if err == nil || err == io.EOF || err == net.ErrClosed {
		return true
	}
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

func resolveTargetAddr(target socksAddr) netip.AddrPort {
	addrPort, err := netip.ParseAddrPort(target.String())
	if err == nil {
		return addrPort
	}
	udpAddr, err := net.ResolveUDPAddr("udp", target.String())
	if err != nil || udpAddr == nil {
		return netip.AddrPort{}
	}
	addr, ok := netip.AddrFromSlice(udpAddr.IP)
	if !ok {
		return netip.AddrPort{}
	}
	return netip.AddrPortFrom(addr.Unmap(), uint16(udpAddr.Port))
}

func dialWithTimeout(dialer netproxy.Dialer, network string, addr string) (netproxy.Conn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), server.DialTimeout)
	defer cancel()
	return dialer.DialContext(ctx, network, addr)
}
