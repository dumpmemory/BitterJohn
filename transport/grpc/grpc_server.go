package grpc

import (
	"errors"
	"github.com/Qv2ray/gun/pkg/proto"
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/BitterJohn/pkg/log"
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/BitterJohn/pool"
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/BitterJohn/protocol"
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/BitterJohn/server"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
	"io"
	"net"
	"os"
	"sync"
	"time"
)

type ServerConn struct {
	localAddr net.Addr
	tun       proto.GunService_TunServer
	muReading sync.Mutex // muReading protects reading
	muWriting sync.Mutex // muWriting protects writing
	buf       []byte
	offset    int

	deadlineMu    sync.Mutex
	readDeadline  *time.Timer
	writeDeadline *time.Timer
	readClosed    chan struct{}
	writeClosed   chan struct{}
	closed        chan struct{}
}

func NewServerConn(tun proto.GunService_TunServer, localAddr net.Addr) *ServerConn {
	return &ServerConn{
		tun:         tun,
		localAddr:   localAddr,
		readClosed:  make(chan struct{}),
		writeClosed: make(chan struct{}),
		closed:      make(chan struct{}),
	}
}

func (c *ServerConn) Read(p []byte) (n int, err error) {
	select {
	case <-c.readClosed:
		return 0, os.ErrDeadlineExceeded
	case <-c.closed:
		return 0, io.EOF
	default:
	}

	c.muReading.Lock()
	defer c.muReading.Unlock()
	if c.buf != nil {
		n = copy(p, c.buf[c.offset:])
		c.offset += n
		if c.offset == len(c.buf) {
			pool.Put(c.buf)
			c.buf = nil
		}
		return n, nil
	}
	// set 1 to avoid channel leak
	readDone := make(chan RecvResp, 1)
	// pass channel to the function to avoid closure leak
	go func(readDone chan RecvResp) {
		recv, e := c.tun.Recv()
		readDone <- RecvResp{
			hunk: recv,
			err:  e,
		}
	}(readDone)
	select {
	case <-c.readClosed:
		return 0, os.ErrDeadlineExceeded
	case <-c.closed:
		return 0, io.EOF
	case recvResp := <-readDone:
		err = recvResp.err
		if err != nil {
			if code := status.Code(err); code == codes.Unavailable || status.Code(err) == codes.OutOfRange {
				err = io.EOF
			}
			return 0, err
		}
		n = copy(p, recvResp.hunk.Data)
		c.buf = pool.Get(len(recvResp.hunk.Data) - n)
		copy(c.buf, recvResp.hunk.Data[n:])
		c.offset = 0
		return n, nil
	}
}

func (c *ServerConn) Write(p []byte) (n int, err error) {
	select {
	case <-c.writeClosed:
		return 0, os.ErrDeadlineExceeded
	case <-c.closed:
		return 0, io.EOF
	default:
	}

	c.muWriting.Lock()
	defer c.muWriting.Unlock()
	// set 1 to avoid channel leak
	sendDone := make(chan error, 1)
	// pass channel to the function to avoid closure leak
	go func(sendDone chan error) {
		e := c.tun.Send(&proto.Hunk{Data: p})
		sendDone <- e
	}(sendDone)
	select {
	case <-c.writeClosed:
		return 0, os.ErrDeadlineExceeded
	case <-c.closed:
		return 0, io.EOF
	case err = <-sendDone:
		if code := status.Code(err); code == codes.Unavailable || status.Code(err) == codes.OutOfRange {
			err = io.EOF
		}
		return len(p), err
	}
}

func (c *ServerConn) Close() error {
	select {
	case <-c.closed:
	default:
		close(c.closed)
	}
	return nil
}
func (c *ServerConn) LocalAddr() net.Addr {
	return c.localAddr
}
func (c *ServerConn) RemoteAddr() net.Addr {
	p, _ := peer.FromContext(c.tun.Context())
	return p.Addr
}

func (c *ServerConn) SetDeadline(t time.Time) error {
	c.deadlineMu.Lock()
	defer c.deadlineMu.Unlock()
	if now := time.Now(); t.After(now) {
		// refresh the deadline if the deadline has been exceeded
		select {
		case <-c.readClosed:
			c.readClosed = make(chan struct{})
		}
		select {
		case <-c.writeClosed:
			c.writeClosed = make(chan struct{})
		}
		// reset the deadline timer to make the c.readClosed and c.writeClosed with the new pointer (if it is)
		if c.readDeadline != nil {
			c.readDeadline.Stop()
		}
		c.readDeadline = time.AfterFunc(t.Sub(now), func() {
			c.deadlineMu.Lock()
			defer c.deadlineMu.Unlock()
			select {
			case <-c.readClosed:
			default:
				close(c.readClosed)
			}
		})
		if c.writeDeadline != nil {
			c.writeDeadline.Stop()
		}
		c.writeDeadline = time.AfterFunc(t.Sub(now), func() {
			c.deadlineMu.Lock()
			defer c.deadlineMu.Unlock()
			select {
			case <-c.writeClosed:
			default:
				close(c.writeClosed)
			}
		})
	} else {
		select {
		case <-c.readClosed:
		default:
			close(c.readClosed)
		}
		select {
		case <-c.writeClosed:
		default:
			close(c.writeClosed)
		}
	}
	return nil
}

func (c *ServerConn) SetReadDeadline(t time.Time) error {
	c.deadlineMu.Lock()
	defer c.deadlineMu.Unlock()
	if now := time.Now(); t.After(now) {
		// refresh the deadline if the deadline has been exceeded
		select {
		case <-c.readClosed:
			c.readClosed = make(chan struct{})
		}
		// reset the deadline timer to make the c.readClosed and c.writeClosed with the new pointer (if it is)
		if c.readDeadline != nil {
			c.readDeadline.Stop()
		}
		c.readDeadline = time.AfterFunc(t.Sub(now), func() {
			c.deadlineMu.Lock()
			defer c.deadlineMu.Unlock()
			select {
			case <-c.readClosed:
			default:
				close(c.readClosed)
			}
		})
	} else {
		select {
		case <-c.readClosed:
		default:
			close(c.readClosed)
		}
	}
	return nil
}

func (c *ServerConn) SetWriteDeadline(t time.Time) error {
	c.deadlineMu.Lock()
	defer c.deadlineMu.Unlock()
	if now := time.Now(); t.After(now) {
		// refresh the deadline if the deadline has been exceeded
		select {
		case <-c.writeClosed:
			c.writeClosed = make(chan struct{})
		}
		if c.writeDeadline != nil {
			c.writeDeadline.Stop()
		}
		c.writeDeadline = time.AfterFunc(t.Sub(now), func() {
			c.deadlineMu.Lock()
			defer c.deadlineMu.Unlock()
			select {
			case <-c.writeClosed:
			default:
				close(c.writeClosed)
			}
		})
	} else {
		select {
		case <-c.writeClosed:
		default:
			close(c.writeClosed)
		}
	}
	return nil
}

type Server struct {
	*grpc.Server
	LocalAddr  net.Addr
	HandleConn func(conn net.Conn) error
}

func (g Server) Tun(tun proto.GunService_TunServer) error {
	if err := g.HandleConn(NewServerConn(tun, g.LocalAddr)); err != nil {
		if errors.Is(err, server.ErrPassageAbuse) ||
			errors.Is(err, protocol.ErrReplayAttack) {
			log.Warn("handleConn: %v", err)
		} else {
			log.Info("handleConn: %v", err)
		}
		return err
	}
	return nil
}

func (g Server) TunDatagram(datagramServer proto.GunService_TunDatagramServer) error {
	return nil
}
