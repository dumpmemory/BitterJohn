package e2e

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/daeuniverse/softwind/netproxy"
	"github.com/daeuniverse/softwind/protocol"
	"github.com/daeuniverse/softwind/protocol/direct"
	bjserver "github.com/e14914c0-6759-480d-be89-66b7b7676451/BitterJohn/server"
	anytlsserver "github.com/e14914c0-6759-480d-be89-66b7b7676451/BitterJohn/server/anytls"
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/SweetLisa/model"
)

const (
	anyTLSImage    = "jonnyan404/anytls:latest"
	anyTLSPassword = "bitterjohn-e2e-password"
)

func TestAnyTLSOfficialServerWithBitterJohnClientTCP(t *testing.T) {
	requireAnyTLSE2E(t)

	echoAddr, closeEcho := startTCPEcho(t)
	t.Cleanup(closeEcho)

	container := runAnyTLSServerContainer(t, anyTLSPassword)

	tests := []struct {
		name      string
		configure func(*protocol.Header)
	}{
		{
			name: "default tls config",
		},
		{
			name: "explicit sni",
			configure: func(header *protocol.Header) {
				header.SNI = "edge.example.com"
			},
		},
		{
			name: "custom tls config",
			configure: func(header *protocol.Header) {
				header.TlsConfig = &tls.Config{
					MinVersion:         tls.VersionTLS12,
					ServerName:         "custom.example.com",
					InsecureSkipVerify: true,
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			header := protocol.Header{
				ProxyAddress: container.Addr,
				Password:     anyTLSPassword,
				IsClient:     true,
			}
			if tt.configure != nil {
				tt.configure(&header)
			}
			dialer, err := anytlsserver.NewDialer(direct.SymmetricDirect, header)
			if err != nil {
				t.Fatal(err)
			}
			if closer, ok := dialer.(interface{ Close() error }); ok {
				t.Cleanup(func() { _ = closer.Close() })
			}

			conn, err := dialer.Dial("tcp", echoAddr)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()

			assertPingPong(t, conn)
		})
	}
}

func TestAnyTLSOfficialServerWithBitterJohnClientUDP(t *testing.T) {
	requireAnyTLSE2E(t)

	echoAddr, closeEcho := startUDPEcho(t)
	t.Cleanup(closeEcho)

	container := runAnyTLSServerContainer(t, anyTLSPassword)

	dialer, err := anytlsserver.NewDialer(direct.SymmetricDirect, protocol.Header{
		ProxyAddress: container.Addr,
		Password:     anyTLSPassword,
		IsClient:     true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if closer, ok := dialer.(interface{ Close() error }); ok {
		t.Cleanup(func() { _ = closer.Close() })
	}

	conn, err := dialer.Dial("udp", echoAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	packetConn := conn.(netproxy.PacketConn)
	if _, err := packetConn.WriteTo([]byte("ping"), echoAddr); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4)
	if _, _, err := packetConn.ReadFrom(buf); err != nil {
		t.Fatal(err)
	}
	if got := string(buf); got != "pong" {
		t.Fatalf("UDP response = %q, want pong", got)
	}
}

func TestAnyTLSBitterJohnServerWithOfficialClientTCP(t *testing.T) {
	requireAnyTLSE2E(t)

	echoAddr, closeEcho := startTCPEcho(t)
	t.Cleanup(closeEcho)

	serverAddr := startBitterJohnAnyTLSServer(t, anyTLSPassword)
	containerServerAddr := hostDockerInternalAddress(serverAddr)

	tests := []struct {
		name string
		args []string
	}{
		{
			name: "flags",
			args: []string{"-s", containerServerAddr, "-p", anyTLSPassword},
		},
		{
			name: "uri with sni",
			args: []string{"-s", fmt.Sprintf("anytls://%s@%s/?sni=edge.example.com", anyTLSPassword, containerServerAddr)},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			container := runAnyTLSClientContainer(t, tt.args...)
			socksAddr := container.MappedAddress(t, "1080/tcp")

			conn, err := dialSOCKS5TCP(context.Background(), socksAddr, echoAddr)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()

			assertPingPong(t, conn)
		})
	}
}

func waitForTCP(t *testing.T, addr string, timeout time.Duration) {
	t.Helper()

	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for TCP listener at %s", addr)
}

func requireAnyTLSE2E(t *testing.T) {
	t.Helper()

	if os.Getenv("BITTERJOHN_E2E") != "1" {
		t.Skip("set BITTERJOHN_E2E=1 to run Docker e2e tests")
	}
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skipf("docker not found: %v", err)
	}
	if err := exec.Command("docker", "info").Run(); err != nil {
		t.Skipf("docker is not available: %v", err)
	}
}

type dockerContainer struct {
	ID string
}

type anyTLSServerContainer struct {
	dockerContainer
	Addr string
}

func runAnyTLSServerContainer(t *testing.T, password string) anyTLSServerContainer {
	t.Helper()

	addr := net.JoinHostPort("127.0.0.1", reserveTCPPort(t))
	id := dockerOutput(t,
		"run", "--rm", "-d",
		"--network", "host",
		"-e", "LOG_LEVEL=debug",
		anyTLSImage,
		"/app/anytls-server",
		"-l", addr,
		"-p", password,
	)
	container := dockerContainer{ID: strings.TrimSpace(id)}
	t.Cleanup(func() {
		if t.Failed() {
			time.Sleep(500 * time.Millisecond)
			t.Logf("anytls server container logs:\n%s", dockerCombinedOutput(t, "logs", container.ID))
		}
		_ = exec.Command("docker", "rm", "-f", container.ID).Run()
	})
	waitForTCP(t, addr, 20*time.Second)
	return anyTLSServerContainer{dockerContainer: container, Addr: addr}
}

func runAnyTLSClientContainer(t *testing.T, clientArgs ...string) dockerContainer {
	t.Helper()

	args := []string{
		"run", "--rm", "-d",
		"--add-host=host.docker.internal:host-gateway",
		"-e", "LOG_LEVEL=debug",
		"-p", "127.0.0.1::1080",
		anyTLSImage,
		"/app/anytls-client",
		"-l", "0.0.0.0:1080",
	}
	args = append(args, clientArgs...)
	id := dockerOutput(t, args...)
	container := dockerContainer{ID: strings.TrimSpace(id)}
	t.Cleanup(func() {
		if t.Failed() {
			time.Sleep(500 * time.Millisecond)
			t.Logf("anytls client container logs:\n%s", dockerCombinedOutput(t, "logs", container.ID))
		}
		_ = exec.Command("docker", "rm", "-f", container.ID).Run()
	})
	waitForTCP(t, container.MappedAddress(t, "1080/tcp"), 20*time.Second)
	return container
}

func (c dockerContainer) MappedAddress(t *testing.T, containerPort string) string {
	t.Helper()

	deadline := time.Now().Add(10 * time.Second)
	var last string
	for time.Now().Before(deadline) {
		last = dockerOutput(t, "port", c.ID, containerPort)
		for _, line := range strings.Split(strings.TrimSpace(last), "\n") {
			line = strings.TrimSpace(line)
			if line != "" {
				return line
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("container %s has no mapped address for %s; last output: %s", c.ID, containerPort, last)
	return ""
}

func dockerOutput(t *testing.T, args ...string) string {
	t.Helper()

	cmd := exec.Command("docker", args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("docker %s failed: %v\nstderr:\n%s", strings.Join(args, " "), err, stderr.String())
	}
	return string(out)
}

func dockerCombinedOutput(t *testing.T, args ...string) string {
	t.Helper()

	out, err := exec.Command("docker", args...).CombinedOutput()
	if err != nil {
		t.Fatalf("docker %s failed: %v\noutput:\n%s", strings.Join(args, " "), err, string(out))
	}
	return string(out)
}

func startBitterJohnAnyTLSServer(t *testing.T, password string) string {
	t.Helper()

	port := reserveTCPPort(t)
	listenAddr := net.JoinHostPort("0.0.0.0", port)
	hostAddr := net.JoinHostPort("127.0.0.1", port)
	srv, err := anytlsserver.New(context.Background(), direct.SymmetricDirect)
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.AddPassages([]bjserver.Passage{{
		Passage: model.Passage{
			In: model.In{Argument: model.Argument{
				Protocol: bjserver.ProtocolAnyTLS,
				Password: password,
			}},
		},
	}}); err != nil {
		t.Fatal(err)
	}

	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.Listen(listenAddr)
	}()
	t.Cleanup(func() {
		_ = srv.Close()
	})
	waitForTCP(t, hostAddr, 5*time.Second)
	select {
	case err := <-errCh:
		t.Fatalf("BitterJohn anytls server exited early: %v", err)
	default:
	}
	return hostAddr
}

func reserveTCPPort(t *testing.T) string {
	t.Helper()

	lt, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := lt.Addr().String()
	if err := lt.Close(); err != nil {
		t.Fatal(err)
	}
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	return port
}

func startTCPEcho(t *testing.T) (string, func()) {
	t.Helper()

	lt, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	_, port, err := net.SplitHostPort(lt.Addr().String())
	if err != nil {
		_ = lt.Close()
		t.Fatal(err)
	}
	addr := net.JoinHostPort("127.0.0.1", port)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := lt.Accept()
			if err != nil {
				return
			}
			go serveTCPEcho(conn)
		}
	}()
	return addr, func() {
		_ = lt.Close()
		<-done
	}
}

func serveTCPEcho(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	buf := make([]byte, 4)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return
	}
	if string(buf) == "ping" {
		_, _ = conn.Write([]byte("pong"))
	}
}

func startUDPEcho(t *testing.T) (string, func()) {
	t.Helper()

	conn, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(netip.MustParseAddrPort("0.0.0.0:0")))
	if err != nil {
		t.Fatal(err)
	}
	_, port, err := net.SplitHostPort(conn.LocalAddr().String())
	if err != nil {
		_ = conn.Close()
		t.Fatal(err)
	}
	addr := net.JoinHostPort("127.0.0.1", port)
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 1500)
		for {
			n, addr, err := conn.ReadFromUDPAddrPort(buf)
			if err != nil {
				return
			}
			if string(buf[:n]) == "ping" {
				_, _ = conn.WriteToUDPAddrPort([]byte("pong"), addr)
			}
		}
	}()
	return addr, func() {
		_ = conn.Close()
		<-done
	}
}

type rwConn interface {
	io.Reader
	io.Writer
}

func assertPingPong(t *testing.T, conn rwConn) {
	t.Helper()

	if d, ok := conn.(interface{ SetDeadline(time.Time) error }); ok {
		_ = d.SetDeadline(time.Now().Add(10 * time.Second))
	}
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	resp := make([]byte, 4)
	if _, err := io.ReadFull(conn, resp); err != nil {
		t.Fatal(err)
	}
	if got := string(resp); got != "pong" {
		t.Fatalf("TCP response = %q, want pong", got)
	}
}

func hostDockerInternalAddress(addr string) string {
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		panic(err)
	}
	return net.JoinHostPort("host.docker.internal", port)
}

func dialSOCKS5TCP(ctx context.Context, socksAddr string, targetAddr string) (net.Conn, error) {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", socksAddr)
	if err != nil {
		return nil, err
	}
	if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		_ = conn.Close()
		return nil, err
	}
	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		_ = conn.Close()
		return nil, err
	}
	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil {
		_ = conn.Close()
		return nil, err
	}
	if resp[0] != 0x05 || resp[1] != 0x00 {
		_ = conn.Close()
		return nil, fmt.Errorf("unexpected socks auth response: %v", resp)
	}
	req, err := socks5ConnectRequest(targetAddr)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	if _, err := conn.Write(req); err != nil {
		_ = conn.Close()
		return nil, err
	}
	if err := readSOCKS5ConnectResponse(conn); err != nil {
		_ = conn.Close()
		return nil, err
	}
	_ = conn.SetDeadline(time.Time{})
	return conn, nil
}

func socks5ConnectRequest(targetAddr string) ([]byte, error) {
	host, strPort, err := net.SplitHostPort(targetAddr)
	if err != nil {
		return nil, err
	}
	port, err := strconv.ParseUint(strPort, 10, 16)
	if err != nil {
		return nil, err
	}

	req := []byte{0x05, 0x01, 0x00}
	if ip, err := netip.ParseAddr(host); err == nil {
		if ip.Is4() {
			req = append(req, 0x01)
			req = append(req, ip.AsSlice()...)
		} else {
			req = append(req, 0x04)
			req = append(req, ip.AsSlice()...)
		}
	} else {
		if len(host) > 255 {
			return nil, fmt.Errorf("SOCKS5 domain too long: %s", host)
		}
		req = append(req, 0x03, byte(len(host)))
		req = append(req, host...)
	}
	return binary.BigEndian.AppendUint16(req, uint16(port)), nil
}

func readSOCKS5ConnectResponse(conn net.Conn) error {
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return err
	}
	if header[0] != 0x05 {
		return fmt.Errorf("unexpected socks version: %d", header[0])
	}
	if header[1] != 0x00 {
		return fmt.Errorf("socks connect failed with code %d", header[1])
	}
	var addrLen int
	switch header[3] {
	case 0x01:
		addrLen = 4
	case 0x04:
		addrLen = 16
	case 0x03:
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			return err
		}
		addrLen = int(lenBuf[0])
	default:
		return fmt.Errorf("unexpected socks address type: %d", header[3])
	}
	if _, err := io.CopyN(io.Discard, conn, int64(addrLen+2)); err != nil {
		return err
	}
	return nil
}
