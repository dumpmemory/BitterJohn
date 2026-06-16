package anytls

import (
	"bytes"
	"testing"
)

func TestSocksAddrRoundTripDomain(t *testing.T) {
	var buf bytes.Buffer
	if err := writeSocksAddr(&buf, "example.com:443"); err != nil {
		t.Fatal(err)
	}

	addr, err := readSocksAddr(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := addr.String(), "example.com:443"; got != want {
		t.Fatalf("addr = %q, want %q", got, want)
	}
}

func TestSocksAddrRoundTripIPv6(t *testing.T) {
	var buf bytes.Buffer
	if err := writeSocksAddr(&buf, "[2001:db8::1]:8443"); err != nil {
		t.Fatal(err)
	}

	addr, err := readSocksAddr(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := addr.String(), "[2001:db8::1]:8443"; got != want {
		t.Fatalf("addr = %q, want %q", got, want)
	}
}
