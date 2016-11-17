package dhcp6rd

import (
	"bytes"
	"fmt"
	"net"
	"testing"
)

func TestMarshalDhclient(t *testing.T) {
	b := "0 32 8193 8194 0 0 0 0 0 0 217.209.228.166"
	opt, err := UnmarshalDhclient(b)
	if err != nil {
		t.Fatal(err)
	}

	if opt.MarshalDhclient() != b {
		t.Fail()
	}

	addr := net.ParseIP("212.113.65.123")
	net, err := opt.IPNet(addr)
	if err != nil {
		t.Fatal(err)
	}

	if net.String() != "2001:2002:d471:417b::/64" {
		t.Fail()
	}

}

func TestMarshal(t *testing.T) {
	b := []byte{
		12, 36,
		0x20, 0x01, 0x20, 0x02,
		0xf0, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x0a, 0xfe, 0x01, 0x01}

	opt, err := Unmarshal(b)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(opt.Marshal(), b) {
		fmt.Printf("%v != %v", opt.Marshal(), b)
		t.Fail()
	}

	addr := net.ParseIP("10.254.1.2")
	net, err := opt.IPNet(addr)
	if err != nil {
		t.Fatal(err)
	}

	if net.String() != "2001:2002:fe01:200::/56" {
		t.Fail()
	}

}

func TestMarshalMultipleRelay(t *testing.T) {
	// srd_masklen, srd_prefixlen, srd_prefix, br_addr
	b := []byte{
		12, 36,
		0x20, 0x01, 0x20, 0x02,
		0xf0, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x0a, 0xfe, 0x01, 0x01,
		0x0a, 0xfe, 0x01, 0x02}

	opt, err := Unmarshal(b)
	if err != nil {
		t.Fatal(err)
	}

	if len(opt.Relay) != 2 {
		fmt.Printf("Number of relay doesn't match: %v", opt.Relay)
		t.Fail()
	}

	if !bytes.Equal(opt.Marshal(), b) {
		fmt.Printf("%v != %v", opt.Marshal(), b)
		t.Fail()
	}

}
