package dhcp6rd

import (
	"bytes"
	"fmt"
	"net"
	"testing"
)

func TestMarshalDhclient(t *testing.T) {
	b := "0 32 8193 3512 0 0 0 0 0 0 192.0.2.1"
	opt, err := UnmarshalDhclient(b)
	if err != nil {
		t.Fatal(err)
	}

	addr := net.ParseIP("192.0.2.200")
	net, err := opt.IPNet(addr)
	if err != nil {
		t.Fatal(err)
	}

	if opt.Prefix.String() != "2001:db8::" {
		t.Fatal("%v != 2001:db8::", opt.Prefix.String())
	}

	if net.String() != "2001:db8:c000:2c8::/64" {
		t.Fatal("%v != 2001:db8:c000:2c8::/64", net.String())
	}

	if ones, size := net.Mask.Size(); ones != 64 || size != 128 {
		t.Fatal("Mask size is incorrect, %v should be 64, %v should be 128", ones, size)
	}

}

func TestMarshalDhclientShort(t *testing.T) {
	b := "0 32 2001:db8:: 192.0.2.1"
	opt, err := UnmarshalDhclient(b)
	if err != nil {
		t.Fatal(err)
	}

	addr := net.ParseIP("192.0.2.200")
	net, err := opt.IPNet(addr)
	if err != nil {
		t.Fatal(err)
	}

	if opt.Prefix.String() != "2001:db8::" {
		t.Fatal("%v != 2001:db8::", opt.Prefix.String())
	}

	if net.String() != "2001:db8:c000:2c8::/64" {
		t.Fatal("%v != 2001:db8:c000:2c8::/64", net.String())
	}

	if ones, size := net.Mask.Size(); ones != 64 || size != 128 {
		t.Fatal("Mask size is incorrect, %v should be 64, %v should be 128", ones, size)
	}
}

func TestMarshal(t *testing.T) {
	b := []byte{
		12, 36,
		0x20, 0x01, 0x0d, 0xb8,
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

	if net.String() != "2001:db8:fe01:200::/56" {
		t.Fail()
	}

}

func TestMarshalMultipleRelay(t *testing.T) {
	// srd_masklen, srd_prefixlen, srd_prefix, br_addr
	b := []byte{
		12, 36,
		0x20, 0x01, 0x0d, 0xb8,
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
