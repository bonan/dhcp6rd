package main

import (
	"github.com/bonan/dhcp6rd"
	"log"
	"net"
)

func main() {
	// Parse option 212 received with dhclient
	opt, err := dhcp6rd.UnmarshalDhclient("0 32 2001:db8:: 192.0.2.1")

	if err != nil {
		log.Fatal(err)
	}

	// Get prefix delegation
	net, err := opt.IPNet(net.ParseIP("192.0.2.200"))

	if err != nil {
		log.Fatal(err)
	}

	// Log the prefix delegation
	log.Printf("Usable 6rd prefix: %v\n", net.String())
}
