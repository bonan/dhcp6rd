package dhcp6rd

import (
	"errors"
	"net"
	"strconv"
	"strings"
)

// Option6RD contains the parsed values for the 6RD DHCP Option
type Option6RD struct {
	MaskLen   int
	Prefix    net.IP
	PrefixLen int
	Relay     []net.IP
}

// IPNet returns the 6rd-prefix that should be used for argument ip
func (o *Option6RD) IPNet(ip net.IP) (*net.IPNet, error) {
	// Make sure that the argument is a valid IPv4 address
	ip4 := ip.To4()
	if ip4 == nil {
		return nil, errors.New("Address is not in IPv4 format")
	}

	ip6mask := net.CIDRMask(o.PrefixLen, 128)
	ip6 := make(net.IP, 16)
	copy(ip6, o.Prefix)

	// Ignore non-zero values in host part of prefix
	for i, v := range ip6 {
		ip6[i] = v & ip6mask[i]
	}

	cur6 := o.PrefixLen
	cur4 := o.MaskLen

	// Iterate over the IPv4 address, starting from the masklen position
	for cur4 < 32 {
		// isolate the current bit
		b4 := ip4[cur4/8] & (0x80 >> uint(cur4%8))

		// OR the current bit with ipv6 prefix
		ip6[cur6/8] = ip6[cur6/8] | b4

		cur6 = cur6 + 1
		cur4 = cur4 + 1
	}

	return &net.IPNet{
		Mask: net.CIDRMask(o.PrefixLen+32-o.MaskLen, 128),
		IP:   ip6}, nil
}

// Marshal returns the 6RD DHCP Option in byte format
func (o *Option6RD) Marshal() []byte {
	ret := []byte{byte(o.MaskLen), byte(o.PrefixLen)}
	ret = append(ret, o.Prefix...)
	for _, v := range o.Relay {
		ret = append(ret, v.To4()...)
	}
	return ret
}

// MarshalDhclient returns the 6RD DHCP Option in dhclient-format
func (o *Option6RD) MarshalDhclient() string {
	str := strconv.Itoa(o.MaskLen) + " " +
		strconv.Itoa(o.PrefixLen) + " " +
		strconv.Itoa(int(o.Prefix[0])<<8+int(o.Prefix[1])) + " " +
		strconv.Itoa(int(o.Prefix[2])<<8+int(o.Prefix[3])) + " " +
		strconv.Itoa(int(o.Prefix[4])<<8+int(o.Prefix[5])) + " " +
		strconv.Itoa(int(o.Prefix[6])<<8+int(o.Prefix[7])) + " " +
		strconv.Itoa(int(o.Prefix[8])<<8+int(o.Prefix[9])) + " " +
		strconv.Itoa(int(o.Prefix[10])<<8+int(o.Prefix[11])) + " " +
		strconv.Itoa(int(o.Prefix[12])<<8+int(o.Prefix[13])) + " " +
		strconv.Itoa(int(o.Prefix[14])<<8+int(o.Prefix[15]))
	for _, v := range o.Relay {
		str = str + " " + v.String()
	}
	return str
}

// Unmarshal parses the raw 6RD DHCP Option and returns a Option6RD struct
func Unmarshal(b []byte) (*Option6RD, error) {
	if len(b) < 18 {
		return nil, errors.New("Unable to parse 6RD DHCP Option (not enough bytes)")
	}
	o := &Option6RD{
		MaskLen:   int(b[0]),
		PrefixLen: int(b[1]),
		Prefix:    b[2:18],
		Relay:     []net.IP{}}
	p := b[18:]
	for len(p) > 0 {
		o.Relay = append(o.Relay, p[0:4])
		p = p[4:]
	}

	return o, nil
}

// UnmarshalDhclient parses the 6RD DHCP Option (from dhclient format) and returns a Option6RD struct
func UnmarshalDhclient(s string) (*Option6RD, error) {
	parts := strings.Split(s, " ")
	if len(parts) < 10 {
		return nil, errors.New("Unable to parse 6RD Option (not enough parameters)")
	}
	b := make([]byte, 18)

	maskLen, err := strconv.Atoi(parts[0])
	if err != nil {
		return nil, err
	}

	prefixLen, err := strconv.Atoi(parts[1])
	if err != nil {
		return nil, err
	}
	b[0] = byte(maskLen)
	b[1] = byte(prefixLen)
	for i := 0; i < 8; i++ {
		p, err := strconv.Atoi(parts[i+2])
		if err != nil {
			return nil, err
		}
		b[2+i*2] = byte((p >> 8) & 0xff)
		b[3+i*2] = byte(p & 0xff)
	}
	for i := 10; i < len(parts); i++ {
		ip := net.ParseIP(parts[i])
		b = append(b, ip.To4()...)
	}
	return Unmarshal(b)
}
