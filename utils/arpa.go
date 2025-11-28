package utils

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"
)

var hexDigit = "0123456789abcdef"

func ConvertAddrToArpa(addr netip.Addr) string {
	switch {
	case addr.Is6():
		b := addr.As16()
		const template = "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.B.D.0.1.0.0.2.ip6.arpa"
		var a [len(template)]byte
		copy(a[:], template)

		// i - index into the output
		i := 0
		// j - index into b (16 byte IPv6 address)
		j := len(b) - 1
		for range len(b) {
			a[i] = hexDigit[b[j]&0xf]
			a[i+2] = hexDigit[b[j]>>4]
			i += 4
			j -= 1
		}
		return string(a[:])
	case addr.Is4():
		b := addr.As4()
		return fmt.Sprintf("%d.%d.%d.%d.in-addr.arpa", b[3], b[2], b[1], b[0])
	default:
		return ""
	}
}

var errInvalidArpa = errors.New("invalid arpa domain name")

func ParseArpaToPrefix(arpa string) (netip.Prefix, error) {
	if addr, cut := strings.CutSuffix(arpa, ".in-addr.arpa"); cut {
		segments := strings.SplitN(addr, ".", 5)
		if len(segments) < 1 || len(segments) > 4 {
			return netip.Prefix{}, errInvalidArpa
		}

		// 1->8, 2->16, 3->24, 4->32
		bits := uint8(len(segments) * 8)

		// Process custom prefixes
		lastOctet := strings.SplitN(segments[0], "_", 3)
		switch len(lastOctet) {
		case 1:
			break
		case 2:
			// Remove the prefix from the segment
			segments[0] = lastOctet[0]
			bitInt, err := strconv.ParseUint(lastOctet[1], 10, 8)
			if err != nil {
				return netip.Prefix{}, err
			}
			bits = uint8(bitInt)
		default:
			return netip.Prefix{}, errInvalidArpa
		}
		slices.Reverse(segments)
		for len(segments) < 4 {
			segments = append(segments, "0")
		}

		// Try to parse the formed CIDR prefix
		return netip.ParsePrefix(strings.Join(segments, ".") + "/" + strconv.FormatUint(uint64(bits), 10))
	}
	if addr, cut := strings.CutSuffix(arpa, ".ip6.arpa"); cut {
		segments := strings.SplitN(addr, ".", 33)
		if len(segments) < 1 || len(segments) > 32 {
			return netip.Prefix{}, errInvalidArpa
		}

		// 1->4, 2->8, 3->12, 4->16
		bits := uint8(len(segments) * 4)

		// Process custom prefixes
		lastHex := strings.SplitN(segments[0], "_", 3)
		switch len(lastHex) {
		case 1:
			break
		case 2:
			// Remove the prefix from the segment
			segments[0] = lastHex[0]
			bitInt, err := strconv.ParseUint(lastHex[1], 10, 8)
			if err != nil {
				return netip.Prefix{}, err
			}
			bits = uint8(bitInt)
		default:
			return netip.Prefix{}, errInvalidArpa
		}
		slices.Reverse(segments)
		for len(segments) < 32 {
			segments = append(segments, "0")
		}

		// Ensure segments are 1 char long and can be mostly merged together into 16-bit parts
		if slices.ContainsFunc(segments, func(s string) bool {
			return len(s) != 1
		}) {
			return netip.Prefix{}, errInvalidArpa
		}

		// Merge 4 hex chars into a 16-bit part
		var hextets [8]string
		j := 0
		for i := 0; i < len(segments); i += 4 {
			hextets[j] = strings.Join(segments[i:i+4], "")
			j++
		}

		// Try to parse the formed CIDR prefix
		return netip.ParsePrefix(strings.Join(hextets[:], ":") + "/" + strconv.FormatUint(uint64(bits), 10))
	}
	return netip.Prefix{}, errInvalidArpa
}
