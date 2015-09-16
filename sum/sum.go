package sum

import (
	"encoding/binary"
	"fmt"
	"math"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func tcpipChecksum(b []byte, sum uint32) uint16 {
	for i := 0; i < len(b)-1; i += 2 {
		sum += uint32(binary.LittleEndian.Uint16(b[i:]))
	}
	if len(b)&1 == 1 {
		sum += uint32(b[len(b)-1])
	}
	for sum > math.MaxUint16 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

func pseudoheaderChecksum4(ip *layers.IPv4) (csum uint32, err error) {
	if err := ip.AddressTo4(); err != nil {
		return 0, err
	}
	csum += (uint32(ip.SrcIP[0]) + uint32(ip.SrcIP[2])) << 8
	csum += uint32(ip.SrcIP[1]) + uint32(ip.SrcIP[3])
	csum += (uint32(ip.DstIP[0]) + uint32(ip.DstIP[2])) << 8
	csum += uint32(ip.DstIP[1]) + uint32(ip.DstIP[3])
	return csum, nil
}

func pseudoheaderChecksum6(ip *layers.IPv6) (csum uint32, err error) {
	if err := ip.AddressTo16(); err != nil {
		return 0, err
	}
	for i := 0; i < 16; i += 2 {
		csum += uint32(ip.SrcIP[i]) << 8
		csum += uint32(ip.SrcIP[i+1])
		csum += uint32(ip.DstIP[i]) << 8
		csum += uint32(ip.DstIP[i+1])
	}
	return csum, nil
}

func SumTCP(net gopacket.NetworkLayer, data []byte) uint16 {
	length := uint32(len(data))
	var csum uint32
	var err error
	switch v := net.(type) {
	case *layers.IPv4:
		if csum, err = pseudoheaderChecksum4(v); err != nil {
			panic(err)
		}
	case *layers.IPv6:
		if csum, err = pseudoheaderChecksum6(v); err != nil {
			panic(err)
		}
	default:
		panic(fmt.Errorf("Unrecognized network layer %v", net))
	}
	csum += uint32(layers.IPProtocolTCP)
	csum += length & 0xffff
	csum += length >> 16
	return tcpipChecksum(data, csum)
}
