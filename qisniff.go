package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"os"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/tcpassembly"
)

type pktID struct {
	srcIP   string
	dstIP   string
	srcPort layers.TCPPort
	dstPort layers.TCPPort
	proto   layers.IPProtocol
	seq     uint32
}

func (p pktID) String() string {
	return fmt.Sprintf("%v:%v->%v:%v %v", hex.EncodeToString([]byte(p.srcIP)), p.srcPort, hex.EncodeToString([]byte(p.dstIP)), p.dstPort, p.seq)
}

type pktData struct {
	sum  uint32
	load gopacket.Payload
	time int64
	pkt  gopacket.Packet
}

type stream struct{}

func (s *stream) Reassembled(rea []tcpassembly.Reassembly) {
	for _, r := range rea {
		fmt.Print(string(r.Bytes))
	}
}

func (s *stream) ReassemblyComplete() {
	fmt.Println("done!")
}

type streamFactory struct{}

func (s *streamFactory) New(netFlow, tcpFlow gopacket.Flow) tcpassembly.Stream {
	return &stream{}
}

func main() {
	file := flag.String("file", "", "What file to parse")

	flag.Parse()

	if *file == "" {
		flag.Usage()
		os.Exit(1)
	}

	var (
		eth     layers.Ethernet
		ip4     layers.IPv4
		ip6     layers.IPv6
		tcp     layers.TCP
		payload gopacket.Payload
		decoded []gopacket.LayerType
	)

	h, err := pcap.OpenOffline(*file)
	if err != nil {
		panic(err)
	}
	source := gopacket.NewPacketSource(h, h.LinkType())
	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &eth, &ip4, &ip6, &tcp, &payload)

	assemblers := map[gopacket.Flow]*tcpassembly.Assembler{}
	pool := tcpassembly.NewStreamPool(&streamFactory{})

	for pkt := range source.Packets() {
		if err := parser.DecodeLayers(pkt.Data(), &decoded); err != nil {
			panic(err)
		}
		isTCP := false
		for _, typ := range decoded {
			if typ == layers.LayerTypeTCP {
				isTCP = true
			}
		}
		if isTCP {
			flow := tcp.TransportFlow()
			ass, found := assemblers[flow]
			if !found {
				ass = tcpassembly.NewAssembler(pool)
				assemblers[flow] = ass
			}
			ass.Assemble(flow, &tcp)
		}
	}
}
