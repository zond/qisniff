package main

import (
	"bytes"
	"github.com/google/gopacket/layers"
	"net"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"time"
	"encoding/hex"
	"fmt"
	"os"
	"flag"
)

type pktID struct {
	srcIP string
	dstIP string
	srcPort layers.TCPPort
	dstPort layers.TCPPort
	proto layers.IPProtocol
	seq uint32
}

func (p pktID) String() string {
	return fmt.Sprintf("%v:%v->%v:%v %v", hex.EncodeToString([]byte(p.srcIP)), p.srcPort, hex.EncodeToString([]byte(p.dstIP)), p.dstPort, p.seq)
}

type pktData struct {
	sum uint32
	load gopacket.Payload
	time int64
	pkt gopacket.Packet
}

func main() {
	var (
	 	eth layers.Ethernet
	 	ip4 layers.IPv4
  	 	ip6 layers.IPv6
  	 	tcp layers.TCP
	 	srcIP net.IP
	 	dstIP net.IP
	 	srcPort layers.TCPPort
	 	dstPort layers.TCPPort
	 	proto layers.IPProtocol
	 	seq uint32
		tcpPayload []byte
	 	payload gopacket.Payload
	)

	assemblers := map[gopacket.Flow]*tcpassembly.Assembler{}

	file := flag.String("file", "", "What file to parse")

	flag.Parse()

	if *file == "" {
		flag.Usage()
		os.Exit(1)
	}

	h, err := pcap.OpenOffline(*file)
	if err != nil {
		panic(err)
	}
	source := gopacket.NewPacketSource(h, h.LinkType())
	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &eth, &ip4, &ip6, &tcp, &payload)
	decoded := []gopacket.LayerType{}

	pks := map[pktID]pktData{}

	for pkt := range source.Packets() {
		if err := parser.DecodeLayers(pkt.Data(), &decoded); err != nil {
			panic(err)
		}
		isTCP := false
		for _, typ := range decoded {
			switch typ {
            		case layers.LayerTypeIPv4:
				srcIP = ip4.SrcIP
				dstIP = ip4.DstIP
				proto = ip4.Protocol
            		case layers.LayerTypeIPv6:
				srcIP = ip6.SrcIP
				dstIP = ip6.DstIP
				proto = 0
            		case layers.LayerTypeTCP:
				tcpPayload = tcp.Payload
				srcPort = tcp.SrcPort
				dstPort = tcp.DstPort
				seq = tcp.Seq
				isTCP = true
			}
		}
		if isTCP && len(tcpPayload) > 0 {
			id := pktID{
				srcIP: string(srcIP),
				dstIP: string(dstIP),
				srcPort: srcPort,
				dstPort: dstPort,
				proto: proto,
				seq: seq,
			}
			data := pktData{
				load: tcpPayload,
				time: pkt.Metadata().Timestamp.UnixNano(),
				pkt: pkt,
			}
			foundData, found := pks[id]
			if found {
				min := len(foundData.load)
				if len(data.load) < min {
					min = len(data.load)
				}
				if found && bytes.Compare(foundData.load[:min], data.load[:min]) != 0 { 
					fmt.Printf("suspicious packet %v: old sum %v, new sum %v, %v apart\n%v\n%v\n", id, foundData.sum, data.sum, time.Duration(data.time - foundData.time), foundData.pkt, pkt)
				}
			}
			pks[id] = data
			flow := tcp.transportFlow()
			ass, found := flows[flow]
			if !found {
				ass = 
		}
	}
}
