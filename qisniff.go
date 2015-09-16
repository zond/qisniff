package main

import (
	"bytes"
	"encoding/hex"
	"flag"
	"fmt"
	"io/ioutil"
	"math"
	"net"
	"os"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/zond/qisniff/blocks"
)

var files []string

type diff struct {
	a []byte
	b []byte
}

type diffs []diff

type streamID struct {
	srcIP   string
	dstIP   string
	srcPort layers.TCPPort
	dstPort layers.TCPPort
}

func (i streamID) String() string {
	return fmt.Sprintf("%v:%v->%v:%v", hex.EncodeToString([]byte(i.srcIP)), i.srcPort, hex.EncodeToString([]byte(i.dstIP)), i.dstPort)
}

type stream struct {
	id      *streamID
	f       *os.File
	offset  int64
	lastSeq uint32
	done    blocks.Blocks
	diffs   diffs
}

func newStream(id *streamID, seq uint32) (*stream, error) {
	f, err := ioutil.TempFile(os.TempDir(), "qisniff")
	if err != nil {
		return nil, err
	}
	files = append(files, f.Name())
	return &stream{
		id:      id,
		f:       f,
		offset:  -int64(seq),
		lastSeq: seq,
	}, nil
}

func (s *stream) write(tcp *layers.TCP) error {

	if (tcp.SYN || tcp.FIN) && len(tcp.Payload) == 0 {
		s.offset--
	}

	if s.lastSeq > (math.MaxUint32-math.MaxUint32/4) && tcp.Seq < math.MaxUint32/4 {
		s.offset += math.MaxUint32
	}

	a := s.offset + int64(tcp.Seq)
	b := a + int64(len(tcp.Payload))

	if b > a {

		if s.done.Overlaps(a, b) {
			previous := make([]byte, b-a)
			if _, err := s.f.Seek(a, 0); err != nil {
				return err
			}
			if _, err := s.f.Read(previous); err != nil {
				return err
			}
			if bytes.Compare(previous, tcp.Payload) != 0 {
				s.diffs = append(s.diffs, diff{previous, tcp.Payload})
			}
		}

		if _, err := s.f.Seek(a, 0); err != nil {
			return fmt.Errorf("Seek(%v, 0): %v", a, err)
		}

		if _, err := s.f.Write(tcp.Payload); err != nil {
			return fmt.Errorf("Write(%v): %v", tcp.Payload, err)
		}

		s.done = s.done.Add(a, b)

	}

	return nil
}

func removeFiles() {
	for _, file := range files {
		os.Remove(file)
	}
}

func main() {
	defer removeFiles()

	file := flag.String("file", "", "A file to parse")

	flag.Parse()

	if *file == "" {
		flag.Usage()
		os.Exit(1)
	}

	var (
		srcIP net.IP
		dstIP net.IP
		eth   layers.Ethernet
		ip4   layers.IPv4
		ip6   layers.IPv6
		tcp   layers.TCP
		//	netLayer gopacket.NetworkLayer
		payload gopacket.Payload
		//tcpFrame []byte
		decoded []gopacket.LayerType
		isTCP   bool
	)

	h, err := pcap.OpenOffline(*file)
	if err != nil {
		panic(err)
	}
	source := gopacket.NewPacketSource(h, h.LinkType())
	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &eth, &ip4, &ip6, &tcp, &payload)
	streams := map[streamID]*stream{}

	for pkt := range source.Packets() {
		if err := parser.DecodeLayers(pkt.Data(), &decoded); err != nil {
			continue
		}
		isTCP = false
		for _, typ := range decoded {
			switch typ {
			case layers.LayerTypeIPv4:
				srcIP = ip4.SrcIP
				dstIP = ip4.DstIP
				//netLayer = &ip4
				//tcpFrame = ip4.Payload
			case layers.LayerTypeIPv6:
				srcIP = ip6.SrcIP
				dstIP = ip6.DstIP
				//tcpFrame = ip6.Payload
				//netLayer = &ip6
			case layers.LayerTypeTCP:
				isTCP = true
			}
		}
		if isTCP {
			/*
				calcSum := sum.SumTCP(netLayer, tcpFrame)

				fmt.Println(calcSum, tcp.Checksum)
			*/
			id := &streamID{
				srcIP:   string(srcIP),
				dstIP:   string(dstIP),
				srcPort: tcp.SrcPort,
				dstPort: tcp.DstPort,
			}

			stream, found := streams[*id]
			if found || tcp.SYN {
				if tcp.SYN {
					if stream, err = newStream(id, tcp.Seq); err != nil {
						panic(err)
					}
					streams[*id] = stream
				}
				if err := stream.write(&tcp); err != nil {
					panic(err)
				}
			}
		}
	}
	for id, stream := range streams {
		if len(stream.diffs) > 0 {
			fmt.Printf("Stream %v has diffs:\n", id)
			for _, diff := range stream.diffs {
				fmt.Printf("<A>\n%s\n</A>\n<B>\n%s\n</B>\n", string(diff.a), string(diff.b))
			}
		}
	}
}
