// Package qilib contains the necessary structs and funcs to create sniffing sessions detecting
// quantum injection attacks.
package qilib

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"math"
	"net"
	"os"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/zond/qisniff/blocks"
)

const (
	cleanInterval = time.Minute * 10
)

// A difference detected.
type Diff struct {
	A   []byte
	B   []byte
	Seq uint32
	ID  StreamID
}

// The public representation of a stream.
type StreamID struct {
	SrcIP   net.IP
	DstIP   net.IP
	SrcPort layers.TCPPort
	DstPort layers.TCPPort
}

func (i StreamID) String() string {
	return fmt.Sprintf("%v:%v->%v:%v", i.SrcIP, i.SrcPort, i.DstIP, i.DstPort)
}

// The internal representation of a stream - uses strings addresses to be hashable.
// Only contains the parts of the 5-tuple that are relevant (we only look at TCP anyway).
type streamID struct {
	srcIP   string
	dstIP   string
	srcPort layers.TCPPort
	dstPort layers.TCPPort
}

func (i streamID) String() string {
	return i.toStreamID().String()
}

func (i streamID) toStreamID() StreamID {
	return StreamID{
		SrcIP:   net.IP(i.srcIP),
		DstIP:   net.IP(i.dstIP),
		SrcPort: i.srcPort,
		DstPort: i.dstPort,
	}
}

// The actual stream.
type stream struct {
	session *Session
	id      *streamID
	f       *os.File
	// What to add to the sequence number to get the byte range this packet affects.
	offset int64
	// The last sequence number, to know when they wrap.
	lastSeq uint32
	// The data we have received so far.
	done       blocks.Blocks
	lastAccess time.Time
}

func newStream(sess *Session, id *streamID, seq uint32) (*stream, error) {
	f, err := ioutil.TempFile(os.TempDir(), "qisniff")
	if err != nil {
		return nil, err
	}
	return &stream{
		session: sess,
		id:      id,
		f:       f,
		offset:  -int64(seq),
		lastSeq: seq,
	}, nil
}

func (s *stream) clean() error {
	if err := s.f.Close(); err != nil {
		return err
	}
	if err := os.Remove(s.f.Name()); err != nil {
		return err
	}
	return nil
}

func (s *stream) write(pkt gopacket.Packet, tcp *layers.TCP) error {

	// Empty SYN and FIN packets will increment the sequence number without incrementing
	// the data pointer, so lets decrement the data pointer ourselves.
	if (tcp.SYN || tcp.FIN) && len(tcp.Payload) == 0 {
		s.offset--
	}

	// If the last sequence number is in the upper quarter of the name space, and the current
	// on in the lower, add the name space size to the offset because now we have wrapped.
	if s.lastSeq > (math.MaxUint32-math.MaxUint32/4) && tcp.Seq < math.MaxUint32/4 {
		s.offset += math.MaxUint32
	}

	// The range this packet writes is defined by its secquence number and length.
	a := s.offset + int64(tcp.Seq)
	b := a + int64(len(tcp.Payload))

	// If it has length, and the packet isn't a one-zero-byte-keepalive packet (length 1, ACK, payload == [0]).
	if b > a && (b-a != 1 || !tcp.ACK || tcp.Payload[0] != 0) {

		// Check if this range is something we have seen before.
		for _, overlap := range s.done.Overlaps(a, b) {
			// Allocate, seek and load the data from our file.
			previous := make([]byte, overlap.B-overlap.A)
			if _, err := s.f.Seek(overlap.A, 0); err != nil {
				return err
			}
			if _, err := s.f.Read(previous); err != nil {
				return err
			}

			// Find the relative indices in this packet to compare this data with.
			relStart := int64(0)
			relEnd := int64(len(tcp.Payload))
			if overlap.A > a {
				relStart += overlap.A - a
			}
			if overlap.B-overlap.A < int64(len(tcp.Payload)) {
				relEnd = relStart + (overlap.B - overlap.A)
			}
			relPayload := tcp.Payload[relStart:relEnd]

			// If they aren't equal, add it to the diffs.
			if bytes.Compare(previous, relPayload) != 0 {
				if s.session.Warning != nil {
					s.session.Warning(pkt, Diff{
						A:   previous,
						B:   relPayload,
						Seq: tcp.Seq,
						ID:  s.id.toStreamID(),
					})
				}
			}
		}

		// Seek and write the data.
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

// The parameters to create a new Session.
type Config struct {
	// The source of packets.
	Handle *pcap.Handle
	// Progress indicator.
	Progress func(pkt gopacket.Packet)
	// Warning indicator.
	Warning func(pkt gopacket.Packet, diff Diff)
	// Unparseable packet indicator.
	Unparseable func(pkt gopacket.Packet)
}

// Session encapsulates a sniffing session.
type Session struct {
	Config

	srcIP        net.IP
	dstIP        net.IP
	eth          layers.Ethernet
	ip4          layers.IPv4
	ip6          layers.IPv6
	tcp          layers.TCP
	payload      gopacket.Payload
	decoded      []gopacket.LayerType
	isTCP        bool
	err          error
	pkt          gopacket.Packet
	source       *gopacket.PacketSource
	parser       *gopacket.DecodingLayerParser
	sID          *streamID
	strm         *stream
	found        bool
	streams      map[streamID]*stream
	nextCleaning time.Time
}

func NewSession(c Config) *Session {
	s := &Session{
		Config:       c,
		streams:      map[streamID]*stream{},
		nextCleaning: time.Now().Add(cleanInterval),
	}
	s.source = gopacket.NewPacketSource(s.Handle, s.Handle.LinkType())
	s.parser = gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &s.eth, &s.ip4, &s.ip6, &s.tcp, &s.payload)
	return s
}

// Clean will remove all created tempfiles.
func (s *Session) Clean() error {
	for id, strm := range s.streams {
		if s.err = strm.clean(); s.err != nil {
			return s.err
		}
		delete(s.streams, id)
	}
	return nil
}

// Run goes through all packets in the source.
func (s *Session) Run() error {
	for packet := range s.source.Packets() {
		s.pkt = packet
		if s.err = s.handle(); s.err != nil {
			return s.err
		}
	}
	return nil
}

// Next looks at the next packet in the source.
func (s *Session) Next() error {
	if s.pkt, s.err = s.source.NextPacket(); s.err != nil {
		return s.err
	}
	return s.handle()
}

func (s *Session) handle() error {
	if s.Progress != nil {
		s.Progress(s.pkt)
	}

	if s.err = s.parser.DecodeLayers(s.pkt.Data(), &s.decoded); s.err != nil {
		if s.Unparseable != nil {
			s.Unparseable(s.pkt)
		}
		return nil
	}
	s.isTCP = false
	for _, typ := range s.decoded {
		switch typ {
		case layers.LayerTypeIPv4:
			s.srcIP = s.ip4.SrcIP
			s.dstIP = s.ip4.DstIP
		case layers.LayerTypeIPv6:
			s.srcIP = s.ip6.SrcIP
			s.dstIP = s.ip6.DstIP
		case layers.LayerTypeTCP:
			s.isTCP = true
		}
	}
	if s.isTCP {
		s.sID = &streamID{
			srcIP:   string(s.srcIP),
			dstIP:   string(s.dstIP),
			srcPort: s.tcp.SrcPort,
			dstPort: s.tcp.DstPort,
		}

		s.strm, s.found = s.streams[*s.sID]
		if s.found || s.tcp.SYN {
			if s.tcp.SYN {
				if s.found {
					// Clean the old stream, this is a new one.
					if s.err = s.strm.clean(); s.err != nil {
						return s.err
					}
				}
				if s.strm, s.err = newStream(s, s.sID, s.tcp.Seq); s.err != nil {
					return s.err
				}
				s.streams[*s.sID] = s.strm
			}
			if s.err = s.strm.write(s.pkt, &s.tcp); s.err != nil {
				return s.err
			}
			s.strm.lastAccess = time.Now()
		}
	}
	if time.Now().After(s.nextCleaning) {
		s.nextCleaning = time.Now().Add(cleanInterval)
		for id, strm := range s.streams {
			if strm.lastAccess.Add(cleanInterval).Before(time.Now()) {
				if s.err = strm.clean(); s.err != nil {
					return s.err
				}
				delete(s.streams, id)
			}
		}
	}
	return nil
}
