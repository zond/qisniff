// qisniff tries to assemble incoming tcp streams, and will warn you if any one of them contained packets
// with different payloads for the same segment of the stream.
package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/zond/qisniff/qilib"
)

func main() {
	file := flag.String("file", "", "A file to parse")
	dev := flag.String("dev", "", "A dev to sniff")

	flag.Parse()

	if (*file == "" && *dev == "") || (*file != "" && *dev != "") {
		flag.Usage()
		os.Exit(1)
	}

	var handle *pcap.Handle
	var err error

	// Open the pcap file or device.
	if *file != "" {
		if handle, err = pcap.OpenOffline(*file); err != nil {
			panic(err)
		}
	} else {
		if handle, err = pcap.OpenLive(*dev, 8196, true, pcap.BlockForever); err != nil {
			panic(err)
		}
	}

	count := 0
	bars := []string{"-", "\\", "|", "/"}

	sess := qilib.NewSession(qilib.Config{
		Handle: handle,
		Progress: func(pkt gopacket.Packet) {
			fmt.Printf("\r%v ", bars[count%len(bars)])
			count++
		},
		Warning: func(pkt gopacket.Packet, diff qilib.Diff) {
			fmt.Printf("%v %v\n<A>\n%s\n</A>\n<B>\n%s\n</B>\n", diff.ID, diff.Seq, diff.A, diff.B)
		},
		Unparseable: func(pkt gopacket.Packet) {
			fmt.Printf("Unparseable packet\n%v\n", pkt)
		},
	})
	defer sess.Clean()

	if err := sess.Run(); err != nil {
		log.Fatal(err)
	}

}
