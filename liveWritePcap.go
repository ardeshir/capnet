package main

import (
	"fmt"
	"os"
	"time"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

var (
	device		  = "ens3"
	snapshotLen int32 = 1024
	promiscuous	  = false
	err	    error
	timeout		  = -1 * time.Second
	handle		  *pcap.Handle
	packetCount	  = 0
)

func main() {
	// Open output file 
	f, _ := os.Create("output.pcap")
	w := pcapgo.NewWriter(f)
	w.WriteFileHeader(uint32(snapshotLen), layers.LinkTypeEthernet)
	defer f.Close()

	// Open device
	handle, err = pcap.OpenLive(device, snapshotLen, promiscuous, timeout)
	if err != nil {
           fmt.Println("Error opening device %s: %v", device, err)
	   os.Exit(1)
	}

	defer handle.Close()

	// Set filter
	var filter string = "tcp and port 80" // or os.Args[1]
	err = handle.SetBPFFilter(filter)
	if err != nil {
	   fmt.Println("Error seeting filter %v", err)
           os.Exit(1)
	}
	// Print capturing TCP port 80 Packets
	fmt.Println("Only capturing TCP port 80 packets...")

	// Use the handle as a packet source to process all packets
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		// Process here
		fmt.Println(packet)
		w.WritePacket(packet.Metadata().CaptureInfo, packet.Data())
		packetCount++

		// Only capture 100 and then stop
		if packetCount > 100 {
		  break
		}
	}

} // end of main
