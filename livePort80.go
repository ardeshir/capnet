package main

import (
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"log"
	"time"
)

var (
	device		  = "ens3"
	snapshotLen int32 = 1024
	promiscuous	  = false
	err	    error
	timeout		  = 30 * time.Second
	handle		  *pcap.Handle
)

func main() {
	// Open device
	handle, err = pcap.OpenLive(device, snapshotLen, promiscuous, timeout)
	if err != nil {
           log.Fatal(err)
	}

	defer handle.Close()

	// Set filter
	var filter string = "tcp and port 80" // or os.Args[1]
	err = handle.SetBPFFilter(filter)
	if err != nil {
	   log.Fatal(err)
	}
	// Print capturing TCP port 80 Packets
	fmt.Println("Only capturing TCP port 80 packets...")

	// Use the handle as a packet source to process all packets
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		// Process here
		fmt.Println(packet)

	}

} // end of main
